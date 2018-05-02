/*
 * QEMU block layer thread pool
 *
 * Copyright IBM, Corp. 2008
 * Copyright Red Hat, Inc. 2012
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Paolo Bonzini     <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */
#include "qemu-common.h"
#include "qemu/queue.h"
#include "qemu/thread.h"
#include "qemu/osdep.h"
#include "block/coroutine.h"
#include "trace.h"
#include "block/block_int.h"
#include "qemu/event_notifier.h"
#include "block/thread-pool.h"

typedef struct ThreadPool ThreadPool;

static void do_spawn_thread(ThreadPool *pool);

typedef struct ThreadPoolElement ThreadPoolElement;

enum ThreadState {
    THREAD_QUEUED,
    THREAD_ACTIVE,
    THREAD_DONE,
    THREAD_CANCELED,
};

struct ThreadPoolElement {
    BlockDriverAIOCB common;
    ThreadPool *pool;
    ThreadPoolFunc *func;
    void *arg;

    /* Moving state out of THREAD_QUEUED is protected by lock.  After
     * that, only the worker thread can write to it.  Reads and writes
     * of state and ret are ordered with memory barriers.
     */
    enum ThreadState state;
    int ret;

    /* Access to this list is protected by lock.  */
    QTAILQ_ENTRY(ThreadPoolElement) reqs;

    /* Access to this list is protected by the global mutex.  */
    QLIST_ENTRY(ThreadPoolElement) all;
};

struct ThreadPool {
    EventNotifier notifier;
    QemuMutex lock;
    QemuCond check_cancel;
    QemuSemaphore sem;
    int max_threads;
    QEMUBH *new_thread_bh;

    /* The following variables are only accessed from one AioContext. */
    QLIST_HEAD(, ThreadPoolElement) head;

    /* The following variables are protected by lock.  */
    QTAILQ_HEAD(, ThreadPoolElement) request_list;
    int cur_threads;
    int idle_threads;
    int new_threads;     /* backlog of threads we need to create */
    int pending_threads; /* threads created but not running yet */
    int pending_cancellations; /* whether we need a cond_broadcast */
};

/* Currently there is only one thread pool instance. */
static ThreadPool global_pool;

static void *worker_thread(void *opaque)
{
    ThreadPool *pool = opaque;

    qemu_mutex_lock(&pool->lock);
    pool->pending_threads--;
    do_spawn_thread(pool);

    while (1) {
        ThreadPoolElement *req;
        int ret;

        do {
            pool->idle_threads++;
            qemu_mutex_unlock(&pool->lock);
            ret = qemu_sem_timedwait(&pool->sem, 10000);
            qemu_mutex_lock(&pool->lock);
            pool->idle_threads--;
        } while (ret == -1 && !QTAILQ_EMPTY(&pool->request_list));
        if (ret == -1) {
            break;
        }

        req = QTAILQ_FIRST(&pool->request_list);
        QTAILQ_REMOVE(&pool->request_list, req, reqs);
        req->state = THREAD_ACTIVE;
        qemu_mutex_unlock(&pool->lock);

        ret = req->func(req->arg);

        req->ret = ret;
        /* Write ret before state.  */
        smp_wmb();
        req->state = THREAD_DONE;

        qemu_mutex_lock(&pool->lock);
        if (pool->pending_cancellations) {
            qemu_cond_broadcast(&pool->check_cancel);
        }

        event_notifier_set(&pool->notifier);
    }

    pool->cur_threads--;
    qemu_mutex_unlock(&pool->lock);
    return NULL;
}

static void do_spawn_thread(ThreadPool *pool)
{
    QemuThread t;

    /* Runs with lock taken.  */
    if (!pool->new_threads) {
        return;
    }

    pool->new_threads--;
    pool->pending_threads++;

    qemu_thread_create(&t, worker_thread, pool, QEMU_THREAD_DETACHED);
}

static void spawn_thread_bh_fn(void *opaque)
{
    ThreadPool *pool = opaque;

    qemu_mutex_lock(&pool->lock);
    do_spawn_thread(pool);
    qemu_mutex_unlock(&pool->lock);
}

static void spawn_thread(ThreadPool *pool)
{
    pool->cur_threads++;
    pool->new_threads++;
    /* If there are threads being created, they will spawn new workers, so
     * we don't spend time creating many threads in a loop holding a mutex or
     * starving the current vcpu.
     *
     * If there are no idle threads, ask the main thread to create one, so we
     * inherit the correct affinity instead of the vcpu affinity.
     */
    if (!pool->pending_threads) {
        qemu_bh_schedule(pool->new_thread_bh);
    }
}

static void event_notifier_ready(EventNotifier *notifier)
{
    ThreadPool *pool = container_of(notifier, ThreadPool, notifier);
    ThreadPoolElement *elem, *next;

    event_notifier_test_and_clear(notifier);
restart:
    QLIST_FOREACH_SAFE(elem, &pool->head, all, next) {
        if (elem->state != THREAD_CANCELED && elem->state != THREAD_DONE) {
            continue;
        }
        if (elem->state == THREAD_DONE) {
            trace_thread_pool_complete(pool, elem, elem->common.opaque,
                                       elem->ret);
        }
        if (elem->state == THREAD_DONE && elem->common.cb) {
            QLIST_REMOVE(elem, all);
            /* Read state before ret.  */
            smp_rmb();
            elem->common.cb(elem->common.opaque, elem->ret);
            qemu_aio_release(elem);
            goto restart;
        } else {
            /* remove the request */
            QLIST_REMOVE(elem, all);
            qemu_aio_release(elem);
        }
    }
}

static int thread_pool_active(EventNotifier *notifier)
{
    ThreadPool *pool = container_of(notifier, ThreadPool, notifier);
    return !QLIST_EMPTY(&pool->head);
}

static void thread_pool_cancel(BlockDriverAIOCB *acb)
{
    ThreadPoolElement *elem = (ThreadPoolElement *)acb;
    ThreadPool *pool = elem->pool;

    trace_thread_pool_cancel(elem, elem->common.opaque);

    qemu_mutex_lock(&pool->lock);
    if (elem->state == THREAD_QUEUED &&
        /* No thread has yet started working on elem. we can try to "steal"
         * the item from the worker if we can get a signal from the
         * semaphore.  Because this is non-blocking, we can do it with
         * the lock taken and ensure that elem will remain THREAD_QUEUED.
         */
        qemu_sem_timedwait(&pool->sem, 0) == 0) {
        QTAILQ_REMOVE(&pool->request_list, elem, reqs);
        elem->state = THREAD_CANCELED;
        event_notifier_set(&pool->notifier);
    } else {
        pool->pending_cancellations++;
        while (elem->state != THREAD_CANCELED && elem->state != THREAD_DONE) {
            qemu_cond_wait(&pool->check_cancel, &pool->lock);
        }
        pool->pending_cancellations--;
    }
    qemu_mutex_unlock(&pool->lock);
}

static const AIOCBInfo thread_pool_aiocb_info = {
    .aiocb_size         = sizeof(ThreadPoolElement),
    .cancel             = thread_pool_cancel,
};

BlockDriverAIOCB *thread_pool_submit_aio(ThreadPoolFunc *func, void *arg,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    ThreadPool *pool = &global_pool;
    ThreadPoolElement *req;

    req = qemu_aio_get(&thread_pool_aiocb_info, NULL, cb, opaque);
    req->func = func;
    req->arg = arg;
    req->state = THREAD_QUEUED;
    req->pool = pool;

    QLIST_INSERT_HEAD(&pool->head, req, all);

    trace_thread_pool_submit(pool, req, arg);

    qemu_mutex_lock(&pool->lock);
    if (pool->idle_threads == 0 && pool->cur_threads < pool->max_threads) {
        spawn_thread(pool);
    }
    QTAILQ_INSERT_TAIL(&pool->request_list, req, reqs);
    qemu_mutex_unlock(&pool->lock);
    qemu_sem_post(&pool->sem);
    return &req->common;
}

typedef struct ThreadPoolCo {
    Coroutine *co;
    int ret;
} ThreadPoolCo;

static void thread_pool_co_cb(void *opaque, int ret)
{
    ThreadPoolCo *co = opaque;

    co->ret = ret;
    qemu_coroutine_enter(co->co, NULL);
}

int coroutine_fn thread_pool_submit_co(ThreadPoolFunc *func, void *arg)
{
    ThreadPoolCo tpc = { .co = qemu_coroutine_self(), .ret = -EINPROGRESS };
    assert(qemu_in_coroutine());
    thread_pool_submit_aio(func, arg, thread_pool_co_cb, &tpc);
    qemu_coroutine_yield();
    return tpc.ret;
}

void thread_pool_submit(ThreadPoolFunc *func, void *arg)
{
    thread_pool_submit_aio(func, arg, NULL, NULL);
}

static void thread_pool_init_one(ThreadPool *pool, AioContext *ctx)
{
    if (!ctx) {
        ctx = qemu_get_aio_context();
    }

    memset(pool, 0, sizeof(*pool));
    event_notifier_init(&pool->notifier, false);
    qemu_mutex_init(&pool->lock);
    qemu_cond_init(&pool->check_cancel);
    qemu_sem_init(&pool->sem, 0);
    pool->max_threads = 64;
    pool->new_thread_bh = aio_bh_new(ctx, spawn_thread_bh_fn, pool);

    QLIST_INIT(&pool->head);
    QTAILQ_INIT(&pool->request_list);

    aio_set_event_notifier(ctx, &pool->notifier, event_notifier_ready,
                           thread_pool_active);
}

static void thread_pool_init(void)
{
    thread_pool_init_one(&global_pool, NULL);
}

block_init(thread_pool_init)
