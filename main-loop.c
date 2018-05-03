/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu-common.h"
#include "qemu/timer.h"
#include "slirp/slirp.h"
#include "qemu/main-loop.h"
#include "block/aio.h"

#ifndef _WIN32

#include "qemu/compatfd.h"

/* If we have signalfd, we mask out the signals we want to handle and then
 * use signalfd to listen for them.  We rely on whatever the current signal
 * handler is to dispatch the signals when we receive them.
 */
static void sigfd_handler(void *opaque)
{
    int fd = (intptr_t)opaque;
    struct qemu_signalfd_siginfo info;
    struct sigaction action;
    ssize_t len;

    while (1) {
        do {
            len = read(fd, &info, sizeof(info));
        } while (len == -1 && errno == EINTR);

        if (len == -1 && errno == EAGAIN) {
            break;
        }

        if (len != sizeof(info)) {
            printf("read from sigfd returned %zd: %m\n", len);
            return;
        }

        sigaction(info.ssi_signo, NULL, &action);
        if ((action.sa_flags & SA_SIGINFO) && action.sa_sigaction) {
            action.sa_sigaction(info.ssi_signo,
                                (siginfo_t *)&info, NULL);
        } else if (action.sa_handler) {
            action.sa_handler(info.ssi_signo);
        }
    }
}

static int qemu_signal_init(void)
{
    int sigfd;
    sigset_t set;

    /*
     * SIG_IPI must be blocked in the main thread and must not be caught
     * by sigwait() in the signal thread. Otherwise, the cpu thread will
     * not catch it reliably.
     */
    sigemptyset(&set);
    sigaddset(&set, SIG_IPI);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGBUS);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    sigdelset(&set, SIG_IPI);
    sigfd = qemu_signalfd(&set);
    if (sigfd == -1) {
        fprintf(stderr, "failed to create signalfd\n");
        return -errno;
    }

    fcntl_setfl(sigfd, O_NONBLOCK);

    qemu_set_fd_handler2(sigfd, NULL, sigfd_handler, NULL,
                         (void *)(intptr_t)sigfd);

    return 0;
}

#else /* _WIN32 */

static int qemu_signal_init(void)
{
    return 0;
}
#endif

static AioContext *qemu_aio_context;

void qemu_notify_event(void)
{
    if (!qemu_aio_context) {
        return;
    }
    aio_notify(qemu_aio_context);
}

static GArray *gpollfds;

int qemu_init_main_loop(void)
{
    int ret;
    GSource *src;

    init_clocks();
    if (init_timer_alarm() < 0) {
        fprintf(stderr, "could not initialize alarm timer\n");
        exit(1);
    }

    ret = qemu_signal_init();
    if (ret) {
        return ret;
    }

    gpollfds = g_array_new(FALSE, FALSE, sizeof(GPollFD));
    qemu_aio_context = aio_context_new();
    src = aio_get_g_source(qemu_aio_context);
    g_source_attach(src, NULL);
    g_source_unref(src);
    return 0;
}

static fd_set rfds, wfds, xfds;
static int nfds;
static int max_priority;

/* Load rfds/wfds/xfds into gpollfds.  Will be removed a few commits later. */
static void gpollfds_from_select(void)
{
    int fd;
    for (fd = 0; fd <= nfds; fd++) {
        int events = 0;
        if (FD_ISSET(fd, &rfds)) {
            events |= G_IO_IN | G_IO_HUP | G_IO_ERR;
        }
        if (FD_ISSET(fd, &wfds)) {
            events |= G_IO_OUT | G_IO_ERR;
        }
        if (FD_ISSET(fd, &xfds)) {
            events |= G_IO_PRI;
        }
        if (events) {
            GPollFD pfd = {
                .fd = fd,
                .events = events,
            };
            g_array_append_val(gpollfds, pfd);
        }
    }
}

/* Store gpollfds revents into rfds/wfds/xfds.  Will be removed a few commits
 * later.
 */
static void gpollfds_to_select(int ret)
{
    int i;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&xfds);

    if (ret <= 0) {
        return;
    }

    for (i = 0; i < gpollfds->len; i++) {
        int fd = g_array_index(gpollfds, GPollFD, i).fd;
        int revents = g_array_index(gpollfds, GPollFD, i).revents;

        if (revents & (G_IO_IN | G_IO_HUP | G_IO_ERR)) {
            FD_SET(fd, &rfds);
        }
        if (revents & (G_IO_OUT | G_IO_ERR)) {
            FD_SET(fd, &wfds);
        }
        if (revents & G_IO_PRI) {
            FD_SET(fd, &xfds);
        }
    }
}

#ifndef _WIN32
static int glib_pollfds_idx;
static int glib_n_poll_fds;

static void glib_pollfds_fill(uint32_t *cur_timeout)
{
    GMainContext *context = g_main_context_default();
    int timeout = 0;
    int n;

    g_main_context_prepare(context, &max_priority);

    glib_pollfds_idx = gpollfds->len;
    n = glib_n_poll_fds;
    do {
        GPollFD *pfds;
        glib_n_poll_fds = n;
        g_array_set_size(gpollfds, glib_pollfds_idx + glib_n_poll_fds);
        pfds = &g_array_index(gpollfds, GPollFD, glib_pollfds_idx);
        n = g_main_context_query(context, max_priority, &timeout, pfds,
                                 glib_n_poll_fds);
    } while (n != glib_n_poll_fds);

    if (timeout >= 0 && timeout < *cur_timeout) {
        *cur_timeout = timeout;
    }
}

static void glib_pollfds_poll(void)
{
    GMainContext *context = g_main_context_default();
    GPollFD *pfds = &g_array_index(gpollfds, GPollFD, glib_pollfds_idx);

    if (g_main_context_check(context, max_priority, pfds, glib_n_poll_fds)) {
        g_main_context_dispatch(context);
    }
}

static int os_host_main_loop_wait(uint32_t timeout)
{
    int ret;

    glib_pollfds_fill(&timeout);

    if (timeout > 0) {
        qemu_mutex_unlock_iothread();
    }

    /* We'll eventually drop fd_set completely.  But for now we still have
     * *_fill() and *_poll() functions that use rfds/wfds/xfds.
     */
    gpollfds_from_select();

    ret = g_poll((GPollFD *)gpollfds->data, gpollfds->len, timeout);

    gpollfds_to_select(ret);

    if (timeout > 0) {
        qemu_mutex_lock_iothread();
    }

    glib_pollfds_poll();
    return ret;
}
#else
/***********************************************************/
/* Polling handling */

typedef struct PollingEntry {
    PollingFunc *func;
    void *opaque;
    struct PollingEntry *next;
} PollingEntry;

static PollingEntry *first_polling_entry;

int qemu_add_polling_cb(PollingFunc *func, void *opaque)
{
    PollingEntry **ppe, *pe;
    pe = g_malloc0(sizeof(PollingEntry));
    pe->func = func;
    pe->opaque = opaque;
    for(ppe = &first_polling_entry; *ppe != NULL; ppe = &(*ppe)->next);
    *ppe = pe;
    return 0;
}

void qemu_del_polling_cb(PollingFunc *func, void *opaque)
{
    PollingEntry **ppe, *pe;
    for(ppe = &first_polling_entry; *ppe != NULL; ppe = &(*ppe)->next) {
        pe = *ppe;
        if (pe->func == func && pe->opaque == opaque) {
            *ppe = pe->next;
            g_free(pe);
            break;
        }
    }
}

/***********************************************************/
/* Wait objects support */
typedef struct WaitObjects {
    int num;
    int revents[MAXIMUM_WAIT_OBJECTS + 1];
    HANDLE events[MAXIMUM_WAIT_OBJECTS + 1];
    WaitObjectFunc *func[MAXIMUM_WAIT_OBJECTS + 1];
    void *opaque[MAXIMUM_WAIT_OBJECTS + 1];
} WaitObjects;

static WaitObjects wait_objects = {0};

int qemu_add_wait_object(HANDLE handle, WaitObjectFunc *func, void *opaque)
{
    WaitObjects *w = &wait_objects;
    if (w->num >= MAXIMUM_WAIT_OBJECTS) {
        return -1;
    }
    w->events[w->num] = handle;
    w->func[w->num] = func;
    w->opaque[w->num] = opaque;
    w->revents[w->num] = 0;
    w->num++;
    return 0;
}

void qemu_del_wait_object(HANDLE handle, WaitObjectFunc *func, void *opaque)
{
    int i, found;
    WaitObjects *w = &wait_objects;

    found = 0;
    for (i = 0; i < w->num; i++) {
        if (w->events[i] == handle) {
            found = 1;
        }
        if (found) {
            w->events[i] = w->events[i + 1];
            w->func[i] = w->func[i + 1];
            w->opaque[i] = w->opaque[i + 1];
            w->revents[i] = w->revents[i + 1];
        }
    }
    if (found) {
        w->num--;
    }
}

void qemu_fd_register(int fd)
{
    WSAEventSelect(fd, event_notifier_get_handle(&qemu_aio_context->notifier),
                   FD_READ | FD_ACCEPT | FD_CLOSE |
                   FD_CONNECT | FD_WRITE | FD_OOB);
}

static int pollfds_fill(GArray *pollfds, fd_set *rfds, fd_set *wfds,
                        fd_set *xfds)
{
    int nfds = -1;
    int i;

    for (i = 0; i < pollfds->len; i++) {
        GPollFD *pfd = &g_array_index(pollfds, GPollFD, i);
        int fd = pfd->fd;
        int events = pfd->events;
        if (events & (G_IO_IN | G_IO_HUP | G_IO_ERR)) {
            FD_SET(fd, rfds);
            nfds = MAX(nfds, fd);
        }
        if (events & (G_IO_OUT | G_IO_ERR)) {
            FD_SET(fd, wfds);
            nfds = MAX(nfds, fd);
        }
        if (events & G_IO_PRI) {
            FD_SET(fd, xfds);
            nfds = MAX(nfds, fd);
        }
    }
    return nfds;
}

static void pollfds_poll(GArray *pollfds, int nfds, fd_set *rfds,
                         fd_set *wfds, fd_set *xfds)
{
    int i;

    for (i = 0; i < pollfds->len; i++) {
        GPollFD *pfd = &g_array_index(pollfds, GPollFD, i);
        int fd = pfd->fd;
        int revents = 0;

        if (FD_ISSET(fd, rfds)) {
            revents |= G_IO_IN | G_IO_HUP | G_IO_ERR;
        }
        if (FD_ISSET(fd, wfds)) {
            revents |= G_IO_OUT | G_IO_ERR;
        }
        if (FD_ISSET(fd, xfds)) {
            revents |= G_IO_PRI;
        }
        pfd->revents = revents & pfd->events;
    }
}

static int os_host_main_loop_wait(uint32_t timeout)
{
    GMainContext *context = g_main_context_default();
    GPollFD poll_fds[1024 * 2]; /* this is probably overkill */
    int select_ret = 0;
    int g_poll_ret, ret, i, n_poll_fds;
    PollingEntry *pe;
    WaitObjects *w = &wait_objects;
    gint poll_timeout;
    static struct timeval tv0;

    /* XXX: need to suppress polling by better using win32 events */
    ret = 0;
    for (pe = first_polling_entry; pe != NULL; pe = pe->next) {
        ret |= pe->func(pe->opaque);
    }
    if (ret != 0) {
        return ret;
    }

    g_main_context_prepare(context, &max_priority);
    n_poll_fds = g_main_context_query(context, max_priority, &poll_timeout,
                                      poll_fds, ARRAY_SIZE(poll_fds));
    g_assert(n_poll_fds <= ARRAY_SIZE(poll_fds));

    for (i = 0; i < w->num; i++) {
        poll_fds[n_poll_fds + i].fd = (DWORD_PTR)w->events[i];
        poll_fds[n_poll_fds + i].events = G_IO_IN;
    }

    if (poll_timeout < 0 || timeout < poll_timeout) {
        poll_timeout = timeout;
    }

    qemu_mutex_unlock_iothread();
    g_poll_ret = g_poll(poll_fds, n_poll_fds + w->num, poll_timeout);
    qemu_mutex_lock_iothread();
    if (g_poll_ret > 0) {
        for (i = 0; i < w->num; i++) {
            w->revents[i] = poll_fds[n_poll_fds + i].revents;
        }
        for (i = 0; i < w->num; i++) {
            if (w->revents[i] && w->func[i]) {
                w->func[i](w->opaque[i]);
            }
        }
    }

    if (g_main_context_check(context, max_priority, poll_fds, n_poll_fds)) {
        g_main_context_dispatch(context);
    }

    /* Call select after g_poll to avoid a useless iteration and therefore
     * improve socket latency.
     */

    /* This back-and-forth between GPollFDs and select(2) is temporary.  We'll
     * drop it in a couple of patches, I promise :).
     */
    gpollfds_from_select();
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&xfds);
    nfds = pollfds_fill(gpollfds, &rfds, &wfds, &xfds);
    if (nfds >= 0) {
        select_ret = select(nfds + 1, &rfds, &wfds, &xfds, &tv0);
        if (select_ret != 0) {
            timeout = 0;
        }
        if (select_ret > 0) {
            pollfds_poll(gpollfds, nfds, &rfds, &wfds, &xfds);
        }
    }
    gpollfds_to_select(select_ret);

    return select_ret || g_poll_ret;
}
#endif

int main_loop_wait(int nonblocking)
{
    int ret;
    uint32_t timeout = UINT32_MAX;

    if (nonblocking) {
        timeout = 0;
    }

    /* poll any events */
    g_array_set_size(gpollfds, 0); /* reset for new iteration */
    /* XXX: separate device handlers from system ones */
    nfds = -1;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&xfds);

#ifdef CONFIG_SLIRP
    slirp_update_timeout(&timeout);
    slirp_pollfds_fill(gpollfds);
#endif
    qemu_iohandler_fill(&nfds, &rfds, &wfds, &xfds);
    ret = os_host_main_loop_wait(timeout);
    qemu_iohandler_poll(&rfds, &wfds, &xfds, ret);
#ifdef CONFIG_SLIRP
    slirp_pollfds_poll(gpollfds, (ret < 0));
#endif

    qemu_run_all_timers();

    return ret;
}

/* Functions to operate on the main QEMU AioContext.  */

QEMUBH *qemu_bh_new(QEMUBHFunc *cb, void *opaque)
{
    return aio_bh_new(qemu_aio_context, cb, opaque);
}

bool qemu_aio_wait(void)
{
    return aio_poll(qemu_aio_context, true);
}

#ifdef CONFIG_POSIX
void qemu_aio_set_fd_handler(int fd,
                             IOHandler *io_read,
                             IOHandler *io_write,
                             AioFlushHandler *io_flush,
                             void *opaque)
{
    aio_set_fd_handler(qemu_aio_context, fd, io_read, io_write, io_flush,
                       opaque);
}
#endif

void qemu_aio_set_event_notifier(EventNotifier *notifier,
                                 EventNotifierHandler *io_read,
                                 AioFlushEventNotifierHandler *io_flush)
{
    aio_set_event_notifier(qemu_aio_context, notifier, io_read, io_flush);
}
