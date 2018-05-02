/*
 * QEMU System Emulator block driver
 *
 * Copyright (c) 2011 IBM Corp.
 * Copyright (c) 2012 Red Hat, Inc.
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

#include "config-host.h"
#include "qemu-common.h"
#include "trace.h"
#include "monitor.h"
#include "block.h"
#include "blockjob.h"
#include "block_int.h"
#include "qjson.h"
#include "qemu-coroutine.h"
#include "qmp-commands.h"
#include "qemu-timer.h"

void *block_job_create(const BlockJobType *job_type, BlockDriverState *bs,
                       int64_t speed, BlockDriverCompletionFunc *cb,
                       void *opaque, Error **errp)
{
    BlockJob *job;

    if (bs->job || bdrv_in_use(bs)) {
        error_set(errp, QERR_DEVICE_IN_USE, bdrv_get_device_name(bs));
        return NULL;
    }
    bdrv_set_in_use(bs, 1);

    job = g_malloc0(job_type->instance_size);
    job->job_type      = job_type;
    job->bs            = bs;
    job->cb            = cb;
    job->opaque        = opaque;
    job->busy          = true;
    bs->job = job;

    /* Only set speed when necessary to avoid NotSupported error */
    if (speed != 0) {
        Error *local_err = NULL;

        block_job_set_speed(job, speed, &local_err);
        if (error_is_set(&local_err)) {
            bs->job = NULL;
            g_free(job);
            bdrv_set_in_use(bs, 0);
            error_propagate(errp, local_err);
            return NULL;
        }
    }
    return job;
}

void block_job_complete(BlockJob *job, int ret)
{
    BlockDriverState *bs = job->bs;

    assert(bs->job == job);
    job->cb(job->opaque, ret);
    bs->job = NULL;
    g_free(job);
    bdrv_set_in_use(bs, 0);
}

void block_job_set_speed(BlockJob *job, int64_t speed, Error **errp)
{
    Error *local_err = NULL;

    if (!job->job_type->set_speed) {
        error_set(errp, QERR_NOT_SUPPORTED);
        return;
    }
    job->job_type->set_speed(job, speed, &local_err);
    if (error_is_set(&local_err)) {
        error_propagate(errp, local_err);
        return;
    }

    job->speed = speed;
}

void block_job_cancel(BlockJob *job)
{
    job->cancelled = true;
    if (job->co && !job->busy) {
        qemu_coroutine_enter(job->co, NULL);
    }
}

bool block_job_is_cancelled(BlockJob *job)
{
    return job->cancelled;
}

struct BlockCancelData {
    BlockJob *job;
    BlockDriverCompletionFunc *cb;
    void *opaque;
    bool cancelled;
    int ret;
};

static void block_job_cancel_cb(void *opaque, int ret)
{
    struct BlockCancelData *data = opaque;

    data->cancelled = block_job_is_cancelled(data->job);
    data->ret = ret;
    data->cb(data->opaque, ret);
}

int block_job_cancel_sync(BlockJob *job)
{
    struct BlockCancelData data;
    BlockDriverState *bs = job->bs;

    assert(bs->job == job);

    /* Set up our own callback to store the result and chain to
     * the original callback.
     */
    data.job = job;
    data.cb = job->cb;
    data.opaque = job->opaque;
    data.ret = -EINPROGRESS;
    job->cb = block_job_cancel_cb;
    job->opaque = &data;
    block_job_cancel(job);
    while (data.ret == -EINPROGRESS) {
        qemu_aio_wait();
    }
    return (data.cancelled && data.ret == 0) ? -ECANCELED : data.ret;
}

void block_job_sleep_ns(BlockJob *job, QEMUClock *clock, int64_t ns)
{
    /* Check cancellation *before* setting busy = false, too!  */
    if (!block_job_is_cancelled(job)) {
        job->busy = false;
        co_sleep_ns(clock, ns);
        job->busy = true;
    }
}

BlockJobInfo *block_job_query(BlockJob *job)
{
    BlockJobInfo *info = g_new0(BlockJobInfo, 1);
    info->type   = g_strdup(job->job_type->job_type);
    info->device = g_strdup(bdrv_get_device_name(job->bs));
    info->len    = job->len;
    info->offset = job->offset;
    info->speed  = job->speed;
    return info;
}
