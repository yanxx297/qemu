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

#include "clients.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "qemu/iov.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "hub.h"

typedef struct DumpState {
    NetClientState nc;
    int64_t start_ts;
    int fd;
    int pcap_caplen;
} DumpState;

#define PCAP_MAGIC 0xa1b2c3d4

struct pcap_file_hdr {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};

struct pcap_sf_pkthdr {
    struct {
        int32_t tv_sec;
        int32_t tv_usec;
    } ts;
    uint32_t caplen;
    uint32_t len;
};

static ssize_t dump_receive_iov(NetClientState *nc, const struct iovec *iov,
                                int cnt)
{
    DumpState *s = DO_UPCAST(DumpState, nc, nc);
    struct pcap_sf_pkthdr hdr;
    int64_t ts;
    int caplen;
    size_t size = iov_size(iov, cnt);
    struct iovec dumpiov[cnt + 1];

    /* Early return in case of previous error. */
    if (s->fd < 0) {
        return size;
    }

    ts = qemu_clock_get_us(QEMU_CLOCK_VIRTUAL);
    caplen = size > s->pcap_caplen ? s->pcap_caplen : size;

    hdr.ts.tv_sec = ts / 1000000 + s->start_ts;
    hdr.ts.tv_usec = ts % 1000000;
    hdr.caplen = caplen;
    hdr.len = size;

    dumpiov[0].iov_base = &hdr;
    dumpiov[0].iov_len = sizeof(hdr);
    cnt = iov_copy(&dumpiov[1], cnt, iov, cnt, 0, caplen);

    if (writev(s->fd, dumpiov, cnt + 1) != sizeof(hdr) + caplen) {
        qemu_log("-net dump write error - stop dump\n");
        close(s->fd);
        s->fd = -1;
    }

    return size;
}

static ssize_t dump_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    struct iovec iov = {
        .iov_base = (void *)buf,
        .iov_len = size
    };
    return dump_receive_iov(nc, &iov, 1);
}

static void dump_cleanup(NetClientState *nc)
{
    DumpState *s = DO_UPCAST(DumpState, nc, nc);

    close(s->fd);
}

static NetClientInfo net_dump_info = {
    .type = NET_CLIENT_OPTIONS_KIND_DUMP,
    .size = sizeof(DumpState),
    .receive = dump_receive,
    .receive_iov = dump_receive_iov,
    .cleanup = dump_cleanup,
};

static int net_dump_state_init(DumpState *s, const char *filename,
                               int len, Error **errp)
{
    struct pcap_file_hdr hdr;
    struct tm tm;
    int fd;

    fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, 0644);
    if (fd < 0) {
        error_setg_errno(errp, errno, "-net dump: can't open %s", filename);
        return -1;
    }

    hdr.magic = PCAP_MAGIC;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = len;
    hdr.linktype = 1;

    if (write(fd, &hdr, sizeof(hdr)) < sizeof(hdr)) {
        error_setg_errno(errp, errno, "-net dump write error");
        close(fd);
        return -1;
    }

    s->fd = fd;
    s->pcap_caplen = len;

    qemu_get_timedate(&tm, 0);
    s->start_ts = mktime(&tm);

    return 0;
}

int net_init_dump(const NetClientOptions *opts, const char *name,
                  NetClientState *peer, Error **errp)
{
    int len, rc;
    const char *file;
    char def_file[128];
    const NetdevDumpOptions *dump;
    NetClientState *nc;

    assert(opts->kind == NET_CLIENT_OPTIONS_KIND_DUMP);
    dump = opts->dump;

    assert(peer);

    if (dump->has_file) {
        file = dump->file;
    } else {
        int id;
        int ret;

        ret = net_hub_id_for_client(peer, &id);
        assert(ret == 0); /* peer must be on a hub */

        snprintf(def_file, sizeof(def_file), "qemu-vlan%d.pcap", id);
        file = def_file;
    }

    if (dump->has_len) {
        if (dump->len > INT_MAX) {
            error_setg(errp, "invalid length: %"PRIu64, dump->len);
            return -1;
        }
        len = dump->len;
    } else {
        len = 65536;
    }

    nc = qemu_new_net_client(&net_dump_info, peer, "dump", name);
    snprintf(nc->info_str, sizeof(nc->info_str),
             "dump to %s (len=%d)", file, len);

    rc = net_dump_state_init(DO_UPCAST(DumpState, nc, nc), file, len, errp);
    if (rc) {
        qemu_del_net_client(nc);
    }
    return rc;
}
