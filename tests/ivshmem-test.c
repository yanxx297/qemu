/*
 * QTest testcase for ivshmem
 *
 * Copyright (c) 2014 SUSE LINUX Products GmbH
 * Copyright (c) 2015 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "contrib/ivshmem-server/ivshmem-server.h"
#include "libqos/pci-pc.h"
#include "libqtest.h"
#include "qemu/osdep.h"
#include "qemu-common.h"

#define TMPSHMSIZE (1 << 20)
static char *tmpshm;
static void *tmpshmem;
static char *tmpdir;
static char *tmpserver;

static void save_fn(QPCIDevice *dev, int devfn, void *data)
{
    QPCIDevice **pdev = (QPCIDevice **) data;

    *pdev = dev;
}

static QPCIDevice *get_device(void)
{
    QPCIDevice *dev;
    QPCIBus *pcibus;

    pcibus = qpci_init_pc();
    qpci_device_foreach(pcibus, 0x1af4, 0x1110, save_fn, &dev);
    g_assert(dev != NULL);

    return dev;
}

typedef struct _IVState {
    QTestState *qtest;
    void *reg_base, *mem_base;
    QPCIDevice *dev;
} IVState;

enum Reg {
    INTRMASK = 0,
    INTRSTATUS = 4,
    IVPOSITION = 8,
    DOORBELL = 12,
};

static const char* reg2str(enum Reg reg) {
    switch (reg) {
    case INTRMASK:
        return "IntrMask";
    case INTRSTATUS:
        return "IntrStatus";
    case IVPOSITION:
        return "IVPosition";
    case DOORBELL:
        return "DoorBell";
    default:
        return NULL;
    }
}

static inline unsigned in_reg(IVState *s, enum Reg reg)
{
    const char *name = reg2str(reg);
    QTestState *qtest = global_qtest;
    unsigned res;

    global_qtest = s->qtest;
    res = qpci_io_readl(s->dev, s->reg_base + reg);
    g_test_message("*%s -> %x\n", name, res);
    global_qtest = qtest;

    return res;
}

static inline void out_reg(IVState *s, enum Reg reg, unsigned v)
{
    const char *name = reg2str(reg);
    QTestState *qtest = global_qtest;

    global_qtest = s->qtest;
    g_test_message("%x -> *%s\n", v, name);
    qpci_io_writel(s->dev, s->reg_base + reg, v);
    global_qtest = qtest;
}

static void setup_vm_cmd(IVState *s, const char *cmd, bool msix)
{
    uint64_t barsize;

    s->qtest = qtest_start(cmd);

    s->dev = get_device();

    /* FIXME: other bar order fails, mappings changes */
    s->mem_base = qpci_iomap(s->dev, 2, &barsize);
    g_assert_nonnull(s->mem_base);
    g_assert_cmpuint(barsize, ==, TMPSHMSIZE);

    if (msix) {
        qpci_msix_enable(s->dev);
    }

    s->reg_base = qpci_iomap(s->dev, 0, &barsize);
    g_assert_nonnull(s->reg_base);
    g_assert_cmpuint(barsize, ==, 256);

    qpci_device_enable(s->dev);
}

static void setup_vm(IVState *s)
{
    char *cmd = g_strdup_printf("-device ivshmem,shm=%s,size=1M", tmpshm);

    setup_vm_cmd(s, cmd, false);

    g_free(cmd);
}

static void test_ivshmem_single(void)
{
    IVState state, *s;
    uint32_t data[1024];
    int i;

    setup_vm(&state);
    s = &state;

    /* valid io */
    out_reg(s, INTRMASK, 0);
    in_reg(s, INTRSTATUS);
    in_reg(s, IVPOSITION);

    out_reg(s, INTRMASK, 0xffffffff);
    g_assert_cmpuint(in_reg(s, INTRMASK), ==, 0xffffffff);
    out_reg(s, INTRSTATUS, 1);
    /* XXX: intercept IRQ, not seen in resp */
    g_assert_cmpuint(in_reg(s, INTRSTATUS), ==, 1);

    /* invalid io */
    out_reg(s, IVPOSITION, 1);
    out_reg(s, DOORBELL, 8 << 16);

    for (i = 0; i < G_N_ELEMENTS(data); i++) {
        data[i] = i;
    }
    qtest_memwrite(s->qtest, (uintptr_t)s->mem_base, data, sizeof(data));

    for (i = 0; i < G_N_ELEMENTS(data); i++) {
        g_assert_cmpuint(((uint32_t *)tmpshmem)[i], ==, i);
    }

    memset(data, 0, sizeof(data));

    qtest_memread(s->qtest, (uintptr_t)s->mem_base, data, sizeof(data));
    for (i = 0; i < G_N_ELEMENTS(data); i++) {
        g_assert_cmpuint(data[i], ==, i);
    }

    qtest_quit(s->qtest);
}

static void test_ivshmem_pair(void)
{
    IVState state1, state2, *s1, *s2;
    char *data;
    int i;

    setup_vm(&state1);
    s1 = &state1;
    setup_vm(&state2);
    s2 = &state2;

    data = g_malloc0(TMPSHMSIZE);

    /* host write, guest 1 & 2 read */
    memset(tmpshmem, 0x42, TMPSHMSIZE);
    qtest_memread(s1->qtest, (uintptr_t)s1->mem_base, data, TMPSHMSIZE);
    for (i = 0; i < TMPSHMSIZE; i++) {
        g_assert_cmpuint(data[i], ==, 0x42);
    }
    qtest_memread(s2->qtest, (uintptr_t)s2->mem_base, data, TMPSHMSIZE);
    for (i = 0; i < TMPSHMSIZE; i++) {
        g_assert_cmpuint(data[i], ==, 0x42);
    }

    /* guest 1 write, guest 2 read */
    memset(data, 0x43, TMPSHMSIZE);
    qtest_memwrite(s1->qtest, (uintptr_t)s1->mem_base, data, TMPSHMSIZE);
    memset(data, 0, TMPSHMSIZE);
    qtest_memread(s2->qtest, (uintptr_t)s2->mem_base, data, TMPSHMSIZE);
    for (i = 0; i < TMPSHMSIZE; i++) {
        g_assert_cmpuint(data[i], ==, 0x43);
    }

    /* guest 2 write, guest 1 read */
    memset(data, 0x44, TMPSHMSIZE);
    qtest_memwrite(s2->qtest, (uintptr_t)s2->mem_base, data, TMPSHMSIZE);
    memset(data, 0, TMPSHMSIZE);
    qtest_memread(s1->qtest, (uintptr_t)s2->mem_base, data, TMPSHMSIZE);
    for (i = 0; i < TMPSHMSIZE; i++) {
        g_assert_cmpuint(data[i], ==, 0x44);
    }

    qtest_quit(s1->qtest);
    qtest_quit(s2->qtest);
    g_free(data);
}

typedef struct ServerThread {
    GThread *thread;
    IvshmemServer *server;
    int pipe[2]; /* to handle quit */
} ServerThread;

static void *server_thread(void *data)
{
    ServerThread *t = data;
    IvshmemServer *server = t->server;

    while (true) {
        fd_set fds;
        int maxfd, ret;

        FD_ZERO(&fds);
        FD_SET(t->pipe[0], &fds);
        maxfd = t->pipe[0] + 1;

        ivshmem_server_get_fds(server, &fds, &maxfd);

        ret = select(maxfd, &fds, NULL, NULL, NULL);

        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }

            g_critical("select error: %s\n", strerror(errno));
            break;
        }
        if (ret == 0) {
            continue;
        }

        if (FD_ISSET(t->pipe[0], &fds)) {
            break;
        }

        if (ivshmem_server_handle_fds(server, &fds, maxfd) < 0) {
            g_critical("ivshmem_server_handle_fds() failed\n");
            break;
        }
    }

    return NULL;
}

static void setup_vm_with_server(IVState *s, int nvectors)
{
    char *cmd = g_strdup_printf("-chardev socket,id=chr0,path=%s,nowait "
                                "-device ivshmem,size=1M,chardev=chr0,vectors=%d",
                                tmpserver, nvectors);

    setup_vm_cmd(s, cmd, true);

    g_free(cmd);
}

static void test_ivshmem_server(void)
{
    IVState state1, state2, *s1, *s2;
    ServerThread thread;
    IvshmemServer server;
    int ret, vm1, vm2;
    int nvectors = 2;
    guint64 end_time = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;

    memset(tmpshmem, 0x42, TMPSHMSIZE);
    ret = ivshmem_server_init(&server, tmpserver, tmpshm,
                              TMPSHMSIZE, nvectors,
                              g_test_verbose());
    g_assert_cmpint(ret, ==, 0);

    ret = ivshmem_server_start(&server);
    g_assert_cmpint(ret, ==, 0);

    setup_vm_with_server(&state1, nvectors);
    s1 = &state1;
    setup_vm_with_server(&state2, nvectors);
    s2 = &state2;

    g_assert_cmpuint(in_reg(s1, IVPOSITION), ==, 0xffffffff);
    g_assert_cmpuint(in_reg(s2, IVPOSITION), ==, 0xffffffff);

    g_assert_cmpuint(qtest_readb(s1->qtest, (uintptr_t)s1->mem_base), ==, 0x00);

    thread.server = &server;
    ret = pipe(thread.pipe);
    g_assert_cmpint(ret, ==, 0);
    thread.thread = g_thread_new("ivshmem-server", server_thread, &thread);
    g_assert(thread.thread != NULL);

    /* waiting until mapping is done */
    while (g_get_monotonic_time() < end_time) {
        g_usleep(1000);

        if (qtest_readb(s1->qtest, (uintptr_t)s1->mem_base) == 0x42 &&
            qtest_readb(s2->qtest, (uintptr_t)s2->mem_base) == 0x42) {
            break;
        }
    }

    /* check got different VM ids */
    vm1 = in_reg(s1, IVPOSITION);
    vm2 = in_reg(s2, IVPOSITION);
    g_assert_cmpuint(vm1, !=, vm2);

    global_qtest = s1->qtest;
    ret = qpci_msix_table_size(s1->dev);
    g_assert_cmpuint(ret, ==, nvectors);

    /* ping vm2 -> vm1 */
    ret = qpci_msix_pending(s1->dev, 0);
    g_assert_cmpuint(ret, ==, 0);
    out_reg(s2, DOORBELL, vm1 << 16);
    do {
        g_usleep(10000);
        ret = qpci_msix_pending(s1->dev, 0);
    } while (ret == 0 && g_get_monotonic_time() < end_time);
    g_assert_cmpuint(ret, !=, 0);

    /* ping vm1 -> vm2 */
    global_qtest = s2->qtest;
    ret = qpci_msix_pending(s2->dev, 0);
    g_assert_cmpuint(ret, ==, 0);
    out_reg(s1, DOORBELL, vm2 << 16);
    do {
        g_usleep(10000);
        ret = qpci_msix_pending(s2->dev, 0);
    } while (ret == 0 && g_get_monotonic_time() < end_time);
    g_assert_cmpuint(ret, !=, 0);

    qtest_quit(s2->qtest);
    qtest_quit(s1->qtest);

    if (qemu_write_full(thread.pipe[1], "q", 1) != 1) {
        g_error("qemu_write_full: %s", g_strerror(errno));
    }

    g_thread_join(thread.thread);

    ivshmem_server_close(&server);
    close(thread.pipe[1]);
    close(thread.pipe[0]);
}

#define PCI_SLOT_HP             0x06

static void test_ivshmem_hotplug(void)
{
    gchar *opts;

    qtest_start("");

    opts = g_strdup_printf("'shm': '%s', 'size': '1M'", tmpshm);

    qpci_plug_device_test("ivshmem", "iv1", PCI_SLOT_HP, opts);
    qpci_unplug_acpi_device_test("iv1", PCI_SLOT_HP);

    qtest_end();
    g_free(opts);
}

static void cleanup(void)
{
    if (tmpshmem) {
        munmap(tmpshmem, TMPSHMSIZE);
        tmpshmem = NULL;
    }

    if (tmpshm) {
        shm_unlink(tmpshm);
        g_free(tmpshm);
        tmpshm = NULL;
    }

    if (tmpserver) {
        g_unlink(tmpserver);
        g_free(tmpserver);
        tmpserver = NULL;
    }

    if (tmpdir) {
        g_rmdir(tmpdir);
        tmpdir = NULL;
    }
}

static void abrt_handler(void *data)
{
    cleanup();
}

static gchar *mktempshm(int size, int *fd)
{
    while (true) {
        gchar *name;

        name = g_strdup_printf("/qtest-%u-%u", getpid(), g_random_int());
        *fd = shm_open(name, O_CREAT|O_RDWR|O_EXCL,
                       S_IRWXU|S_IRWXG|S_IRWXO);
        if (*fd > 0) {
            g_assert(ftruncate(*fd, size) == 0);
            return name;
        }

        g_free(name);

        if (errno != EEXIST) {
            perror("shm_open");
            return NULL;
        }
    }
}

int main(int argc, char **argv)
{
    int ret, fd;
    gchar dir[] = "/tmp/ivshmem-test.XXXXXX";

#if !GLIB_CHECK_VERSION(2, 31, 0)
    if (!g_thread_supported()) {
        g_thread_init(NULL);
    }
#endif

    g_test_init(&argc, &argv, NULL);

    qtest_add_abrt_handler(abrt_handler, NULL);
    /* shm */
    tmpshm = mktempshm(TMPSHMSIZE, &fd);
    if (!tmpshm) {
        return 0;
    }
    tmpshmem = mmap(0, TMPSHMSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    g_assert(tmpshmem != MAP_FAILED);
    /* server */
    if (mkdtemp(dir) == NULL) {
        g_error("mkdtemp: %s", g_strerror(errno));
    }
    tmpdir = dir;
    tmpserver = g_strconcat(tmpdir, "/server", NULL);

    qtest_add_func("/ivshmem/single", test_ivshmem_single);
    qtest_add_func("/ivshmem/pair", test_ivshmem_pair);
    qtest_add_func("/ivshmem/server", test_ivshmem_server);
    qtest_add_func("/ivshmem/hotplug", test_ivshmem_hotplug);

    ret = g_test_run();

    cleanup();

    return ret;
}
