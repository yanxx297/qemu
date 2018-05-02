/*
 * gdb server stub
 *
 * Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "config.h"
#include "qemu-common.h"
#ifdef CONFIG_USER_ONLY
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "qemu.h"
#else
#include "monitor/monitor.h"
#include "sysemu/char.h"
#include "sysemu/sysemu.h"
#include "exec/gdbstub.h"
#endif

#define MAX_PACKET_LENGTH 4096

#include "cpu.h"
#include "qemu/sockets.h"
#include "sysemu/kvm.h"
#include "qemu/bitops.h"

static inline int target_memory_rw_debug(CPUState *cpu, target_ulong addr,
                                         uint8_t *buf, int len, bool is_write)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->memory_rw_debug) {
        return cc->memory_rw_debug(cpu, addr, buf, len, is_write);
    }
    return cpu_memory_rw_debug(cpu, addr, buf, len, is_write);
}

enum {
    GDB_SIGNAL_0 = 0,
    GDB_SIGNAL_INT = 2,
    GDB_SIGNAL_QUIT = 3,
    GDB_SIGNAL_TRAP = 5,
    GDB_SIGNAL_ABRT = 6,
    GDB_SIGNAL_ALRM = 14,
    GDB_SIGNAL_IO = 23,
    GDB_SIGNAL_XCPU = 24,
    GDB_SIGNAL_UNKNOWN = 143
};

#ifdef CONFIG_USER_ONLY

/* Map target signal numbers to GDB protocol signal numbers and vice
 * versa.  For user emulation's currently supported systems, we can
 * assume most signals are defined.
 */

static int gdb_signal_table[] = {
    0,
    TARGET_SIGHUP,
    TARGET_SIGINT,
    TARGET_SIGQUIT,
    TARGET_SIGILL,
    TARGET_SIGTRAP,
    TARGET_SIGABRT,
    -1, /* SIGEMT */
    TARGET_SIGFPE,
    TARGET_SIGKILL,
    TARGET_SIGBUS,
    TARGET_SIGSEGV,
    TARGET_SIGSYS,
    TARGET_SIGPIPE,
    TARGET_SIGALRM,
    TARGET_SIGTERM,
    TARGET_SIGURG,
    TARGET_SIGSTOP,
    TARGET_SIGTSTP,
    TARGET_SIGCONT,
    TARGET_SIGCHLD,
    TARGET_SIGTTIN,
    TARGET_SIGTTOU,
    TARGET_SIGIO,
    TARGET_SIGXCPU,
    TARGET_SIGXFSZ,
    TARGET_SIGVTALRM,
    TARGET_SIGPROF,
    TARGET_SIGWINCH,
    -1, /* SIGLOST */
    TARGET_SIGUSR1,
    TARGET_SIGUSR2,
#ifdef TARGET_SIGPWR
    TARGET_SIGPWR,
#else
    -1,
#endif
    -1, /* SIGPOLL */
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
#ifdef __SIGRTMIN
    __SIGRTMIN + 1,
    __SIGRTMIN + 2,
    __SIGRTMIN + 3,
    __SIGRTMIN + 4,
    __SIGRTMIN + 5,
    __SIGRTMIN + 6,
    __SIGRTMIN + 7,
    __SIGRTMIN + 8,
    __SIGRTMIN + 9,
    __SIGRTMIN + 10,
    __SIGRTMIN + 11,
    __SIGRTMIN + 12,
    __SIGRTMIN + 13,
    __SIGRTMIN + 14,
    __SIGRTMIN + 15,
    __SIGRTMIN + 16,
    __SIGRTMIN + 17,
    __SIGRTMIN + 18,
    __SIGRTMIN + 19,
    __SIGRTMIN + 20,
    __SIGRTMIN + 21,
    __SIGRTMIN + 22,
    __SIGRTMIN + 23,
    __SIGRTMIN + 24,
    __SIGRTMIN + 25,
    __SIGRTMIN + 26,
    __SIGRTMIN + 27,
    __SIGRTMIN + 28,
    __SIGRTMIN + 29,
    __SIGRTMIN + 30,
    __SIGRTMIN + 31,
    -1, /* SIGCANCEL */
    __SIGRTMIN,
    __SIGRTMIN + 32,
    __SIGRTMIN + 33,
    __SIGRTMIN + 34,
    __SIGRTMIN + 35,
    __SIGRTMIN + 36,
    __SIGRTMIN + 37,
    __SIGRTMIN + 38,
    __SIGRTMIN + 39,
    __SIGRTMIN + 40,
    __SIGRTMIN + 41,
    __SIGRTMIN + 42,
    __SIGRTMIN + 43,
    __SIGRTMIN + 44,
    __SIGRTMIN + 45,
    __SIGRTMIN + 46,
    __SIGRTMIN + 47,
    __SIGRTMIN + 48,
    __SIGRTMIN + 49,
    __SIGRTMIN + 50,
    __SIGRTMIN + 51,
    __SIGRTMIN + 52,
    __SIGRTMIN + 53,
    __SIGRTMIN + 54,
    __SIGRTMIN + 55,
    __SIGRTMIN + 56,
    __SIGRTMIN + 57,
    __SIGRTMIN + 58,
    __SIGRTMIN + 59,
    __SIGRTMIN + 60,
    __SIGRTMIN + 61,
    __SIGRTMIN + 62,
    __SIGRTMIN + 63,
    __SIGRTMIN + 64,
    __SIGRTMIN + 65,
    __SIGRTMIN + 66,
    __SIGRTMIN + 67,
    __SIGRTMIN + 68,
    __SIGRTMIN + 69,
    __SIGRTMIN + 70,
    __SIGRTMIN + 71,
    __SIGRTMIN + 72,
    __SIGRTMIN + 73,
    __SIGRTMIN + 74,
    __SIGRTMIN + 75,
    __SIGRTMIN + 76,
    __SIGRTMIN + 77,
    __SIGRTMIN + 78,
    __SIGRTMIN + 79,
    __SIGRTMIN + 80,
    __SIGRTMIN + 81,
    __SIGRTMIN + 82,
    __SIGRTMIN + 83,
    __SIGRTMIN + 84,
    __SIGRTMIN + 85,
    __SIGRTMIN + 86,
    __SIGRTMIN + 87,
    __SIGRTMIN + 88,
    __SIGRTMIN + 89,
    __SIGRTMIN + 90,
    __SIGRTMIN + 91,
    __SIGRTMIN + 92,
    __SIGRTMIN + 93,
    __SIGRTMIN + 94,
    __SIGRTMIN + 95,
    -1, /* SIGINFO */
    -1, /* UNKNOWN */
    -1, /* DEFAULT */
    -1,
    -1,
    -1,
    -1,
    -1,
    -1
#endif
};
#else
/* In system mode we only need SIGINT and SIGTRAP; other signals
   are not yet supported.  */

enum {
    TARGET_SIGINT = 2,
    TARGET_SIGTRAP = 5
};

static int gdb_signal_table[] = {
    -1,
    -1,
    TARGET_SIGINT,
    -1,
    -1,
    TARGET_SIGTRAP
};
#endif

#ifdef CONFIG_USER_ONLY
static int target_signal_to_gdb (int sig)
{
    int i;
    for (i = 0; i < ARRAY_SIZE (gdb_signal_table); i++)
        if (gdb_signal_table[i] == sig)
            return i;
    return GDB_SIGNAL_UNKNOWN;
}
#endif

static int gdb_signal_to_target (int sig)
{
    if (sig < ARRAY_SIZE (gdb_signal_table))
        return gdb_signal_table[sig];
    else
        return -1;
}

//#define DEBUG_GDB

typedef struct GDBRegisterState {
    int base_reg;
    int num_regs;
    gdb_reg_cb get_reg;
    gdb_reg_cb set_reg;
    const char *xml;
    struct GDBRegisterState *next;
} GDBRegisterState;

enum RSState {
    RS_INACTIVE,
    RS_IDLE,
    RS_GETLINE,
    RS_CHKSUM1,
    RS_CHKSUM2,
};
typedef struct GDBState {
    CPUState *c_cpu; /* current CPU for step/continue ops */
    CPUState *g_cpu; /* current CPU for other ops */
    CPUState *query_cpu; /* for q{f|s}ThreadInfo */
    enum RSState state; /* parsing state */
    char line_buf[MAX_PACKET_LENGTH];
    int line_buf_index;
    int line_csum;
    uint8_t last_packet[MAX_PACKET_LENGTH + 4];
    int last_packet_len;
    int signal;
#ifdef CONFIG_USER_ONLY
    int fd;
    int running_state;
#else
    CharDriverState *chr;
    CharDriverState *mon_chr;
#endif
    char syscall_buf[256];
    gdb_syscall_complete_cb current_syscall_cb;
} GDBState;

/* By default use no IRQs and no timers while single stepping so as to
 * make single stepping like an ICE HW step.
 */
static int sstep_flags = SSTEP_ENABLE|SSTEP_NOIRQ|SSTEP_NOTIMER;

static GDBState *gdbserver_state;

/* This is an ugly hack to cope with both new and old gdb.
   If gdb sends qXfer:features:read then assume we're talking to a newish
   gdb that understands target descriptions.  */
static int gdb_has_xml;

#ifdef CONFIG_USER_ONLY
/* XXX: This is not thread safe.  Do we care?  */
static int gdbserver_fd = -1;

static int get_char(GDBState *s)
{
    uint8_t ch;
    int ret;

    for(;;) {
        ret = qemu_recv(s->fd, &ch, 1, 0);
        if (ret < 0) {
            if (errno == ECONNRESET)
                s->fd = -1;
            if (errno != EINTR && errno != EAGAIN)
                return -1;
        } else if (ret == 0) {
            close(s->fd);
            s->fd = -1;
            return -1;
        } else {
            break;
        }
    }
    return ch;
}
#endif

static enum {
    GDB_SYS_UNKNOWN,
    GDB_SYS_ENABLED,
    GDB_SYS_DISABLED,
} gdb_syscall_mode;

/* If gdb is connected when the first semihosting syscall occurs then use
   remote gdb syscalls.  Otherwise use native file IO.  */
int use_gdb_syscalls(void)
{
    if (gdb_syscall_mode == GDB_SYS_UNKNOWN) {
        gdb_syscall_mode = (gdbserver_state ? GDB_SYS_ENABLED
                                            : GDB_SYS_DISABLED);
    }
    return gdb_syscall_mode == GDB_SYS_ENABLED;
}

/* Resume execution.  */
static inline void gdb_continue(GDBState *s)
{
#ifdef CONFIG_USER_ONLY
    s->running_state = 1;
#else
    if (runstate_check(RUN_STATE_GUEST_PANICKED)) {
        runstate_set(RUN_STATE_DEBUG);
    }
    if (!runstate_needs_reset()) {
        vm_start();
    }
#endif
}

static void put_buffer(GDBState *s, const uint8_t *buf, int len)
{
#ifdef CONFIG_USER_ONLY
    int ret;

    while (len > 0) {
        ret = send(s->fd, buf, len, 0);
        if (ret < 0) {
            if (errno != EINTR && errno != EAGAIN)
                return;
        } else {
            buf += ret;
            len -= ret;
        }
    }
#else
    qemu_chr_fe_write(s->chr, buf, len);
#endif
}

static inline int fromhex(int v)
{
    if (v >= '0' && v <= '9')
        return v - '0';
    else if (v >= 'A' && v <= 'F')
        return v - 'A' + 10;
    else if (v >= 'a' && v <= 'f')
        return v - 'a' + 10;
    else
        return 0;
}

static inline int tohex(int v)
{
    if (v < 10)
        return v + '0';
    else
        return v - 10 + 'a';
}

static void memtohex(char *buf, const uint8_t *mem, int len)
{
    int i, c;
    char *q;
    q = buf;
    for(i = 0; i < len; i++) {
        c = mem[i];
        *q++ = tohex(c >> 4);
        *q++ = tohex(c & 0xf);
    }
    *q = '\0';
}

static void hextomem(uint8_t *mem, const char *buf, int len)
{
    int i;

    for(i = 0; i < len; i++) {
        mem[i] = (fromhex(buf[0]) << 4) | fromhex(buf[1]);
        buf += 2;
    }
}

/* return -1 if error, 0 if OK */
static int put_packet_binary(GDBState *s, const char *buf, int len)
{
    int csum, i;
    uint8_t *p;

    for(;;) {
        p = s->last_packet;
        *(p++) = '$';
        memcpy(p, buf, len);
        p += len;
        csum = 0;
        for(i = 0; i < len; i++) {
            csum += buf[i];
        }
        *(p++) = '#';
        *(p++) = tohex((csum >> 4) & 0xf);
        *(p++) = tohex((csum) & 0xf);

        s->last_packet_len = p - s->last_packet;
        put_buffer(s, (uint8_t *)s->last_packet, s->last_packet_len);

#ifdef CONFIG_USER_ONLY
        i = get_char(s);
        if (i < 0)
            return -1;
        if (i == '+')
            break;
#else
        break;
#endif
    }
    return 0;
}

/* return -1 if error, 0 if OK */
static int put_packet(GDBState *s, const char *buf)
{
#ifdef DEBUG_GDB
    printf("reply='%s'\n", buf);
#endif

    return put_packet_binary(s, buf, strlen(buf));
}

/* The GDB remote protocol transfers values in target byte order.  This means
   we can use the raw memory access routines to access the value buffer.
   Conveniently, these also handle the case where the buffer is mis-aligned.
 */
#define GET_REG8(val) do { \
    stb_p(mem_buf, val); \
    return 1; \
    } while(0)
#define GET_REG16(val) do { \
    stw_p(mem_buf, val); \
    return 2; \
    } while(0)
#define GET_REG32(val) do { \
    stl_p(mem_buf, val); \
    return 4; \
    } while(0)
#define GET_REG64(val) do { \
    stq_p(mem_buf, val); \
    return 8; \
    } while(0)

#if TARGET_LONG_BITS == 64
#define GET_REGL(val) GET_REG64(val)
#define ldtul_p(addr) ldq_p(addr)
#else
#define GET_REGL(val) GET_REG32(val)
#define ldtul_p(addr) ldl_p(addr)
#endif

#if defined(TARGET_I386)

#include "target-i386/gdbstub.c"

#elif defined (TARGET_PPC)

#if defined (TARGET_PPC64)
#define GDB_CORE_XML "power64-core.xml"
#else
#define GDB_CORE_XML "power-core.xml"
#endif

#include "target-ppc/gdbstub.c"

#elif defined (TARGET_SPARC)

#include "target-sparc/gdbstub.c"

#elif defined (TARGET_ARM)

#define GDB_CORE_XML "arm-core.xml"

#include "target-arm/gdbstub.c"

#elif defined (TARGET_M68K)

#define GDB_CORE_XML "cf-core.xml"

#include "target-m68k/gdbstub.c"

#elif defined (TARGET_MIPS)

#include "target-mips/gdbstub.c"

#elif defined(TARGET_OPENRISC)

#include "target-openrisc/gdbstub.c"

#elif defined (TARGET_SH4)

#include "target-sh4/gdbstub.c"

#elif defined (TARGET_MICROBLAZE)

static int cpu_gdb_read_register(CPUMBState *env, uint8_t *mem_buf, int n)
{
    if (n < 32) {
        GET_REG32(env->regs[n]);
    } else {
        GET_REG32(env->sregs[n - 32]);
    }
    return 0;
}

static int cpu_gdb_write_register(CPUMBState *env, uint8_t *mem_buf, int n)
{
    MicroBlazeCPU *cpu = mb_env_get_cpu(env);
    CPUClass *cc = CPU_GET_CLASS(cpu);
    uint32_t tmp;

    if (n > cc->gdb_num_core_regs) {
        return 0;
    }

    tmp = ldl_p(mem_buf);

    if (n < 32) {
        env->regs[n] = tmp;
    } else {
        env->sregs[n - 32] = tmp;
    }
    return 4;
}
#elif defined (TARGET_CRIS)

static int
read_register_crisv10(CPUCRISState *env, uint8_t *mem_buf, int n)
{
    if (n < 15) {
        GET_REG32(env->regs[n]);
    }

    if (n == 15) {
        GET_REG32(env->pc);
    }

    if (n < 32) {
        switch (n) {
        case 16:
            GET_REG8(env->pregs[n - 16]);
        case 17:
            GET_REG8(env->pregs[n - 16]);
        case 20:
        case 21:
            GET_REG16(env->pregs[n - 16]);
        default:
            if (n >= 23) {
                GET_REG32(env->pregs[n - 16]);
            }
            break;
        }
    }
    return 0;
}

static int cpu_gdb_read_register(CPUCRISState *env, uint8_t *mem_buf, int n)
{
    uint8_t srs;

    if (env->pregs[PR_VR] < 32) {
        return read_register_crisv10(env, mem_buf, n);
    }

    srs = env->pregs[PR_SRS];
    if (n < 16) {
        GET_REG32(env->regs[n]);
    }

    if (n >= 21 && n < 32) {
        GET_REG32(env->pregs[n - 16]);
    }
    if (n >= 33 && n < 49) {
        GET_REG32(env->sregs[srs][n - 33]);
    }
    switch (n) {
    case 16:
        GET_REG8(env->pregs[0]);
    case 17:
        GET_REG8(env->pregs[1]);
    case 18:
        GET_REG32(env->pregs[2]);
    case 19:
        GET_REG8(srs);
    case 20:
        GET_REG16(env->pregs[4]);
    case 32:
        GET_REG32(env->pc);
    }

    return 0;
}

static int cpu_gdb_write_register(CPUCRISState *env, uint8_t *mem_buf, int n)
{
    uint32_t tmp;

    if (n > 49) {
        return 0;
    }

    tmp = ldl_p(mem_buf);

    if (n < 16) {
        env->regs[n] = tmp;
    }

    if (n >= 21 && n < 32) {
        env->pregs[n - 16] = tmp;
    }

    /* FIXME: Should support function regs be writable?  */
    switch (n) {
    case 16:
        return 1;
    case 17:
        return 1;
    case 18:
        env->pregs[PR_PID] = tmp;
        break;
    case 19:
        return 1;
    case 20:
        return 2;
    case 32:
        env->pc = tmp;
        break;
    }

    return 4;
}
#elif defined (TARGET_ALPHA)

static int cpu_gdb_read_register(CPUAlphaState *env, uint8_t *mem_buf, int n)
{
    uint64_t val;
    CPU_DoubleU d;

    switch (n) {
    case 0 ... 30:
        val = env->ir[n];
        break;
    case 32 ... 62:
        d.d = env->fir[n - 32];
        val = d.ll;
        break;
    case 63:
        val = cpu_alpha_load_fpcr(env);
        break;
    case 64:
        val = env->pc;
        break;
    case 66:
        val = env->unique;
        break;
    case 31:
    case 65:
        /* 31 really is the zero register; 65 is unassigned in the
           gdb protocol, but is still required to occupy 8 bytes. */
        val = 0;
        break;
    default:
        return 0;
    }
    GET_REGL(val);
}

static int cpu_gdb_write_register(CPUAlphaState *env, uint8_t *mem_buf, int n)
{
    target_ulong tmp = ldtul_p(mem_buf);
    CPU_DoubleU d;

    switch (n) {
    case 0 ... 30:
        env->ir[n] = tmp;
        break;
    case 32 ... 62:
        d.ll = tmp;
        env->fir[n - 32] = d.d;
        break;
    case 63:
        cpu_alpha_store_fpcr(env, tmp);
        break;
    case 64:
        env->pc = tmp;
        break;
    case 66:
        env->unique = tmp;
        break;
    case 31:
    case 65:
        /* 31 really is the zero register; 65 is unassigned in the
           gdb protocol, but is still required to occupy 8 bytes. */
        break;
    default:
        return 0;
    }
    return 8;
}
#elif defined (TARGET_S390X)

static int cpu_gdb_read_register(CPUS390XState *env, uint8_t *mem_buf, int n)
{
    uint64_t val;
    int cc_op;

    switch (n) {
    case S390_PSWM_REGNUM:
        cc_op = calc_cc(env, env->cc_op, env->cc_src, env->cc_dst, env->cc_vr);
        val = deposit64(env->psw.mask, 44, 2, cc_op);
        GET_REGL(val);
    case S390_PSWA_REGNUM:
        GET_REGL(env->psw.addr);
    case S390_R0_REGNUM ... S390_R15_REGNUM:
        GET_REGL(env->regs[n-S390_R0_REGNUM]);
    case S390_A0_REGNUM ... S390_A15_REGNUM:
        GET_REG32(env->aregs[n-S390_A0_REGNUM]);
    case S390_FPC_REGNUM:
        GET_REG32(env->fpc);
    case S390_F0_REGNUM ... S390_F15_REGNUM:
        GET_REG64(env->fregs[n-S390_F0_REGNUM].ll);
    }

    return 0;
}

static int cpu_gdb_write_register(CPUS390XState *env, uint8_t *mem_buf, int n)
{
    target_ulong tmpl;
    uint32_t tmp32;
    int r = 8;
    tmpl = ldtul_p(mem_buf);
    tmp32 = ldl_p(mem_buf);

    switch (n) {
    case S390_PSWM_REGNUM:
        env->psw.mask = tmpl;
        env->cc_op = extract64(tmpl, 44, 2);
        break;
    case S390_PSWA_REGNUM:
        env->psw.addr = tmpl;
        break;
    case S390_R0_REGNUM ... S390_R15_REGNUM:
        env->regs[n-S390_R0_REGNUM] = tmpl;
        break;
    case S390_A0_REGNUM ... S390_A15_REGNUM:
        env->aregs[n-S390_A0_REGNUM] = tmp32;
        r = 4;
        break;
    case S390_FPC_REGNUM:
        env->fpc = tmp32;
        r = 4;
        break;
    case S390_F0_REGNUM ... S390_F15_REGNUM:
        env->fregs[n-S390_F0_REGNUM].ll = tmpl;
        break;
    default:
        return 0;
    }
    return r;
}
#elif defined (TARGET_LM32)

#include "hw/lm32/lm32_pic.h"

static int cpu_gdb_read_register(CPULM32State *env, uint8_t *mem_buf, int n)
{
    if (n < 32) {
        GET_REG32(env->regs[n]);
    } else {
        switch (n) {
        case 32:
            GET_REG32(env->pc);
        /* FIXME: put in right exception ID */
        case 33:
            GET_REG32(0);
        case 34:
            GET_REG32(env->eba);
        case 35:
            GET_REG32(env->deba);
        case 36:
            GET_REG32(env->ie);
        case 37:
            GET_REG32(lm32_pic_get_im(env->pic_state));
        case 38:
            GET_REG32(lm32_pic_get_ip(env->pic_state));
        }
    }
    return 0;
}

static int cpu_gdb_write_register(CPULM32State *env, uint8_t *mem_buf, int n)
{
    LM32CPU *cpu = lm32_env_get_cpu(env);
    CPUClass *cc = CPU_GET_CLASS(cpu);
    uint32_t tmp;

    if (n > cc->gdb_num_core_regs) {
        return 0;
    }

    tmp = ldl_p(mem_buf);

    if (n < 32) {
        env->regs[n] = tmp;
    } else {
        switch (n) {
        case 32:
            env->pc = tmp;
            break;
        case 34:
            env->eba = tmp;
            break;
        case 35:
            env->deba = tmp;
            break;
        case 36:
            env->ie = tmp;
            break;
        case 37:
            lm32_pic_set_im(env->pic_state, tmp);
            break;
        case 38:
            lm32_pic_set_ip(env->pic_state, tmp);
            break;
        }
    }
    return 4;
}
#elif defined(TARGET_XTENSA)

static int cpu_gdb_read_register(CPUXtensaState *env, uint8_t *mem_buf, int n)
{
    const XtensaGdbReg *reg = env->config->gdb_regmap.reg + n;

    if (n < 0 || n >= env->config->gdb_regmap.num_regs) {
        return 0;
    }

    switch (reg->type) {
    case 9: /*pc*/
        GET_REG32(env->pc);

    case 1: /*ar*/
        xtensa_sync_phys_from_window(env);
        GET_REG32(env->phys_regs[(reg->targno & 0xff) % env->config->nareg]);

    case 2: /*SR*/
        GET_REG32(env->sregs[reg->targno & 0xff]);

    case 3: /*UR*/
        GET_REG32(env->uregs[reg->targno & 0xff]);

    case 4: /*f*/
        GET_REG32(float32_val(env->fregs[reg->targno & 0x0f]));

    case 8: /*a*/
        GET_REG32(env->regs[reg->targno & 0x0f]);

    default:
        qemu_log("%s from reg %d of unsupported type %d\n",
                 __func__, n, reg->type);
        return 0;
    }
}

static int cpu_gdb_write_register(CPUXtensaState *env, uint8_t *mem_buf, int n)
{
    uint32_t tmp;
    const XtensaGdbReg *reg = env->config->gdb_regmap.reg + n;

    if (n < 0 || n >= env->config->gdb_regmap.num_regs) {
        return 0;
    }

    tmp = ldl_p(mem_buf);

    switch (reg->type) {
    case 9: /*pc*/
        env->pc = tmp;
        break;

    case 1: /*ar*/
        env->phys_regs[(reg->targno & 0xff) % env->config->nareg] = tmp;
        xtensa_sync_window_from_phys(env);
        break;

    case 2: /*SR*/
        env->sregs[reg->targno & 0xff] = tmp;
        break;

    case 3: /*UR*/
        env->uregs[reg->targno & 0xff] = tmp;
        break;

    case 4: /*f*/
        env->fregs[reg->targno & 0x0f] = make_float32(tmp);
        break;

    case 8: /*a*/
        env->regs[reg->targno & 0x0f] = tmp;
        break;

    default:
        qemu_log("%s to reg %d of unsupported type %d\n",
                 __func__, n, reg->type);
        return 0;
    }

    return 4;
}
#else

static int cpu_gdb_read_register(CPUArchState *env, uint8_t *mem_buf, int n)
{
    return 0;
}

static int cpu_gdb_write_register(CPUArchState *env, uint8_t *mem_buf, int n)
{
    return 0;
}

#endif

#ifdef GDB_CORE_XML
/* Encode data using the encoding for 'x' packets.  */
static int memtox(char *buf, const char *mem, int len)
{
    char *p = buf;
    char c;

    while (len--) {
        c = *(mem++);
        switch (c) {
        case '#': case '$': case '*': case '}':
            *(p++) = '}';
            *(p++) = c ^ 0x20;
            break;
        default:
            *(p++) = c;
            break;
        }
    }
    return p - buf;
}

static const char *get_feature_xml(const char *p, const char **newp)
{
    size_t len;
    int i;
    const char *name;
    static char target_xml[1024];

    len = 0;
    while (p[len] && p[len] != ':')
        len++;
    *newp = p + len;

    name = NULL;
    if (strncmp(p, "target.xml", len) == 0) {
        /* Generate the XML description for this CPU.  */
        if (!target_xml[0]) {
            GDBRegisterState *r;
            CPUState *cpu = first_cpu;

            snprintf(target_xml, sizeof(target_xml),
                     "<?xml version=\"1.0\"?>"
                     "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
                     "<target>"
                     "<xi:include href=\"%s\"/>",
                     GDB_CORE_XML);

            for (r = cpu->gdb_regs; r; r = r->next) {
                pstrcat(target_xml, sizeof(target_xml), "<xi:include href=\"");
                pstrcat(target_xml, sizeof(target_xml), r->xml);
                pstrcat(target_xml, sizeof(target_xml), "\"/>");
            }
            pstrcat(target_xml, sizeof(target_xml), "</target>");
        }
        return target_xml;
    }
    for (i = 0; ; i++) {
        name = xml_builtin[i][0];
        if (!name || (strncmp(name, p, len) == 0 && strlen(name) == len))
            break;
    }
    return name ? xml_builtin[i][1] : NULL;
}
#endif

static int gdb_read_register(CPUState *cpu, uint8_t *mem_buf, int reg)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    CPUArchState *env = cpu->env_ptr;
    GDBRegisterState *r;

    if (reg < cc->gdb_num_core_regs) {
        return cpu_gdb_read_register(env, mem_buf, reg);
    }

    for (r = cpu->gdb_regs; r; r = r->next) {
        if (r->base_reg <= reg && reg < r->base_reg + r->num_regs) {
            return r->get_reg(env, mem_buf, reg - r->base_reg);
        }
    }
    return 0;
}

static int gdb_write_register(CPUState *cpu, uint8_t *mem_buf, int reg)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    CPUArchState *env = cpu->env_ptr;
    GDBRegisterState *r;

    if (reg < cc->gdb_num_core_regs) {
        return cpu_gdb_write_register(env, mem_buf, reg);
    }

    for (r = cpu->gdb_regs; r; r = r->next) {
        if (r->base_reg <= reg && reg < r->base_reg + r->num_regs) {
            return r->set_reg(env, mem_buf, reg - r->base_reg);
        }
    }
    return 0;
}

/* Register a supplemental set of CPU registers.  If g_pos is nonzero it
   specifies the first register number and these registers are included in
   a standard "g" packet.  Direction is relative to gdb, i.e. get_reg is
   gdb reading a CPU register, and set_reg is gdb modifying a CPU register.
 */

void gdb_register_coprocessor(CPUState *cpu,
                              gdb_reg_cb get_reg, gdb_reg_cb set_reg,
                              int num_regs, const char *xml, int g_pos)
{
    GDBRegisterState *s;
    GDBRegisterState **p;

    p = &cpu->gdb_regs;
    while (*p) {
        /* Check for duplicates.  */
        if (strcmp((*p)->xml, xml) == 0)
            return;
        p = &(*p)->next;
    }

    s = g_new0(GDBRegisterState, 1);
    s->base_reg = cpu->gdb_num_regs;
    s->num_regs = num_regs;
    s->get_reg = get_reg;
    s->set_reg = set_reg;
    s->xml = xml;

    /* Add to end of list.  */
    cpu->gdb_num_regs += num_regs;
    *p = s;
    if (g_pos) {
        if (g_pos != s->base_reg) {
            fprintf(stderr, "Error: Bad gdb register numbering for '%s'\n"
                    "Expected %d got %d\n", xml, g_pos, s->base_reg);
        }
    }
}

#ifndef CONFIG_USER_ONLY
static const int xlat_gdb_type[] = {
    [GDB_WATCHPOINT_WRITE]  = BP_GDB | BP_MEM_WRITE,
    [GDB_WATCHPOINT_READ]   = BP_GDB | BP_MEM_READ,
    [GDB_WATCHPOINT_ACCESS] = BP_GDB | BP_MEM_ACCESS,
};
#endif

static int gdb_breakpoint_insert(target_ulong addr, target_ulong len, int type)
{
    CPUState *cpu;
    CPUArchState *env;
    int err = 0;

    if (kvm_enabled()) {
        return kvm_insert_breakpoint(gdbserver_state->c_cpu, addr, len, type);
    }

    switch (type) {
    case GDB_BREAKPOINT_SW:
    case GDB_BREAKPOINT_HW:
        for (cpu = first_cpu; cpu != NULL; cpu = cpu->next_cpu) {
            env = cpu->env_ptr;
            err = cpu_breakpoint_insert(env, addr, BP_GDB, NULL);
            if (err)
                break;
        }
        return err;
#ifndef CONFIG_USER_ONLY
    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_READ:
    case GDB_WATCHPOINT_ACCESS:
        for (cpu = first_cpu; cpu != NULL; cpu = cpu->next_cpu) {
            env = cpu->env_ptr;
            err = cpu_watchpoint_insert(env, addr, len, xlat_gdb_type[type],
                                        NULL);
            if (err)
                break;
        }
        return err;
#endif
    default:
        return -ENOSYS;
    }
}

static int gdb_breakpoint_remove(target_ulong addr, target_ulong len, int type)
{
    CPUState *cpu;
    CPUArchState *env;
    int err = 0;

    if (kvm_enabled()) {
        return kvm_remove_breakpoint(gdbserver_state->c_cpu, addr, len, type);
    }

    switch (type) {
    case GDB_BREAKPOINT_SW:
    case GDB_BREAKPOINT_HW:
        for (cpu = first_cpu; cpu != NULL; cpu = cpu->next_cpu) {
            env = cpu->env_ptr;
            err = cpu_breakpoint_remove(env, addr, BP_GDB);
            if (err)
                break;
        }
        return err;
#ifndef CONFIG_USER_ONLY
    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_READ:
    case GDB_WATCHPOINT_ACCESS:
        for (cpu = first_cpu; cpu != NULL; cpu = cpu->next_cpu) {
            env = cpu->env_ptr;
            err = cpu_watchpoint_remove(env, addr, len, xlat_gdb_type[type]);
            if (err)
                break;
        }
        return err;
#endif
    default:
        return -ENOSYS;
    }
}

static void gdb_breakpoint_remove_all(void)
{
    CPUState *cpu;
    CPUArchState *env;

    if (kvm_enabled()) {
        kvm_remove_all_breakpoints(gdbserver_state->c_cpu);
        return;
    }

    for (cpu = first_cpu; cpu != NULL; cpu = cpu->next_cpu) {
        env = cpu->env_ptr;
        cpu_breakpoint_remove_all(env, BP_GDB);
#ifndef CONFIG_USER_ONLY
        cpu_watchpoint_remove_all(env, BP_GDB);
#endif
    }
}

static void gdb_set_cpu_pc(GDBState *s, target_ulong pc)
{
    CPUState *cpu = s->c_cpu;
    CPUClass *cc = CPU_GET_CLASS(cpu);

    cpu_synchronize_state(cpu);
    if (cc->set_pc) {
        cc->set_pc(cpu, pc);
    }
}

static CPUState *find_cpu(uint32_t thread_id)
{
    CPUState *cpu;

    for (cpu = first_cpu; cpu != NULL; cpu = cpu->next_cpu) {
        if (cpu_index(cpu) == thread_id) {
            return cpu;
        }
    }

    return NULL;
}

static int gdb_handle_packet(GDBState *s, const char *line_buf)
{
    CPUState *cpu;
    const char *p;
    uint32_t thread;
    int ch, reg_size, type, res;
    char buf[MAX_PACKET_LENGTH];
    uint8_t mem_buf[MAX_PACKET_LENGTH];
    uint8_t *registers;
    target_ulong addr, len;

#ifdef DEBUG_GDB
    printf("command='%s'\n", line_buf);
#endif
    p = line_buf;
    ch = *p++;
    switch(ch) {
    case '?':
        /* TODO: Make this return the correct value for user-mode.  */
        snprintf(buf, sizeof(buf), "T%02xthread:%02x;", GDB_SIGNAL_TRAP,
                 cpu_index(s->c_cpu));
        put_packet(s, buf);
        /* Remove all the breakpoints when this query is issued,
         * because gdb is doing and initial connect and the state
         * should be cleaned up.
         */
        gdb_breakpoint_remove_all();
        break;
    case 'c':
        if (*p != '\0') {
            addr = strtoull(p, (char **)&p, 16);
            gdb_set_cpu_pc(s, addr);
        }
        s->signal = 0;
        gdb_continue(s);
	return RS_IDLE;
    case 'C':
        s->signal = gdb_signal_to_target (strtoul(p, (char **)&p, 16));
        if (s->signal == -1)
            s->signal = 0;
        gdb_continue(s);
        return RS_IDLE;
    case 'v':
        if (strncmp(p, "Cont", 4) == 0) {
            int res_signal, res_thread;

            p += 4;
            if (*p == '?') {
                put_packet(s, "vCont;c;C;s;S");
                break;
            }
            res = 0;
            res_signal = 0;
            res_thread = 0;
            while (*p) {
                int action, signal;

                if (*p++ != ';') {
                    res = 0;
                    break;
                }
                action = *p++;
                signal = 0;
                if (action == 'C' || action == 'S') {
                    signal = strtoul(p, (char **)&p, 16);
                } else if (action != 'c' && action != 's') {
                    res = 0;
                    break;
                }
                thread = 0;
                if (*p == ':') {
                    thread = strtoull(p+1, (char **)&p, 16);
                }
                action = tolower(action);
                if (res == 0 || (res == 'c' && action == 's')) {
                    res = action;
                    res_signal = signal;
                    res_thread = thread;
                }
            }
            if (res) {
                if (res_thread != -1 && res_thread != 0) {
                    cpu = find_cpu(res_thread);
                    if (cpu == NULL) {
                        put_packet(s, "E22");
                        break;
                    }
                    s->c_cpu = cpu;
                }
                if (res == 's') {
                    cpu_single_step(s->c_cpu, sstep_flags);
                }
                s->signal = res_signal;
                gdb_continue(s);
                return RS_IDLE;
            }
            break;
        } else {
            goto unknown_command;
        }
    case 'k':
#ifdef CONFIG_USER_ONLY
        /* Kill the target */
        fprintf(stderr, "\nQEMU: Terminated via GDBstub\n");
        exit(0);
#endif
    case 'D':
        /* Detach packet */
        gdb_breakpoint_remove_all();
        gdb_syscall_mode = GDB_SYS_DISABLED;
        gdb_continue(s);
        put_packet(s, "OK");
        break;
    case 's':
        if (*p != '\0') {
            addr = strtoull(p, (char **)&p, 16);
            gdb_set_cpu_pc(s, addr);
        }
        cpu_single_step(s->c_cpu, sstep_flags);
        gdb_continue(s);
	return RS_IDLE;
    case 'F':
        {
            target_ulong ret;
            target_ulong err;

            ret = strtoull(p, (char **)&p, 16);
            if (*p == ',') {
                p++;
                err = strtoull(p, (char **)&p, 16);
            } else {
                err = 0;
            }
            if (*p == ',')
                p++;
            type = *p;
            if (s->current_syscall_cb) {
                s->current_syscall_cb(s->c_cpu, ret, err);
                s->current_syscall_cb = NULL;
            }
            if (type == 'C') {
                put_packet(s, "T02");
            } else {
                gdb_continue(s);
            }
        }
        break;
    case 'g':
        cpu_synchronize_state(s->g_cpu);
        len = 0;
        for (addr = 0; addr < s->g_cpu->gdb_num_regs; addr++) {
            reg_size = gdb_read_register(s->g_cpu, mem_buf + len, addr);
            len += reg_size;
        }
        memtohex(buf, mem_buf, len);
        put_packet(s, buf);
        break;
    case 'G':
        cpu_synchronize_state(s->g_cpu);
        registers = mem_buf;
        len = strlen(p) / 2;
        hextomem((uint8_t *)registers, p, len);
        for (addr = 0; addr < s->g_cpu->gdb_num_regs && len > 0; addr++) {
            reg_size = gdb_write_register(s->g_cpu, registers, addr);
            len -= reg_size;
            registers += reg_size;
        }
        put_packet(s, "OK");
        break;
    case 'm':
        addr = strtoull(p, (char **)&p, 16);
        if (*p == ',')
            p++;
        len = strtoull(p, NULL, 16);
        if (target_memory_rw_debug(s->g_cpu, addr, mem_buf, len, false) != 0) {
            put_packet (s, "E14");
        } else {
            memtohex(buf, mem_buf, len);
            put_packet(s, buf);
        }
        break;
    case 'M':
        addr = strtoull(p, (char **)&p, 16);
        if (*p == ',')
            p++;
        len = strtoull(p, (char **)&p, 16);
        if (*p == ':')
            p++;
        hextomem(mem_buf, p, len);
        if (target_memory_rw_debug(s->g_cpu, addr, mem_buf, len,
                                   true) != 0) {
            put_packet(s, "E14");
        } else {
            put_packet(s, "OK");
        }
        break;
    case 'p':
        /* Older gdb are really dumb, and don't use 'g' if 'p' is avaialable.
           This works, but can be very slow.  Anything new enough to
           understand XML also knows how to use this properly.  */
        if (!gdb_has_xml)
            goto unknown_command;
        addr = strtoull(p, (char **)&p, 16);
        reg_size = gdb_read_register(s->g_cpu, mem_buf, addr);
        if (reg_size) {
            memtohex(buf, mem_buf, reg_size);
            put_packet(s, buf);
        } else {
            put_packet(s, "E14");
        }
        break;
    case 'P':
        if (!gdb_has_xml)
            goto unknown_command;
        addr = strtoull(p, (char **)&p, 16);
        if (*p == '=')
            p++;
        reg_size = strlen(p) / 2;
        hextomem(mem_buf, p, reg_size);
        gdb_write_register(s->g_cpu, mem_buf, addr);
        put_packet(s, "OK");
        break;
    case 'Z':
    case 'z':
        type = strtoul(p, (char **)&p, 16);
        if (*p == ',')
            p++;
        addr = strtoull(p, (char **)&p, 16);
        if (*p == ',')
            p++;
        len = strtoull(p, (char **)&p, 16);
        if (ch == 'Z')
            res = gdb_breakpoint_insert(addr, len, type);
        else
            res = gdb_breakpoint_remove(addr, len, type);
        if (res >= 0)
             put_packet(s, "OK");
        else if (res == -ENOSYS)
            put_packet(s, "");
        else
            put_packet(s, "E22");
        break;
    case 'H':
        type = *p++;
        thread = strtoull(p, (char **)&p, 16);
        if (thread == -1 || thread == 0) {
            put_packet(s, "OK");
            break;
        }
        cpu = find_cpu(thread);
        if (cpu == NULL) {
            put_packet(s, "E22");
            break;
        }
        switch (type) {
        case 'c':
            s->c_cpu = cpu;
            put_packet(s, "OK");
            break;
        case 'g':
            s->g_cpu = cpu;
            put_packet(s, "OK");
            break;
        default:
             put_packet(s, "E22");
             break;
        }
        break;
    case 'T':
        thread = strtoull(p, (char **)&p, 16);
        cpu = find_cpu(thread);

        if (cpu != NULL) {
            put_packet(s, "OK");
        } else {
            put_packet(s, "E22");
        }
        break;
    case 'q':
    case 'Q':
        /* parse any 'q' packets here */
        if (!strcmp(p,"qemu.sstepbits")) {
            /* Query Breakpoint bit definitions */
            snprintf(buf, sizeof(buf), "ENABLE=%x,NOIRQ=%x,NOTIMER=%x",
                     SSTEP_ENABLE,
                     SSTEP_NOIRQ,
                     SSTEP_NOTIMER);
            put_packet(s, buf);
            break;
        } else if (strncmp(p,"qemu.sstep",10) == 0) {
            /* Display or change the sstep_flags */
            p += 10;
            if (*p != '=') {
                /* Display current setting */
                snprintf(buf, sizeof(buf), "0x%x", sstep_flags);
                put_packet(s, buf);
                break;
            }
            p++;
            type = strtoul(p, (char **)&p, 16);
            sstep_flags = type;
            put_packet(s, "OK");
            break;
        } else if (strcmp(p,"C") == 0) {
            /* "Current thread" remains vague in the spec, so always return
             *  the first CPU (gdb returns the first thread). */
            put_packet(s, "QC1");
            break;
        } else if (strcmp(p,"fThreadInfo") == 0) {
            s->query_cpu = first_cpu;
            goto report_cpuinfo;
        } else if (strcmp(p,"sThreadInfo") == 0) {
        report_cpuinfo:
            if (s->query_cpu) {
                snprintf(buf, sizeof(buf), "m%x", cpu_index(s->query_cpu));
                put_packet(s, buf);
                s->query_cpu = s->query_cpu->next_cpu;
            } else
                put_packet(s, "l");
            break;
        } else if (strncmp(p,"ThreadExtraInfo,", 16) == 0) {
            thread = strtoull(p+16, (char **)&p, 16);
            cpu = find_cpu(thread);
            if (cpu != NULL) {
                cpu_synchronize_state(cpu);
                len = snprintf((char *)mem_buf, sizeof(mem_buf),
                               "CPU#%d [%s]", cpu->cpu_index,
                               cpu->halted ? "halted " : "running");
                memtohex(buf, mem_buf, len);
                put_packet(s, buf);
            }
            break;
        }
#ifdef CONFIG_USER_ONLY
        else if (strncmp(p, "Offsets", 7) == 0) {
            CPUArchState *env = s->c_cpu->env_ptr;
            TaskState *ts = env->opaque;

            snprintf(buf, sizeof(buf),
                     "Text=" TARGET_ABI_FMT_lx ";Data=" TARGET_ABI_FMT_lx
                     ";Bss=" TARGET_ABI_FMT_lx,
                     ts->info->code_offset,
                     ts->info->data_offset,
                     ts->info->data_offset);
            put_packet(s, buf);
            break;
        }
#else /* !CONFIG_USER_ONLY */
        else if (strncmp(p, "Rcmd,", 5) == 0) {
            int len = strlen(p + 5);

            if ((len % 2) != 0) {
                put_packet(s, "E01");
                break;
            }
            hextomem(mem_buf, p + 5, len);
            len = len / 2;
            mem_buf[len++] = 0;
            qemu_chr_be_write(s->mon_chr, mem_buf, len);
            put_packet(s, "OK");
            break;
        }
#endif /* !CONFIG_USER_ONLY */
        if (strncmp(p, "Supported", 9) == 0) {
            snprintf(buf, sizeof(buf), "PacketSize=%x", MAX_PACKET_LENGTH);
#ifdef GDB_CORE_XML
            pstrcat(buf, sizeof(buf), ";qXfer:features:read+");
#endif
            put_packet(s, buf);
            break;
        }
#ifdef GDB_CORE_XML
        if (strncmp(p, "Xfer:features:read:", 19) == 0) {
            const char *xml;
            target_ulong total_len;

            gdb_has_xml = 1;
            p += 19;
            xml = get_feature_xml(p, &p);
            if (!xml) {
                snprintf(buf, sizeof(buf), "E00");
                put_packet(s, buf);
                break;
            }

            if (*p == ':')
                p++;
            addr = strtoul(p, (char **)&p, 16);
            if (*p == ',')
                p++;
            len = strtoul(p, (char **)&p, 16);

            total_len = strlen(xml);
            if (addr > total_len) {
                snprintf(buf, sizeof(buf), "E00");
                put_packet(s, buf);
                break;
            }
            if (len > (MAX_PACKET_LENGTH - 5) / 2)
                len = (MAX_PACKET_LENGTH - 5) / 2;
            if (len < total_len - addr) {
                buf[0] = 'm';
                len = memtox(buf + 1, xml + addr, len);
            } else {
                buf[0] = 'l';
                len = memtox(buf + 1, xml + addr, total_len - addr);
            }
            put_packet_binary(s, buf, len + 1);
            break;
        }
#endif
        /* Unrecognised 'q' command.  */
        goto unknown_command;

    default:
    unknown_command:
        /* put empty packet */
        buf[0] = '\0';
        put_packet(s, buf);
        break;
    }
    return RS_IDLE;
}

void gdb_set_stop_cpu(CPUState *cpu)
{
    gdbserver_state->c_cpu = cpu;
    gdbserver_state->g_cpu = cpu;
}

#ifndef CONFIG_USER_ONLY
static void gdb_vm_state_change(void *opaque, int running, RunState state)
{
    GDBState *s = gdbserver_state;
    CPUArchState *env = s->c_cpu->env_ptr;
    CPUState *cpu = s->c_cpu;
    char buf[256];
    const char *type;
    int ret;

    if (running || s->state == RS_INACTIVE) {
        return;
    }
    /* Is there a GDB syscall waiting to be sent?  */
    if (s->current_syscall_cb) {
        put_packet(s, s->syscall_buf);
        return;
    }
    switch (state) {
    case RUN_STATE_DEBUG:
        if (env->watchpoint_hit) {
            switch (env->watchpoint_hit->flags & BP_MEM_ACCESS) {
            case BP_MEM_READ:
                type = "r";
                break;
            case BP_MEM_ACCESS:
                type = "a";
                break;
            default:
                type = "";
                break;
            }
            snprintf(buf, sizeof(buf),
                     "T%02xthread:%02x;%swatch:" TARGET_FMT_lx ";",
                     GDB_SIGNAL_TRAP, cpu_index(cpu), type,
                     env->watchpoint_hit->vaddr);
            env->watchpoint_hit = NULL;
            goto send_packet;
        }
        tb_flush(env);
        ret = GDB_SIGNAL_TRAP;
        break;
    case RUN_STATE_PAUSED:
        ret = GDB_SIGNAL_INT;
        break;
    case RUN_STATE_SHUTDOWN:
        ret = GDB_SIGNAL_QUIT;
        break;
    case RUN_STATE_IO_ERROR:
        ret = GDB_SIGNAL_IO;
        break;
    case RUN_STATE_WATCHDOG:
        ret = GDB_SIGNAL_ALRM;
        break;
    case RUN_STATE_INTERNAL_ERROR:
        ret = GDB_SIGNAL_ABRT;
        break;
    case RUN_STATE_SAVE_VM:
    case RUN_STATE_RESTORE_VM:
        return;
    case RUN_STATE_FINISH_MIGRATE:
        ret = GDB_SIGNAL_XCPU;
        break;
    default:
        ret = GDB_SIGNAL_UNKNOWN;
        break;
    }
    snprintf(buf, sizeof(buf), "T%02xthread:%02x;", ret, cpu_index(cpu));

send_packet:
    put_packet(s, buf);

    /* disable single step if it was enabled */
    cpu_single_step(cpu, 0);
}
#endif

/* Send a gdb syscall request.
   This accepts limited printf-style format specifiers, specifically:
    %x  - target_ulong argument printed in hex.
    %lx - 64-bit argument printed in hex.
    %s  - string pointer (target_ulong) and length (int) pair.  */
void gdb_do_syscall(gdb_syscall_complete_cb cb, const char *fmt, ...)
{
    va_list va;
    char *p;
    char *p_end;
    target_ulong addr;
    uint64_t i64;
    GDBState *s;

    s = gdbserver_state;
    if (!s)
        return;
    s->current_syscall_cb = cb;
#ifndef CONFIG_USER_ONLY
    vm_stop(RUN_STATE_DEBUG);
#endif
    va_start(va, fmt);
    p = s->syscall_buf;
    p_end = &s->syscall_buf[sizeof(s->syscall_buf)];
    *(p++) = 'F';
    while (*fmt) {
        if (*fmt == '%') {
            fmt++;
            switch (*fmt++) {
            case 'x':
                addr = va_arg(va, target_ulong);
                p += snprintf(p, p_end - p, TARGET_FMT_lx, addr);
                break;
            case 'l':
                if (*(fmt++) != 'x')
                    goto bad_format;
                i64 = va_arg(va, uint64_t);
                p += snprintf(p, p_end - p, "%" PRIx64, i64);
                break;
            case 's':
                addr = va_arg(va, target_ulong);
                p += snprintf(p, p_end - p, TARGET_FMT_lx "/%x",
                              addr, va_arg(va, int));
                break;
            default:
            bad_format:
                fprintf(stderr, "gdbstub: Bad syscall format string '%s'\n",
                        fmt - 1);
                break;
            }
        } else {
            *(p++) = *(fmt++);
        }
    }
    *p = 0;
    va_end(va);
#ifdef CONFIG_USER_ONLY
    put_packet(s, s->syscall_buf);
    gdb_handlesig(s->c_cpu, 0);
#else
    /* In this case wait to send the syscall packet until notification that
       the CPU has stopped.  This must be done because if the packet is sent
       now the reply from the syscall request could be received while the CPU
       is still in the running state, which can cause packets to be dropped
       and state transition 'T' packets to be sent while the syscall is still
       being processed.  */
    cpu_exit(s->c_cpu);
#endif
}

static void gdb_read_byte(GDBState *s, int ch)
{
    int i, csum;
    uint8_t reply;

#ifndef CONFIG_USER_ONLY
    if (s->last_packet_len) {
        /* Waiting for a response to the last packet.  If we see the start
           of a new command then abandon the previous response.  */
        if (ch == '-') {
#ifdef DEBUG_GDB
            printf("Got NACK, retransmitting\n");
#endif
            put_buffer(s, (uint8_t *)s->last_packet, s->last_packet_len);
        }
#ifdef DEBUG_GDB
        else if (ch == '+')
            printf("Got ACK\n");
        else
            printf("Got '%c' when expecting ACK/NACK\n", ch);
#endif
        if (ch == '+' || ch == '$')
            s->last_packet_len = 0;
        if (ch != '$')
            return;
    }
    if (runstate_is_running()) {
        /* when the CPU is running, we cannot do anything except stop
           it when receiving a char */
        vm_stop(RUN_STATE_PAUSED);
    } else
#endif
    {
        switch(s->state) {
        case RS_IDLE:
            if (ch == '$') {
                s->line_buf_index = 0;
                s->state = RS_GETLINE;
            }
            break;
        case RS_GETLINE:
            if (ch == '#') {
            s->state = RS_CHKSUM1;
            } else if (s->line_buf_index >= sizeof(s->line_buf) - 1) {
                s->state = RS_IDLE;
            } else {
            s->line_buf[s->line_buf_index++] = ch;
            }
            break;
        case RS_CHKSUM1:
            s->line_buf[s->line_buf_index] = '\0';
            s->line_csum = fromhex(ch) << 4;
            s->state = RS_CHKSUM2;
            break;
        case RS_CHKSUM2:
            s->line_csum |= fromhex(ch);
            csum = 0;
            for(i = 0; i < s->line_buf_index; i++) {
                csum += s->line_buf[i];
            }
            if (s->line_csum != (csum & 0xff)) {
                reply = '-';
                put_buffer(s, &reply, 1);
                s->state = RS_IDLE;
            } else {
                reply = '+';
                put_buffer(s, &reply, 1);
                s->state = gdb_handle_packet(s, s->line_buf);
            }
            break;
        default:
            abort();
        }
    }
}

/* Tell the remote gdb that the process has exited.  */
void gdb_exit(CPUArchState *env, int code)
{
  GDBState *s;
  char buf[4];

  s = gdbserver_state;
  if (!s) {
      return;
  }
#ifdef CONFIG_USER_ONLY
  if (gdbserver_fd < 0 || s->fd < 0) {
      return;
  }
#endif

  snprintf(buf, sizeof(buf), "W%02x", (uint8_t)code);
  put_packet(s, buf);

#ifndef CONFIG_USER_ONLY
  if (s->chr) {
      qemu_chr_delete(s->chr);
  }
#endif
}

#ifdef CONFIG_USER_ONLY
int
gdb_queuesig (void)
{
    GDBState *s;

    s = gdbserver_state;

    if (gdbserver_fd < 0 || s->fd < 0)
        return 0;
    else
        return 1;
}

int
gdb_handlesig(CPUState *cpu, int sig)
{
    CPUArchState *env = cpu->env_ptr;
    GDBState *s;
    char buf[256];
    int n;

    s = gdbserver_state;
    if (gdbserver_fd < 0 || s->fd < 0) {
        return sig;
    }

    /* disable single step if it was enabled */
    cpu_single_step(cpu, 0);
    tb_flush(env);

    if (sig != 0) {
        snprintf(buf, sizeof(buf), "S%02x", target_signal_to_gdb(sig));
        put_packet(s, buf);
    }
    /* put_packet() might have detected that the peer terminated the
       connection.  */
    if (s->fd < 0) {
        return sig;
    }

    sig = 0;
    s->state = RS_IDLE;
    s->running_state = 0;
    while (s->running_state == 0) {
        n = read(s->fd, buf, 256);
        if (n > 0) {
            int i;

            for (i = 0; i < n; i++) {
                gdb_read_byte(s, buf[i]);
            }
        } else if (n == 0 || errno != EAGAIN) {
            /* XXX: Connection closed.  Should probably wait for another
               connection before continuing.  */
            return sig;
        }
    }
    sig = s->signal;
    s->signal = 0;
    return sig;
}

/* Tell the remote gdb that the process has exited due to SIG.  */
void gdb_signalled(CPUArchState *env, int sig)
{
    GDBState *s;
    char buf[4];

    s = gdbserver_state;
    if (gdbserver_fd < 0 || s->fd < 0) {
        return;
    }

    snprintf(buf, sizeof(buf), "X%02x", target_signal_to_gdb(sig));
    put_packet(s, buf);
}

static void gdb_accept(void)
{
    GDBState *s;
    struct sockaddr_in sockaddr;
    socklen_t len;
    int fd;

    for(;;) {
        len = sizeof(sockaddr);
        fd = accept(gdbserver_fd, (struct sockaddr *)&sockaddr, &len);
        if (fd < 0 && errno != EINTR) {
            perror("accept");
            return;
        } else if (fd >= 0) {
#ifndef _WIN32
            fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
            break;
        }
    }

    /* set short latency */
    socket_set_nodelay(fd);

    s = g_malloc0(sizeof(GDBState));
    s->c_cpu = first_cpu;
    s->g_cpu = first_cpu;
    s->fd = fd;
    gdb_has_xml = 0;

    gdbserver_state = s;

    fcntl(fd, F_SETFL, O_NONBLOCK);
}

static int gdbserver_open(int port)
{
    struct sockaddr_in sockaddr;
    int fd, val, ret;

    fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
#ifndef _WIN32
    fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif

    /* allow fast reuse */
    val = 1;
    qemu_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(port);
    sockaddr.sin_addr.s_addr = 0;
    ret = bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (ret < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    ret = listen(fd, 0);
    if (ret < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

int gdbserver_start(int port)
{
    gdbserver_fd = gdbserver_open(port);
    if (gdbserver_fd < 0)
        return -1;
    /* accept connections */
    gdb_accept();
    return 0;
}

/* Disable gdb stub for child processes.  */
void gdbserver_fork(CPUArchState *env)
{
    GDBState *s = gdbserver_state;
    if (gdbserver_fd < 0 || s->fd < 0)
      return;
    close(s->fd);
    s->fd = -1;
    cpu_breakpoint_remove_all(env, BP_GDB);
    cpu_watchpoint_remove_all(env, BP_GDB);
}
#else
static int gdb_chr_can_receive(void *opaque)
{
  /* We can handle an arbitrarily large amount of data.
   Pick the maximum packet size, which is as good as anything.  */
  return MAX_PACKET_LENGTH;
}

static void gdb_chr_receive(void *opaque, const uint8_t *buf, int size)
{
    int i;

    for (i = 0; i < size; i++) {
        gdb_read_byte(gdbserver_state, buf[i]);
    }
}

static void gdb_chr_event(void *opaque, int event)
{
    switch (event) {
    case CHR_EVENT_OPENED:
        vm_stop(RUN_STATE_PAUSED);
        gdb_has_xml = 0;
        break;
    default:
        break;
    }
}

static void gdb_monitor_output(GDBState *s, const char *msg, int len)
{
    char buf[MAX_PACKET_LENGTH];

    buf[0] = 'O';
    if (len > (MAX_PACKET_LENGTH/2) - 1)
        len = (MAX_PACKET_LENGTH/2) - 1;
    memtohex(buf + 1, (uint8_t *)msg, len);
    put_packet(s, buf);
}

static int gdb_monitor_write(CharDriverState *chr, const uint8_t *buf, int len)
{
    const char *p = (const char *)buf;
    int max_sz;

    max_sz = (sizeof(gdbserver_state->last_packet) - 2) / 2;
    for (;;) {
        if (len <= max_sz) {
            gdb_monitor_output(gdbserver_state, p, len);
            break;
        }
        gdb_monitor_output(gdbserver_state, p, max_sz);
        p += max_sz;
        len -= max_sz;
    }
    return len;
}

#ifndef _WIN32
static void gdb_sigterm_handler(int signal)
{
    if (runstate_is_running()) {
        vm_stop(RUN_STATE_PAUSED);
    }
}
#endif

int gdbserver_start(const char *device)
{
    GDBState *s;
    char gdbstub_device_name[128];
    CharDriverState *chr = NULL;
    CharDriverState *mon_chr;

    if (!device)
        return -1;
    if (strcmp(device, "none") != 0) {
        if (strstart(device, "tcp:", NULL)) {
            /* enforce required TCP attributes */
            snprintf(gdbstub_device_name, sizeof(gdbstub_device_name),
                     "%s,nowait,nodelay,server", device);
            device = gdbstub_device_name;
        }
#ifndef _WIN32
        else if (strcmp(device, "stdio") == 0) {
            struct sigaction act;

            memset(&act, 0, sizeof(act));
            act.sa_handler = gdb_sigterm_handler;
            sigaction(SIGINT, &act, NULL);
        }
#endif
        chr = qemu_chr_new("gdb", device, NULL);
        if (!chr)
            return -1;

        qemu_chr_fe_claim_no_fail(chr);
        qemu_chr_add_handlers(chr, gdb_chr_can_receive, gdb_chr_receive,
                              gdb_chr_event, NULL);
    }

    s = gdbserver_state;
    if (!s) {
        s = g_malloc0(sizeof(GDBState));
        gdbserver_state = s;

        qemu_add_vm_change_state_handler(gdb_vm_state_change, NULL);

        /* Initialize a monitor terminal for gdb */
        mon_chr = g_malloc0(sizeof(*mon_chr));
        mon_chr->chr_write = gdb_monitor_write;
        monitor_init(mon_chr, 0);
    } else {
        if (s->chr)
            qemu_chr_delete(s->chr);
        mon_chr = s->mon_chr;
        memset(s, 0, sizeof(GDBState));
    }
    s->c_cpu = first_cpu;
    s->g_cpu = first_cpu;
    s->chr = chr;
    s->state = chr ? RS_IDLE : RS_INACTIVE;
    s->mon_chr = mon_chr;
    s->current_syscall_cb = NULL;

    return 0;
}
#endif
