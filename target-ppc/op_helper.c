/*
 *  PowerPC emulation helpers for QEMU.
 *
 *  Copyright (c) 2003-2007 Jocelyn Mayer
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
#include <string.h>
#include "cpu.h"
#include "dyngen-exec.h"
#include "host-utils.h"
#include "helper.h"

#include "helper_regs.h"

#if !defined(CONFIG_USER_ONLY)
#include "softmmu_exec.h"
#endif /* !defined(CONFIG_USER_ONLY) */

//#define DEBUG_OP
//#define DEBUG_SOFTWARE_TLB

#ifdef DEBUG_SOFTWARE_TLB
#  define LOG_SWTLB(...) qemu_log(__VA_ARGS__)
#else
#  define LOG_SWTLB(...) do { } while (0)
#endif

/*****************************************************************************/
/* SPR accesses */
void helper_load_dump_spr(uint32_t sprn)
{
    qemu_log("Read SPR %d %03x => " TARGET_FMT_lx "\n", sprn, sprn,
             env->spr[sprn]);
}

void helper_store_dump_spr(uint32_t sprn)
{
    qemu_log("Write SPR %d %03x <= " TARGET_FMT_lx "\n", sprn, sprn,
             env->spr[sprn]);
}

target_ulong helper_load_tbl(void)
{
    return (target_ulong)cpu_ppc_load_tbl(env);
}

target_ulong helper_load_tbu(void)
{
    return cpu_ppc_load_tbu(env);
}

target_ulong helper_load_atbl(void)
{
    return (target_ulong)cpu_ppc_load_atbl(env);
}

target_ulong helper_load_atbu(void)
{
    return cpu_ppc_load_atbu(env);
}

#if defined(TARGET_PPC64) && !defined(CONFIG_USER_ONLY)
target_ulong helper_load_purr(void)
{
    return (target_ulong)cpu_ppc_load_purr(env);
}
#endif

target_ulong helper_load_601_rtcl(void)
{
    return cpu_ppc601_load_rtcl(env);
}

target_ulong helper_load_601_rtcu(void)
{
    return cpu_ppc601_load_rtcu(env);
}

#if !defined(CONFIG_USER_ONLY)
#if defined(TARGET_PPC64)
void helper_store_asr(target_ulong val)
{
    ppc_store_asr(env, val);
}
#endif

void helper_store_sdr1(target_ulong val)
{
    ppc_store_sdr1(env, val);
}

void helper_store_tbl(target_ulong val)
{
    cpu_ppc_store_tbl(env, val);
}

void helper_store_tbu(target_ulong val)
{
    cpu_ppc_store_tbu(env, val);
}

void helper_store_atbl(target_ulong val)
{
    cpu_ppc_store_atbl(env, val);
}

void helper_store_atbu(target_ulong val)
{
    cpu_ppc_store_atbu(env, val);
}

void helper_store_601_rtcl(target_ulong val)
{
    cpu_ppc601_store_rtcl(env, val);
}

void helper_store_601_rtcu(target_ulong val)
{
    cpu_ppc601_store_rtcu(env, val);
}

target_ulong helper_load_decr(void)
{
    return cpu_ppc_load_decr(env);
}

void helper_store_decr(target_ulong val)
{
    cpu_ppc_store_decr(env, val);
}

void helper_store_hid0_601(target_ulong val)
{
    target_ulong hid0;

    hid0 = env->spr[SPR_HID0];
    if ((val ^ hid0) & 0x00000008) {
        /* Change current endianness */
        env->hflags &= ~(1 << MSR_LE);
        env->hflags_nmsr &= ~(1 << MSR_LE);
        env->hflags_nmsr |= (1 << MSR_LE) & (((val >> 3) & 1) << MSR_LE);
        env->hflags |= env->hflags_nmsr;
        qemu_log("%s: set endianness to %c => " TARGET_FMT_lx "\n", __func__,
                 val & 0x8 ? 'l' : 'b', env->hflags);
    }
    env->spr[SPR_HID0] = (uint32_t)val;
}

void helper_store_403_pbr(uint32_t num, target_ulong value)
{
    if (likely(env->pb[num] != value)) {
        env->pb[num] = value;
        /* Should be optimized */
        tlb_flush(env, 1);
    }
}

target_ulong helper_load_40x_pit(void)
{
    return load_40x_pit(env);
}

void helper_store_40x_pit(target_ulong val)
{
    store_40x_pit(env, val);
}

void helper_store_40x_dbcr0(target_ulong val)
{
    store_40x_dbcr0(env, val);
}

void helper_store_40x_sler(target_ulong val)
{
    store_40x_sler(env, val);
}

void helper_store_booke_tcr(target_ulong val)
{
    store_booke_tcr(env, val);
}

void helper_store_booke_tsr(target_ulong val)
{
    store_booke_tsr(env, val);
}

void helper_store_ibatu(uint32_t nr, target_ulong val)
{
    ppc_store_ibatu(env, nr, val);
}

void helper_store_ibatl(uint32_t nr, target_ulong val)
{
    ppc_store_ibatl(env, nr, val);
}

void helper_store_dbatu(uint32_t nr, target_ulong val)
{
    ppc_store_dbatu(env, nr, val);
}

void helper_store_dbatl(uint32_t nr, target_ulong val)
{
    ppc_store_dbatl(env, nr, val);
}

void helper_store_601_batl(uint32_t nr, target_ulong val)
{
    ppc_store_ibatl_601(env, nr, val);
}

void helper_store_601_batu(uint32_t nr, target_ulong val)
{
    ppc_store_ibatu_601(env, nr, val);
}
#endif

/*****************************************************************************/
/* Memory load and stores */

static inline target_ulong addr_add(target_ulong addr, target_long arg)
{
#if defined(TARGET_PPC64)
    if (!msr_sf) {
        return (uint32_t)(addr + arg);
    } else
#endif
    {
        return addr + arg;
    }
}

void helper_lmw(target_ulong addr, uint32_t reg)
{
    for (; reg < 32; reg++) {
        if (msr_le) {
            env->gpr[reg] = bswap32(ldl(addr));
        } else {
            env->gpr[reg] = ldl(addr);
        }
        addr = addr_add(addr, 4);
    }
}

void helper_stmw(target_ulong addr, uint32_t reg)
{
    for (; reg < 32; reg++) {
        if (msr_le) {
            stl(addr, bswap32((uint32_t)env->gpr[reg]));
        } else {
            stl(addr, (uint32_t)env->gpr[reg]);
        }
        addr = addr_add(addr, 4);
    }
}

void helper_lsw(target_ulong addr, uint32_t nb, uint32_t reg)
{
    int sh;

    for (; nb > 3; nb -= 4) {
        env->gpr[reg] = ldl(addr);
        reg = (reg + 1) % 32;
        addr = addr_add(addr, 4);
    }
    if (unlikely(nb > 0)) {
        env->gpr[reg] = 0;
        for (sh = 24; nb > 0; nb--, sh -= 8) {
            env->gpr[reg] |= ldub(addr) << sh;
            addr = addr_add(addr, 1);
        }
    }
}
/* PPC32 specification says we must generate an exception if
 * rA is in the range of registers to be loaded.
 * In an other hand, IBM says this is valid, but rA won't be loaded.
 * For now, I'll follow the spec...
 */
void helper_lswx(target_ulong addr, uint32_t reg, uint32_t ra, uint32_t rb)
{
    if (likely(xer_bc != 0)) {
        if (unlikely((ra != 0 && reg < ra && (reg + xer_bc) > ra) ||
                     (reg < rb && (reg + xer_bc) > rb))) {
            helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                       POWERPC_EXCP_INVAL |
                                       POWERPC_EXCP_INVAL_LSWX);
        } else {
            helper_lsw(addr, xer_bc, reg);
        }
    }
}

void helper_stsw(target_ulong addr, uint32_t nb, uint32_t reg)
{
    int sh;

    for (; nb > 3; nb -= 4) {
        stl(addr, env->gpr[reg]);
        reg = (reg + 1) % 32;
        addr = addr_add(addr, 4);
    }
    if (unlikely(nb > 0)) {
        for (sh = 24; nb > 0; nb--, sh -= 8) {
            stb(addr, (env->gpr[reg] >> sh) & 0xFF);
            addr = addr_add(addr, 1);
        }
    }
}

static void do_dcbz(target_ulong addr, int dcache_line_size)
{
    int i;

    addr &= ~(dcache_line_size - 1);
    for (i = 0; i < dcache_line_size; i += 4) {
        stl(addr + i, 0);
    }
    if (env->reserve_addr == addr) {
        env->reserve_addr = (target_ulong)-1ULL;
    }
}

void helper_dcbz(target_ulong addr)
{
    do_dcbz(addr, env->dcache_line_size);
}

void helper_dcbz_970(target_ulong addr)
{
    if (((env->spr[SPR_970_HID5] >> 7) & 0x3) == 1) {
        do_dcbz(addr, 32);
    } else {
        do_dcbz(addr, env->dcache_line_size);
    }
}

void helper_icbi(target_ulong addr)
{
    addr &= ~(env->dcache_line_size - 1);
    /* Invalidate one cache line :
     * PowerPC specification says this is to be treated like a load
     * (not a fetch) by the MMU. To be sure it will be so,
     * do the load "by hand".
     */
    ldl(addr);
}

/* XXX: to be tested */
target_ulong helper_lscbx(target_ulong addr, uint32_t reg, uint32_t ra,
                          uint32_t rb)
{
    int i, c, d;

    d = 24;
    for (i = 0; i < xer_bc; i++) {
        c = ldub(addr);
        addr = addr_add(addr, 1);
        /* ra (if not 0) and rb are never modified */
        if (likely(reg != rb && (ra == 0 || reg != ra))) {
            env->gpr[reg] = (env->gpr[reg] & ~(0xFF << d)) | (c << d);
        }
        if (unlikely(c == xer_cmp)) {
            break;
        }
        if (likely(d != 0)) {
            d -= 8;
        } else {
            d = 24;
            reg++;
            reg = reg & 0x1F;
        }
    }
    return i;
}

/*****************************************************************************/
/* Fixed point operations helpers */
#if defined(TARGET_PPC64)

/* multiply high word */
uint64_t helper_mulhd(uint64_t arg1, uint64_t arg2)
{
    uint64_t tl, th;

    muls64(&tl, &th, arg1, arg2);
    return th;
}

/* multiply high word unsigned */
uint64_t helper_mulhdu(uint64_t arg1, uint64_t arg2)
{
    uint64_t tl, th;

    mulu64(&tl, &th, arg1, arg2);
    return th;
}

uint64_t helper_mulldo(uint64_t arg1, uint64_t arg2)
{
    int64_t th;
    uint64_t tl;

    muls64(&tl, (uint64_t *)&th, arg1, arg2);
    /* If th != 0 && th != -1, then we had an overflow */
    if (likely((uint64_t)(th + 1) <= 1)) {
        env->xer &= ~(1 << XER_OV);
    } else {
        env->xer |= (1 << XER_OV) | (1 << XER_SO);
    }
    return (int64_t)tl;
}
#endif

target_ulong helper_cntlzw(target_ulong t)
{
    return clz32(t);
}

#if defined(TARGET_PPC64)
target_ulong helper_cntlzd(target_ulong t)
{
    return clz64(t);
}
#endif

/* shift right arithmetic helper */
target_ulong helper_sraw(target_ulong value, target_ulong shift)
{
    int32_t ret;

    if (likely(!(shift & 0x20))) {
        if (likely((uint32_t)shift != 0)) {
            shift &= 0x1f;
            ret = (int32_t)value >> shift;
            if (likely(ret >= 0 || (value & ((1 << shift) - 1)) == 0)) {
                env->xer &= ~(1 << XER_CA);
            } else {
                env->xer |= (1 << XER_CA);
            }
        } else {
            ret = (int32_t)value;
            env->xer &= ~(1 << XER_CA);
        }
    } else {
        ret = (int32_t)value >> 31;
        if (ret) {
            env->xer |= (1 << XER_CA);
        } else {
            env->xer &= ~(1 << XER_CA);
        }
    }
    return (target_long)ret;
}

#if defined(TARGET_PPC64)
target_ulong helper_srad(target_ulong value, target_ulong shift)
{
    int64_t ret;

    if (likely(!(shift & 0x40))) {
        if (likely((uint64_t)shift != 0)) {
            shift &= 0x3f;
            ret = (int64_t)value >> shift;
            if (likely(ret >= 0 || (value & ((1 << shift) - 1)) == 0)) {
                env->xer &= ~(1 << XER_CA);
            } else {
                env->xer |= (1 << XER_CA);
            }
        } else {
            ret = (int64_t)value;
            env->xer &= ~(1 << XER_CA);
        }
    } else {
        ret = (int64_t)value >> 63;
        if (ret) {
            env->xer |= (1 << XER_CA);
        } else {
            env->xer &= ~(1 << XER_CA);
        }
    }
    return ret;
}
#endif

#if defined(TARGET_PPC64)
target_ulong helper_popcntb(target_ulong val)
{
    val = (val & 0x5555555555555555ULL) + ((val >>  1) &
                                           0x5555555555555555ULL);
    val = (val & 0x3333333333333333ULL) + ((val >>  2) &
                                           0x3333333333333333ULL);
    val = (val & 0x0f0f0f0f0f0f0f0fULL) + ((val >>  4) &
                                           0x0f0f0f0f0f0f0f0fULL);
    return val;
}

target_ulong helper_popcntw(target_ulong val)
{
    val = (val & 0x5555555555555555ULL) + ((val >>  1) &
                                           0x5555555555555555ULL);
    val = (val & 0x3333333333333333ULL) + ((val >>  2) &
                                           0x3333333333333333ULL);
    val = (val & 0x0f0f0f0f0f0f0f0fULL) + ((val >>  4) &
                                           0x0f0f0f0f0f0f0f0fULL);
    val = (val & 0x00ff00ff00ff00ffULL) + ((val >>  8) &
                                           0x00ff00ff00ff00ffULL);
    val = (val & 0x0000ffff0000ffffULL) + ((val >> 16) &
                                           0x0000ffff0000ffffULL);
    return val;
}

target_ulong helper_popcntd(target_ulong val)
{
    return ctpop64(val);
}
#else
target_ulong helper_popcntb(target_ulong val)
{
    val = (val & 0x55555555) + ((val >>  1) & 0x55555555);
    val = (val & 0x33333333) + ((val >>  2) & 0x33333333);
    val = (val & 0x0f0f0f0f) + ((val >>  4) & 0x0f0f0f0f);
    return val;
}

target_ulong helper_popcntw(target_ulong val)
{
    val = (val & 0x55555555) + ((val >>  1) & 0x55555555);
    val = (val & 0x33333333) + ((val >>  2) & 0x33333333);
    val = (val & 0x0f0f0f0f) + ((val >>  4) & 0x0f0f0f0f);
    val = (val & 0x00ff00ff) + ((val >>  8) & 0x00ff00ff);
    val = (val & 0x0000ffff) + ((val >> 16) & 0x0000ffff);
    return val;
}
#endif

/*****************************************************************************/
/* PowerPC 601 specific instructions (POWER bridge) */

target_ulong helper_clcs(uint32_t arg)
{
    switch (arg) {
    case 0x0CUL:
        /* Instruction cache line size */
        return env->icache_line_size;
        break;
    case 0x0DUL:
        /* Data cache line size */
        return env->dcache_line_size;
        break;
    case 0x0EUL:
        /* Minimum cache line size */
        return (env->icache_line_size < env->dcache_line_size) ?
            env->icache_line_size : env->dcache_line_size;
        break;
    case 0x0FUL:
        /* Maximum cache line size */
        return (env->icache_line_size > env->dcache_line_size) ?
            env->icache_line_size : env->dcache_line_size;
        break;
    default:
        /* Undefined */
        return 0;
        break;
    }
}

target_ulong helper_div(target_ulong arg1, target_ulong arg2)
{
    uint64_t tmp = (uint64_t)arg1 << 32 | env->spr[SPR_MQ];

    if (((int32_t)tmp == INT32_MIN && (int32_t)arg2 == (int32_t)-1) ||
        (int32_t)arg2 == 0) {
        env->spr[SPR_MQ] = 0;
        return INT32_MIN;
    } else {
        env->spr[SPR_MQ] = tmp % arg2;
        return  tmp / (int32_t)arg2;
    }
}

target_ulong helper_divo(target_ulong arg1, target_ulong arg2)
{
    uint64_t tmp = (uint64_t)arg1 << 32 | env->spr[SPR_MQ];

    if (((int32_t)tmp == INT32_MIN && (int32_t)arg2 == (int32_t)-1) ||
        (int32_t)arg2 == 0) {
        env->xer |= (1 << XER_OV) | (1 << XER_SO);
        env->spr[SPR_MQ] = 0;
        return INT32_MIN;
    } else {
        env->spr[SPR_MQ] = tmp % arg2;
        tmp /= (int32_t)arg2;
        if ((int32_t)tmp != tmp) {
            env->xer |= (1 << XER_OV) | (1 << XER_SO);
        } else {
            env->xer &= ~(1 << XER_OV);
        }
        return tmp;
    }
}

target_ulong helper_divs(target_ulong arg1, target_ulong arg2)
{
    if (((int32_t)arg1 == INT32_MIN && (int32_t)arg2 == (int32_t)-1) ||
        (int32_t)arg2 == 0) {
        env->spr[SPR_MQ] = 0;
        return INT32_MIN;
    } else {
        env->spr[SPR_MQ] = (int32_t)arg1 % (int32_t)arg2;
        return (int32_t)arg1 / (int32_t)arg2;
    }
}

target_ulong helper_divso(target_ulong arg1, target_ulong arg2)
{
    if (((int32_t)arg1 == INT32_MIN && (int32_t)arg2 == (int32_t)-1) ||
        (int32_t)arg2 == 0) {
        env->xer |= (1 << XER_OV) | (1 << XER_SO);
        env->spr[SPR_MQ] = 0;
        return INT32_MIN;
    } else {
        env->xer &= ~(1 << XER_OV);
        env->spr[SPR_MQ] = (int32_t)arg1 % (int32_t)arg2;
        return (int32_t)arg1 / (int32_t)arg2;
    }
}

#if !defined(CONFIG_USER_ONLY)
target_ulong helper_rac(target_ulong addr)
{
    mmu_ctx_t ctx;
    int nb_BATs;
    target_ulong ret = 0;

    /* We don't have to generate many instances of this instruction,
     * as rac is supervisor only.
     */
    /* XXX: FIX THIS: Pretend we have no BAT */
    nb_BATs = env->nb_BATs;
    env->nb_BATs = 0;
    if (get_physical_address(env, &ctx, addr, 0, ACCESS_INT) == 0) {
        ret = ctx.raddr;
    }
    env->nb_BATs = nb_BATs;
    return ret;
}
#endif

/*****************************************************************************/
/* 602 specific instructions */
/* mfrom is the most crazy instruction ever seen, imho ! */
/* Real implementation uses a ROM table. Do the same */
/* Extremely decomposed:
 *                      -arg / 256
 * return 256 * log10(10           + 1.0) + 0.5
 */
#if !defined(CONFIG_USER_ONLY)
target_ulong helper_602_mfrom(target_ulong arg)
{
    if (likely(arg < 602)) {
#include "mfrom_table.c"
        return mfrom_ROM_table[arg];
    } else {
        return 0;
    }
}
#endif

/*****************************************************************************/
/* Embedded PowerPC specific helpers */

/* XXX: to be improved to check access rights when in user-mode */
target_ulong helper_load_dcr(target_ulong dcrn)
{
    uint32_t val = 0;

    if (unlikely(env->dcr_env == NULL)) {
        qemu_log("No DCR environment\n");
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL |
                                   POWERPC_EXCP_INVAL_INVAL);
    } else if (unlikely(ppc_dcr_read(env->dcr_env,
                                     (uint32_t)dcrn, &val) != 0)) {
        qemu_log("DCR read error %d %03x\n", (uint32_t)dcrn, (uint32_t)dcrn);
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL | POWERPC_EXCP_PRIV_REG);
    }
    return val;
}

void helper_store_dcr(target_ulong dcrn, target_ulong val)
{
    if (unlikely(env->dcr_env == NULL)) {
        qemu_log("No DCR environment\n");
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL |
                                   POWERPC_EXCP_INVAL_INVAL);
    } else if (unlikely(ppc_dcr_write(env->dcr_env, (uint32_t)dcrn,
                                      (uint32_t)val) != 0)) {
        qemu_log("DCR write error %d %03x\n", (uint32_t)dcrn, (uint32_t)dcrn);
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL | POWERPC_EXCP_PRIV_REG);
    }
}

/* 440 specific */
target_ulong helper_dlmzb(target_ulong high, target_ulong low,
                          uint32_t update_Rc)
{
    target_ulong mask;
    int i;

    i = 1;
    for (mask = 0xFF000000; mask != 0; mask = mask >> 8) {
        if ((high & mask) == 0) {
            if (update_Rc) {
                env->crf[0] = 0x4;
            }
            goto done;
        }
        i++;
    }
    for (mask = 0xFF000000; mask != 0; mask = mask >> 8) {
        if ((low & mask) == 0) {
            if (update_Rc) {
                env->crf[0] = 0x8;
            }
            goto done;
        }
        i++;
    }
    if (update_Rc) {
        env->crf[0] = 0x2;
    }
 done:
    env->xer = (env->xer & ~0x7F) | i;
    if (update_Rc) {
        env->crf[0] |= xer_so;
    }
    return i;
}

/*****************************************************************************/
/* Altivec extension helpers */
#if defined(HOST_WORDS_BIGENDIAN)
#define HI_IDX 0
#define LO_IDX 1
#else
#define HI_IDX 1
#define LO_IDX 0
#endif

#if defined(HOST_WORDS_BIGENDIAN)
#define VECTOR_FOR_INORDER_I(index, element)                    \
    for (index = 0; index < ARRAY_SIZE(r->element); index++)
#else
#define VECTOR_FOR_INORDER_I(index, element)                    \
    for (index = ARRAY_SIZE(r->element)-1; index >= 0; index--)
#endif

/* If X is a NaN, store the corresponding QNaN into RESULT.  Otherwise,
 * execute the following block.  */
#define DO_HANDLE_NAN(result, x)                        \
    if (float32_is_any_nan(x)) {                        \
        CPU_FloatU __f;                                 \
        __f.f = x;                                      \
        __f.l = __f.l | (1 << 22);  /* Set QNaN bit. */ \
        result = __f.f;                                 \
    } else

#define HANDLE_NAN1(result, x)                  \
    DO_HANDLE_NAN(result, x)
#define HANDLE_NAN2(result, x, y)                       \
    DO_HANDLE_NAN(result, x) DO_HANDLE_NAN(result, y)
#define HANDLE_NAN3(result, x, y, z)                                    \
    DO_HANDLE_NAN(result, x) DO_HANDLE_NAN(result, y) DO_HANDLE_NAN(result, z)

/* Saturating arithmetic helpers.  */
#define SATCVT(from, to, from_type, to_type, min, max)          \
    static inline to_type cvt##from##to(from_type x, int *sat)  \
    {                                                           \
        to_type r;                                              \
                                                                \
        if (x < (from_type)min) {                               \
            r = min;                                            \
            *sat = 1;                                           \
        } else if (x > (from_type)max) {                        \
            r = max;                                            \
            *sat = 1;                                           \
        } else {                                                \
            r = x;                                              \
        }                                                       \
        return r;                                               \
    }
#define SATCVTU(from, to, from_type, to_type, min, max)         \
    static inline to_type cvt##from##to(from_type x, int *sat)  \
    {                                                           \
        to_type r;                                              \
                                                                \
        if (x > (from_type)max) {                               \
            r = max;                                            \
            *sat = 1;                                           \
        } else {                                                \
            r = x;                                              \
        }                                                       \
        return r;                                               \
    }
SATCVT(sh, sb, int16_t, int8_t, INT8_MIN, INT8_MAX)
SATCVT(sw, sh, int32_t, int16_t, INT16_MIN, INT16_MAX)
SATCVT(sd, sw, int64_t, int32_t, INT32_MIN, INT32_MAX)

SATCVTU(uh, ub, uint16_t, uint8_t, 0, UINT8_MAX)
SATCVTU(uw, uh, uint32_t, uint16_t, 0, UINT16_MAX)
SATCVTU(ud, uw, uint64_t, uint32_t, 0, UINT32_MAX)
SATCVT(sh, ub, int16_t, uint8_t, 0, UINT8_MAX)
SATCVT(sw, uh, int32_t, uint16_t, 0, UINT16_MAX)
SATCVT(sd, uw, int64_t, uint32_t, 0, UINT32_MAX)
#undef SATCVT
#undef SATCVTU

#define LVE(name, access, swap, element)                        \
    void helper_##name(ppc_avr_t *r, target_ulong addr)         \
    {                                                           \
        size_t n_elems = ARRAY_SIZE(r->element);                \
        int adjust = HI_IDX*(n_elems - 1);                      \
        int sh = sizeof(r->element[0]) >> 1;                    \
        int index = (addr & 0xf) >> sh;                         \
                                                                \
        if (msr_le) {                                           \
            r->element[LO_IDX ? index : (adjust - index)] =     \
                swap(access(addr));                             \
        } else {                                                \
            r->element[LO_IDX ? index : (adjust - index)] =     \
                access(addr);                                   \
        }                                                       \
    }
#define I(x) (x)
LVE(lvebx, ldub, I, u8)
LVE(lvehx, lduw, bswap16, u16)
LVE(lvewx, ldl, bswap32, u32)
#undef I
#undef LVE

void helper_lvsl(ppc_avr_t *r, target_ulong sh)
{
    int i, j = (sh & 0xf);

    VECTOR_FOR_INORDER_I(i, u8) {
        r->u8[i] = j++;
    }
}

void helper_lvsr(ppc_avr_t *r, target_ulong sh)
{
    int i, j = 0x10 - (sh & 0xf);

    VECTOR_FOR_INORDER_I(i, u8) {
        r->u8[i] = j++;
    }
}

#define STVE(name, access, swap, element)                               \
    void helper_##name(ppc_avr_t *r, target_ulong addr)                 \
    {                                                                   \
        size_t n_elems = ARRAY_SIZE(r->element);                        \
        int adjust = HI_IDX * (n_elems - 1);                            \
        int sh = sizeof(r->element[0]) >> 1;                            \
        int index = (addr & 0xf) >> sh;                                 \
                                                                        \
        if (msr_le) {                                                   \
            access(addr, swap(r->element[LO_IDX ? index : (adjust - index)])); \
        } else {                                                        \
            access(addr, r->element[LO_IDX ? index : (adjust - index)]); \
        }                                                               \
    }
#define I(x) (x)
STVE(stvebx, stb, I, u8)
STVE(stvehx, stw, bswap16, u16)
STVE(stvewx, stl, bswap32, u32)
#undef I
#undef LVE

void helper_mtvscr(ppc_avr_t *r)
{
#if defined(HOST_WORDS_BIGENDIAN)
    env->vscr = r->u32[3];
#else
    env->vscr = r->u32[0];
#endif
    set_flush_to_zero(vscr_nj, &env->vec_status);
}

void helper_vaddcuw(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(r->u32); i++) {
        r->u32[i] = ~a->u32[i] < b->u32[i];
    }
}

#define VARITH_DO(name, op, element)                                    \
    void helper_v##name(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)       \
    {                                                                   \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->element); i++) {                  \
            r->element[i] = a->element[i] op b->element[i];             \
        }                                                               \
    }
#define VARITH(suffix, element)                 \
    VARITH_DO(add##suffix, +, element)          \
    VARITH_DO(sub##suffix, -, element)
VARITH(ubm, u8)
VARITH(uhm, u16)
VARITH(uwm, u32)
#undef VARITH_DO
#undef VARITH

#define VARITHFP(suffix, func)                                          \
    void helper_v##suffix(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)     \
    {                                                                   \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->f); i++) {                        \
            HANDLE_NAN2(r->f[i], a->f[i], b->f[i]) {                    \
                r->f[i] = func(a->f[i], b->f[i], &env->vec_status);     \
            }                                                           \
        }                                                               \
    }
VARITHFP(addfp, float32_add)
VARITHFP(subfp, float32_sub)
#undef VARITHFP

#define VARITHSAT_CASE(type, op, cvt, element)                          \
    {                                                                   \
        type result = (type)a->element[i] op (type)b->element[i];       \
        r->element[i] = cvt(result, &sat);                              \
    }

#define VARITHSAT_DO(name, op, optype, cvt, element)                    \
    void helper_v##name(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)       \
    {                                                                   \
        int sat = 0;                                                    \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->element); i++) {                  \
            switch (sizeof(r->element[0])) {                            \
            case 1:                                                     \
                VARITHSAT_CASE(optype, op, cvt, element);               \
                break;                                                  \
            case 2:                                                     \
                VARITHSAT_CASE(optype, op, cvt, element);               \
                break;                                                  \
            case 4:                                                     \
                VARITHSAT_CASE(optype, op, cvt, element);               \
                break;                                                  \
            }                                                           \
        }                                                               \
        if (sat) {                                                      \
            env->vscr |= (1 << VSCR_SAT);                               \
        }                                                               \
    }
#define VARITHSAT_SIGNED(suffix, element, optype, cvt)          \
    VARITHSAT_DO(adds##suffix##s, +, optype, cvt, element)      \
    VARITHSAT_DO(subs##suffix##s, -, optype, cvt, element)
#define VARITHSAT_UNSIGNED(suffix, element, optype, cvt)        \
    VARITHSAT_DO(addu##suffix##s, +, optype, cvt, element)      \
    VARITHSAT_DO(subu##suffix##s, -, optype, cvt, element)
VARITHSAT_SIGNED(b, s8, int16_t, cvtshsb)
VARITHSAT_SIGNED(h, s16, int32_t, cvtswsh)
VARITHSAT_SIGNED(w, s32, int64_t, cvtsdsw)
VARITHSAT_UNSIGNED(b, u8, uint16_t, cvtshub)
VARITHSAT_UNSIGNED(h, u16, uint32_t, cvtswuh)
VARITHSAT_UNSIGNED(w, u32, uint64_t, cvtsduw)
#undef VARITHSAT_CASE
#undef VARITHSAT_DO
#undef VARITHSAT_SIGNED
#undef VARITHSAT_UNSIGNED

#define VAVG_DO(name, element, etype)                                   \
    void helper_v##name(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)       \
    {                                                                   \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->element); i++) {                  \
            etype x = (etype)a->element[i] + (etype)b->element[i] + 1;  \
            r->element[i] = x >> 1;                                     \
        }                                                               \
    }

#define VAVG(type, signed_element, signed_type, unsigned_element,       \
             unsigned_type)                                             \
    VAVG_DO(avgs##type, signed_element, signed_type)                    \
    VAVG_DO(avgu##type, unsigned_element, unsigned_type)
VAVG(b, s8, int16_t, u8, uint16_t)
VAVG(h, s16, int32_t, u16, uint32_t)
VAVG(w, s32, int64_t, u32, uint64_t)
#undef VAVG_DO
#undef VAVG

#define VCF(suffix, cvt, element)                                       \
    void helper_vcf##suffix(ppc_avr_t *r, ppc_avr_t *b, uint32_t uim)   \
    {                                                                   \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->f); i++) {                        \
            float32 t = cvt(b->element[i], &env->vec_status);           \
            r->f[i] = float32_scalbn(t, -uim, &env->vec_status);        \
        }                                                               \
    }
VCF(ux, uint32_to_float32, u32)
VCF(sx, int32_to_float32, s32)
#undef VCF

#define VCMP_DO(suffix, compare, element, record)                       \
    void helper_vcmp##suffix(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)  \
    {                                                                   \
        uint32_t ones = (uint32_t)-1;                                   \
        uint32_t all = ones;                                            \
        uint32_t none = 0;                                              \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->element); i++) {                  \
            uint32_t result = (a->element[i] compare b->element[i] ?    \
                               ones : 0x0);                             \
            switch (sizeof(a->element[0])) {                            \
            case 4:                                                     \
                r->u32[i] = result;                                     \
                break;                                                  \
            case 2:                                                     \
                r->u16[i] = result;                                     \
                break;                                                  \
            case 1:                                                     \
                r->u8[i] = result;                                      \
                break;                                                  \
            }                                                           \
            all &= result;                                              \
            none |= result;                                             \
        }                                                               \
        if (record) {                                                   \
            env->crf[6] = ((all != 0) << 3) | ((none == 0) << 1);       \
        }                                                               \
    }
#define VCMP(suffix, compare, element)          \
    VCMP_DO(suffix, compare, element, 0)        \
    VCMP_DO(suffix##_dot, compare, element, 1)
VCMP(equb, ==, u8)
VCMP(equh, ==, u16)
VCMP(equw, ==, u32)
VCMP(gtub, >, u8)
VCMP(gtuh, >, u16)
VCMP(gtuw, >, u32)
VCMP(gtsb, >, s8)
VCMP(gtsh, >, s16)
VCMP(gtsw, >, s32)
#undef VCMP_DO
#undef VCMP

#define VCMPFP_DO(suffix, compare, order, record)                       \
    void helper_vcmp##suffix(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)  \
    {                                                                   \
        uint32_t ones = (uint32_t)-1;                                   \
        uint32_t all = ones;                                            \
        uint32_t none = 0;                                              \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->f); i++) {                        \
            uint32_t result;                                            \
            int rel = float32_compare_quiet(a->f[i], b->f[i],           \
                                            &env->vec_status);          \
            if (rel == float_relation_unordered) {                      \
                result = 0;                                             \
            } else if (rel compare order) {                             \
                result = ones;                                          \
            } else {                                                    \
                result = 0;                                             \
            }                                                           \
            r->u32[i] = result;                                         \
            all &= result;                                              \
            none |= result;                                             \
        }                                                               \
        if (record) {                                                   \
            env->crf[6] = ((all != 0) << 3) | ((none == 0) << 1);       \
        }                                                               \
    }
#define VCMPFP(suffix, compare, order)          \
    VCMPFP_DO(suffix, compare, order, 0)        \
    VCMPFP_DO(suffix##_dot, compare, order, 1)
VCMPFP(eqfp, ==, float_relation_equal)
VCMPFP(gefp, !=, float_relation_less)
VCMPFP(gtfp, ==, float_relation_greater)
#undef VCMPFP_DO
#undef VCMPFP

static inline void vcmpbfp_internal(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b,
                                    int record)
{
    int i;
    int all_in = 0;

    for (i = 0; i < ARRAY_SIZE(r->f); i++) {
        int le_rel = float32_compare_quiet(a->f[i], b->f[i], &env->vec_status);
        if (le_rel == float_relation_unordered) {
            r->u32[i] = 0xc0000000;
            /* ALL_IN does not need to be updated here.  */
        } else {
            float32 bneg = float32_chs(b->f[i]);
            int ge_rel = float32_compare_quiet(a->f[i], bneg, &env->vec_status);
            int le = le_rel != float_relation_greater;
            int ge = ge_rel != float_relation_less;

            r->u32[i] = ((!le) << 31) | ((!ge) << 30);
            all_in |= (!le | !ge);
        }
    }
    if (record) {
        env->crf[6] = (all_in == 0) << 1;
    }
}

void helper_vcmpbfp(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)
{
    vcmpbfp_internal(r, a, b, 0);
}

void helper_vcmpbfp_dot(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)
{
    vcmpbfp_internal(r, a, b, 1);
}

#define VCT(suffix, satcvt, element)                                    \
    void helper_vct##suffix(ppc_avr_t *r, ppc_avr_t *b, uint32_t uim)   \
    {                                                                   \
        int i;                                                          \
        int sat = 0;                                                    \
        float_status s = env->vec_status;                               \
                                                                        \
        set_float_rounding_mode(float_round_to_zero, &s);               \
        for (i = 0; i < ARRAY_SIZE(r->f); i++) {                        \
            if (float32_is_any_nan(b->f[i])) {                          \
                r->element[i] = 0;                                      \
            } else {                                                    \
                float64 t = float32_to_float64(b->f[i], &s);            \
                int64_t j;                                              \
                                                                        \
                t = float64_scalbn(t, uim, &s);                         \
                j = float64_to_int64(t, &s);                            \
                r->element[i] = satcvt(j, &sat);                        \
            }                                                           \
        }                                                               \
        if (sat) {                                                      \
            env->vscr |= (1 << VSCR_SAT);                               \
        }                                                               \
    }
VCT(uxs, cvtsduw, u32)
VCT(sxs, cvtsdsw, s32)
#undef VCT

void helper_vmaddfp(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(r->f); i++) {
        HANDLE_NAN3(r->f[i], a->f[i], b->f[i], c->f[i]) {
            /* Need to do the computation in higher precision and round
             * once at the end.  */
            float64 af, bf, cf, t;

            af = float32_to_float64(a->f[i], &env->vec_status);
            bf = float32_to_float64(b->f[i], &env->vec_status);
            cf = float32_to_float64(c->f[i], &env->vec_status);
            t = float64_mul(af, cf, &env->vec_status);
            t = float64_add(t, bf, &env->vec_status);
            r->f[i] = float64_to_float32(t, &env->vec_status);
        }
    }
}

void helper_vmhaddshs(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    int sat = 0;
    int i;

    for (i = 0; i < ARRAY_SIZE(r->s16); i++) {
        int32_t prod = a->s16[i] * b->s16[i];
        int32_t t = (int32_t)c->s16[i] + (prod >> 15);

        r->s16[i] = cvtswsh(t, &sat);
    }

    if (sat) {
        env->vscr |= (1 << VSCR_SAT);
    }
}

void helper_vmhraddshs(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    int sat = 0;
    int i;

    for (i = 0; i < ARRAY_SIZE(r->s16); i++) {
        int32_t prod = a->s16[i] * b->s16[i] + 0x00004000;
        int32_t t = (int32_t)c->s16[i] + (prod >> 15);
        r->s16[i] = cvtswsh(t, &sat);
    }

    if (sat) {
        env->vscr |= (1 << VSCR_SAT);
    }
}

#define VMINMAX_DO(name, compare, element)                              \
    void helper_v##name(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)       \
    {                                                                   \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->element); i++) {                  \
            if (a->element[i] compare b->element[i]) {                  \
                r->element[i] = b->element[i];                          \
            } else {                                                    \
                r->element[i] = a->element[i];                          \
            }                                                           \
        }                                                               \
    }
#define VMINMAX(suffix, element)                \
    VMINMAX_DO(min##suffix, >, element)         \
    VMINMAX_DO(max##suffix, <, element)
VMINMAX(sb, s8)
VMINMAX(sh, s16)
VMINMAX(sw, s32)
VMINMAX(ub, u8)
VMINMAX(uh, u16)
VMINMAX(uw, u32)
#undef VMINMAX_DO
#undef VMINMAX

#define VMINMAXFP(suffix, rT, rF)                                       \
    void helper_v##suffix(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)     \
    {                                                                   \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->f); i++) {                        \
            HANDLE_NAN2(r->f[i], a->f[i], b->f[i]) {                    \
                if (float32_lt_quiet(a->f[i], b->f[i],                  \
                                     &env->vec_status)) {               \
                    r->f[i] = rT->f[i];                                 \
                } else {                                                \
                    r->f[i] = rF->f[i];                                 \
                }                                                       \
            }                                                           \
        }                                                               \
    }
VMINMAXFP(minfp, a, b)
VMINMAXFP(maxfp, b, a)
#undef VMINMAXFP

void helper_vmladduhm(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(r->s16); i++) {
        int32_t prod = a->s16[i] * b->s16[i];
        r->s16[i] = (int16_t) (prod + c->s16[i]);
    }
}

#define VMRG_DO(name, element, highp)                                   \
    void helper_v##name(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)       \
    {                                                                   \
        ppc_avr_t result;                                               \
        int i;                                                          \
        size_t n_elems = ARRAY_SIZE(r->element);                        \
                                                                        \
        for (i = 0; i < n_elems / 2; i++) {                             \
            if (highp) {                                                \
                result.element[i*2+HI_IDX] = a->element[i];             \
                result.element[i*2+LO_IDX] = b->element[i];             \
            } else {                                                    \
                result.element[n_elems - i * 2 - (1 + HI_IDX)] =        \
                    b->element[n_elems - i - 1];                        \
                result.element[n_elems - i * 2 - (1 + LO_IDX)] =        \
                    a->element[n_elems - i - 1];                        \
            }                                                           \
        }                                                               \
        *r = result;                                                    \
    }
#if defined(HOST_WORDS_BIGENDIAN)
#define MRGHI 0
#define MRGLO 1
#else
#define MRGHI 1
#define MRGLO 0
#endif
#define VMRG(suffix, element)                   \
    VMRG_DO(mrgl##suffix, element, MRGHI)       \
    VMRG_DO(mrgh##suffix, element, MRGLO)
VMRG(b, u8)
VMRG(h, u16)
VMRG(w, u32)
#undef VMRG_DO
#undef VMRG
#undef MRGHI
#undef MRGLO

void helper_vmsummbm(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    int32_t prod[16];
    int i;

    for (i = 0; i < ARRAY_SIZE(r->s8); i++) {
        prod[i] = (int32_t)a->s8[i] * b->u8[i];
    }

    VECTOR_FOR_INORDER_I(i, s32) {
        r->s32[i] = c->s32[i] + prod[4 * i] + prod[4 * i + 1] +
            prod[4 * i + 2] + prod[4 * i + 3];
    }
}

void helper_vmsumshm(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    int32_t prod[8];
    int i;

    for (i = 0; i < ARRAY_SIZE(r->s16); i++) {
        prod[i] = a->s16[i] * b->s16[i];
    }

    VECTOR_FOR_INORDER_I(i, s32) {
        r->s32[i] = c->s32[i] + prod[2 * i] + prod[2 * i + 1];
    }
}

void helper_vmsumshs(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    int32_t prod[8];
    int i;
    int sat = 0;

    for (i = 0; i < ARRAY_SIZE(r->s16); i++) {
        prod[i] = (int32_t)a->s16[i] * b->s16[i];
    }

    VECTOR_FOR_INORDER_I(i, s32) {
        int64_t t = (int64_t)c->s32[i] + prod[2 * i] + prod[2 * i + 1];

        r->u32[i] = cvtsdsw(t, &sat);
    }

    if (sat) {
        env->vscr |= (1 << VSCR_SAT);
    }
}

void helper_vmsumubm(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    uint16_t prod[16];
    int i;

    for (i = 0; i < ARRAY_SIZE(r->u8); i++) {
        prod[i] = a->u8[i] * b->u8[i];
    }

    VECTOR_FOR_INORDER_I(i, u32) {
        r->u32[i] = c->u32[i] + prod[4 * i] + prod[4 * i + 1] +
            prod[4 * i + 2] + prod[4 * i + 3];
    }
}

void helper_vmsumuhm(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    uint32_t prod[8];
    int i;

    for (i = 0; i < ARRAY_SIZE(r->u16); i++) {
        prod[i] = a->u16[i] * b->u16[i];
    }

    VECTOR_FOR_INORDER_I(i, u32) {
        r->u32[i] = c->u32[i] + prod[2 * i] + prod[2 * i + 1];
    }
}

void helper_vmsumuhs(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    uint32_t prod[8];
    int i;
    int sat = 0;

    for (i = 0; i < ARRAY_SIZE(r->u16); i++) {
        prod[i] = a->u16[i] * b->u16[i];
    }

    VECTOR_FOR_INORDER_I(i, s32) {
        uint64_t t = (uint64_t)c->u32[i] + prod[2 * i] + prod[2 * i + 1];

        r->u32[i] = cvtuduw(t, &sat);
    }

    if (sat) {
        env->vscr |= (1 << VSCR_SAT);
    }
}

#define VMUL_DO(name, mul_element, prod_element, evenp)                 \
    void helper_v##name(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)       \
    {                                                                   \
        int i;                                                          \
                                                                        \
        VECTOR_FOR_INORDER_I(i, prod_element) {                         \
            if (evenp) {                                                \
                r->prod_element[i] = a->mul_element[i * 2 + HI_IDX] *   \
                    b->mul_element[i * 2 + HI_IDX];                     \
            } else {                                                    \
                r->prod_element[i] = a->mul_element[i * 2 + LO_IDX] *   \
                    b->mul_element[i * 2 + LO_IDX];                     \
            }                                                           \
        }                                                               \
    }
#define VMUL(suffix, mul_element, prod_element)         \
    VMUL_DO(mule##suffix, mul_element, prod_element, 1) \
    VMUL_DO(mulo##suffix, mul_element, prod_element, 0)
VMUL(sb, s8, s16)
VMUL(sh, s16, s32)
VMUL(ub, u8, u16)
VMUL(uh, u16, u32)
#undef VMUL_DO
#undef VMUL

void helper_vnmsubfp(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(r->f); i++) {
        HANDLE_NAN3(r->f[i], a->f[i], b->f[i], c->f[i]) {
            /* Need to do the computation is higher precision and round
             * once at the end.  */
            float64 af, bf, cf, t;

            af = float32_to_float64(a->f[i], &env->vec_status);
            bf = float32_to_float64(b->f[i], &env->vec_status);
            cf = float32_to_float64(c->f[i], &env->vec_status);
            t = float64_mul(af, cf, &env->vec_status);
            t = float64_sub(t, bf, &env->vec_status);
            t = float64_chs(t);
            r->f[i] = float64_to_float32(t, &env->vec_status);
        }
    }
}

void helper_vperm(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    ppc_avr_t result;
    int i;

    VECTOR_FOR_INORDER_I(i, u8) {
        int s = c->u8[i] & 0x1f;
#if defined(HOST_WORDS_BIGENDIAN)
        int index = s & 0xf;
#else
        int index = 15 - (s & 0xf);
#endif

        if (s & 0x10) {
            result.u8[i] = b->u8[index];
        } else {
            result.u8[i] = a->u8[index];
        }
    }
    *r = result;
}

#if defined(HOST_WORDS_BIGENDIAN)
#define PKBIG 1
#else
#define PKBIG 0
#endif
void helper_vpkpx(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)
{
    int i, j;
    ppc_avr_t result;
#if defined(HOST_WORDS_BIGENDIAN)
    const ppc_avr_t *x[2] = { a, b };
#else
    const ppc_avr_t *x[2] = { b, a };
#endif

    VECTOR_FOR_INORDER_I(i, u64) {
        VECTOR_FOR_INORDER_I(j, u32) {
            uint32_t e = x[i]->u32[j];

            result.u16[4*i+j] = (((e >> 9) & 0xfc00) |
                                 ((e >> 6) & 0x3e0) |
                                 ((e >> 3) & 0x1f));
        }
    }
    *r = result;
}

#define VPK(suffix, from, to, cvt, dosat)                               \
    void helper_vpk##suffix(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)   \
    {                                                                   \
        int i;                                                          \
        int sat = 0;                                                    \
        ppc_avr_t result;                                               \
        ppc_avr_t *a0 = PKBIG ? a : b;                                  \
        ppc_avr_t *a1 = PKBIG ? b : a;                                  \
                                                                        \
        VECTOR_FOR_INORDER_I(i, from) {                                 \
            result.to[i] = cvt(a0->from[i], &sat);                      \
            result.to[i+ARRAY_SIZE(r->from)] = cvt(a1->from[i], &sat);  \
        }                                                               \
        *r = result;                                                    \
        if (dosat && sat) {                                             \
            env->vscr |= (1 << VSCR_SAT);                               \
        }                                                               \
    }
#define I(x, y) (x)
VPK(shss, s16, s8, cvtshsb, 1)
VPK(shus, s16, u8, cvtshub, 1)
VPK(swss, s32, s16, cvtswsh, 1)
VPK(swus, s32, u16, cvtswuh, 1)
VPK(uhus, u16, u8, cvtuhub, 1)
VPK(uwus, u32, u16, cvtuwuh, 1)
VPK(uhum, u16, u8, I, 0)
VPK(uwum, u32, u16, I, 0)
#undef I
#undef VPK
#undef PKBIG

void helper_vrefp(ppc_avr_t *r, ppc_avr_t *b)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(r->f); i++) {
        HANDLE_NAN1(r->f[i], b->f[i]) {
            r->f[i] = float32_div(float32_one, b->f[i], &env->vec_status);
        }
    }
}

#define VRFI(suffix, rounding)                                  \
    void helper_vrfi##suffix(ppc_avr_t *r, ppc_avr_t *b)        \
    {                                                           \
        int i;                                                  \
        float_status s = env->vec_status;                       \
                                                                \
        set_float_rounding_mode(rounding, &s);                  \
        for (i = 0; i < ARRAY_SIZE(r->f); i++) {                \
            HANDLE_NAN1(r->f[i], b->f[i]) {                     \
                r->f[i] = float32_round_to_int (b->f[i], &s);   \
            }                                                   \
        }                                                       \
    }
VRFI(n, float_round_nearest_even)
VRFI(m, float_round_down)
VRFI(p, float_round_up)
VRFI(z, float_round_to_zero)
#undef VRFI

#define VROTATE(suffix, element)                                        \
    void helper_vrl##suffix(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)   \
    {                                                                   \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->element); i++) {                  \
            unsigned int mask = ((1 <<                                  \
                                  (3 + (sizeof(a->element[0]) >> 1)))   \
                                 - 1);                                  \
            unsigned int shift = b->element[i] & mask;                  \
            r->element[i] = (a->element[i] << shift) |                  \
                (a->element[i] >> (sizeof(a->element[0]) * 8 - shift)); \
        }                                                               \
    }
VROTATE(b, u8)
VROTATE(h, u16)
VROTATE(w, u32)
#undef VROTATE

void helper_vrsqrtefp(ppc_avr_t *r, ppc_avr_t *b)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(r->f); i++) {
        HANDLE_NAN1(r->f[i], b->f[i]) {
            float32 t = float32_sqrt(b->f[i], &env->vec_status);

            r->f[i] = float32_div(float32_one, t, &env->vec_status);
        }
    }
}

void helper_vsel(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, ppc_avr_t *c)
{
    r->u64[0] = (a->u64[0] & ~c->u64[0]) | (b->u64[0] & c->u64[0]);
    r->u64[1] = (a->u64[1] & ~c->u64[1]) | (b->u64[1] & c->u64[1]);
}

void helper_vexptefp(ppc_avr_t *r, ppc_avr_t *b)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(r->f); i++) {
        HANDLE_NAN1(r->f[i], b->f[i]) {
            r->f[i] = float32_exp2(b->f[i], &env->vec_status);
        }
    }
}

void helper_vlogefp(ppc_avr_t *r, ppc_avr_t *b)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(r->f); i++) {
        HANDLE_NAN1(r->f[i], b->f[i]) {
            r->f[i] = float32_log2(b->f[i], &env->vec_status);
        }
    }
}

#if defined(HOST_WORDS_BIGENDIAN)
#define LEFT 0
#define RIGHT 1
#else
#define LEFT 1
#define RIGHT 0
#endif
/* The specification says that the results are undefined if all of the
 * shift counts are not identical.  We check to make sure that they are
 * to conform to what real hardware appears to do.  */
#define VSHIFT(suffix, leftp)                                           \
    void helper_vs##suffix(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)    \
    {                                                                   \
        int shift = b->u8[LO_IDX*15] & 0x7;                             \
        int doit = 1;                                                   \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->u8); i++) {                       \
            doit = doit && ((b->u8[i] & 0x7) == shift);                 \
        }                                                               \
        if (doit) {                                                     \
            if (shift == 0) {                                           \
                *r = *a;                                                \
            } else if (leftp) {                                         \
                uint64_t carry = a->u64[LO_IDX] >> (64 - shift);        \
                                                                        \
                r->u64[HI_IDX] = (a->u64[HI_IDX] << shift) | carry;     \
                r->u64[LO_IDX] = a->u64[LO_IDX] << shift;               \
            } else {                                                    \
                uint64_t carry = a->u64[HI_IDX] << (64 - shift);        \
                                                                        \
                r->u64[LO_IDX] = (a->u64[LO_IDX] >> shift) | carry;     \
                r->u64[HI_IDX] = a->u64[HI_IDX] >> shift;               \
            }                                                           \
        }                                                               \
    }
VSHIFT(l, LEFT)
VSHIFT(r, RIGHT)
#undef VSHIFT
#undef LEFT
#undef RIGHT

#define VSL(suffix, element)                                            \
    void helper_vsl##suffix(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)   \
    {                                                                   \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->element); i++) {                  \
            unsigned int mask = ((1 <<                                  \
                                  (3 + (sizeof(a->element[0]) >> 1)))   \
                                 - 1);                                  \
            unsigned int shift = b->element[i] & mask;                  \
                                                                        \
            r->element[i] = a->element[i] << shift;                     \
        }                                                               \
    }
VSL(b, u8)
VSL(h, u16)
VSL(w, u32)
#undef VSL

void helper_vsldoi(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b, uint32_t shift)
{
    int sh = shift & 0xf;
    int i;
    ppc_avr_t result;

#if defined(HOST_WORDS_BIGENDIAN)
    for (i = 0; i < ARRAY_SIZE(r->u8); i++) {
        int index = sh + i;
        if (index > 0xf) {
            result.u8[i] = b->u8[index - 0x10];
        } else {
            result.u8[i] = a->u8[index];
        }
    }
#else
    for (i = 0; i < ARRAY_SIZE(r->u8); i++) {
        int index = (16 - sh) + i;
        if (index > 0xf) {
            result.u8[i] = a->u8[index - 0x10];
        } else {
            result.u8[i] = b->u8[index];
        }
    }
#endif
    *r = result;
}

void helper_vslo(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)
{
    int sh = (b->u8[LO_IDX*0xf] >> 3) & 0xf;

#if defined(HOST_WORDS_BIGENDIAN)
    memmove(&r->u8[0], &a->u8[sh], 16 - sh);
    memset(&r->u8[16-sh], 0, sh);
#else
    memmove(&r->u8[sh], &a->u8[0], 16 - sh);
    memset(&r->u8[0], 0, sh);
#endif
}

/* Experimental testing shows that hardware masks the immediate.  */
#define _SPLAT_MASKED(element) (splat & (ARRAY_SIZE(r->element) - 1))
#if defined(HOST_WORDS_BIGENDIAN)
#define SPLAT_ELEMENT(element) _SPLAT_MASKED(element)
#else
#define SPLAT_ELEMENT(element)                                  \
    (ARRAY_SIZE(r->element) - 1 - _SPLAT_MASKED(element))
#endif
#define VSPLT(suffix, element)                                          \
    void helper_vsplt##suffix(ppc_avr_t *r, ppc_avr_t *b, uint32_t splat) \
    {                                                                   \
        uint32_t s = b->element[SPLAT_ELEMENT(element)];                \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->element); i++) {                  \
            r->element[i] = s;                                          \
        }                                                               \
    }
VSPLT(b, u8)
VSPLT(h, u16)
VSPLT(w, u32)
#undef VSPLT
#undef SPLAT_ELEMENT
#undef _SPLAT_MASKED

#define VSPLTI(suffix, element, splat_type)                     \
    void helper_vspltis##suffix(ppc_avr_t *r, uint32_t splat)   \
    {                                                           \
        splat_type x = (int8_t)(splat << 3) >> 3;               \
        int i;                                                  \
                                                                \
        for (i = 0; i < ARRAY_SIZE(r->element); i++) {          \
            r->element[i] = x;                                  \
        }                                                       \
    }
VSPLTI(b, s8, int8_t)
VSPLTI(h, s16, int16_t)
VSPLTI(w, s32, int32_t)
#undef VSPLTI

#define VSR(suffix, element)                                            \
    void helper_vsr##suffix(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)   \
    {                                                                   \
        int i;                                                          \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->element); i++) {                  \
            unsigned int mask = ((1 <<                                  \
                                  (3 + (sizeof(a->element[0]) >> 1)))   \
                                 - 1);                                  \
            unsigned int shift = b->element[i] & mask;                  \
                                                                        \
            r->element[i] = a->element[i] >> shift;                     \
        }                                                               \
    }
VSR(ab, s8)
VSR(ah, s16)
VSR(aw, s32)
VSR(b, u8)
VSR(h, u16)
VSR(w, u32)
#undef VSR

void helper_vsro(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)
{
    int sh = (b->u8[LO_IDX * 0xf] >> 3) & 0xf;

#if defined(HOST_WORDS_BIGENDIAN)
    memmove(&r->u8[sh], &a->u8[0], 16 - sh);
    memset(&r->u8[0], 0, sh);
#else
    memmove(&r->u8[0], &a->u8[sh], 16 - sh);
    memset(&r->u8[16 - sh], 0, sh);
#endif
}

void helper_vsubcuw(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(r->u32); i++) {
        r->u32[i] = a->u32[i] >= b->u32[i];
    }
}

void helper_vsumsws(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)
{
    int64_t t;
    int i, upper;
    ppc_avr_t result;
    int sat = 0;

#if defined(HOST_WORDS_BIGENDIAN)
    upper = ARRAY_SIZE(r->s32)-1;
#else
    upper = 0;
#endif
    t = (int64_t)b->s32[upper];
    for (i = 0; i < ARRAY_SIZE(r->s32); i++) {
        t += a->s32[i];
        result.s32[i] = 0;
    }
    result.s32[upper] = cvtsdsw(t, &sat);
    *r = result;

    if (sat) {
        env->vscr |= (1 << VSCR_SAT);
    }
}

void helper_vsum2sws(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)
{
    int i, j, upper;
    ppc_avr_t result;
    int sat = 0;

#if defined(HOST_WORDS_BIGENDIAN)
    upper = 1;
#else
    upper = 0;
#endif
    for (i = 0; i < ARRAY_SIZE(r->u64); i++) {
        int64_t t = (int64_t)b->s32[upper + i * 2];

        result.u64[i] = 0;
        for (j = 0; j < ARRAY_SIZE(r->u64); j++) {
            t += a->s32[2 * i + j];
        }
        result.s32[upper + i * 2] = cvtsdsw(t, &sat);
    }

    *r = result;
    if (sat) {
        env->vscr |= (1 << VSCR_SAT);
    }
}

void helper_vsum4sbs(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)
{
    int i, j;
    int sat = 0;

    for (i = 0; i < ARRAY_SIZE(r->s32); i++) {
        int64_t t = (int64_t)b->s32[i];

        for (j = 0; j < ARRAY_SIZE(r->s32); j++) {
            t += a->s8[4 * i + j];
        }
        r->s32[i] = cvtsdsw(t, &sat);
    }

    if (sat) {
        env->vscr |= (1 << VSCR_SAT);
    }
}

void helper_vsum4shs(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)
{
    int sat = 0;
    int i;

    for (i = 0; i < ARRAY_SIZE(r->s32); i++) {
        int64_t t = (int64_t)b->s32[i];

        t += a->s16[2 * i] + a->s16[2 * i + 1];
        r->s32[i] = cvtsdsw(t, &sat);
    }

    if (sat) {
        env->vscr |= (1 << VSCR_SAT);
    }
}

void helper_vsum4ubs(ppc_avr_t *r, ppc_avr_t *a, ppc_avr_t *b)
{
    int i, j;
    int sat = 0;

    for (i = 0; i < ARRAY_SIZE(r->u32); i++) {
        uint64_t t = (uint64_t)b->u32[i];

        for (j = 0; j < ARRAY_SIZE(r->u32); j++) {
            t += a->u8[4 * i + j];
        }
        r->u32[i] = cvtuduw(t, &sat);
    }

    if (sat) {
        env->vscr |= (1 << VSCR_SAT);
    }
}

#if defined(HOST_WORDS_BIGENDIAN)
#define UPKHI 1
#define UPKLO 0
#else
#define UPKHI 0
#define UPKLO 1
#endif
#define VUPKPX(suffix, hi)                                              \
    void helper_vupk##suffix(ppc_avr_t *r, ppc_avr_t *b)                \
    {                                                                   \
        int i;                                                          \
        ppc_avr_t result;                                               \
                                                                        \
        for (i = 0; i < ARRAY_SIZE(r->u32); i++) {                      \
            uint16_t e = b->u16[hi ? i : i+4];                          \
            uint8_t a = (e >> 15) ? 0xff : 0;                           \
            uint8_t r = (e >> 10) & 0x1f;                               \
            uint8_t g = (e >> 5) & 0x1f;                                \
            uint8_t b = e & 0x1f;                                       \
                                                                        \
            result.u32[i] = (a << 24) | (r << 16) | (g << 8) | b;       \
        }                                                               \
        *r = result;                                                    \
    }
VUPKPX(lpx, UPKLO)
VUPKPX(hpx, UPKHI)
#undef VUPKPX

#define VUPK(suffix, unpacked, packee, hi)                              \
    void helper_vupk##suffix(ppc_avr_t *r, ppc_avr_t *b)                \
    {                                                                   \
        int i;                                                          \
        ppc_avr_t result;                                               \
                                                                        \
        if (hi) {                                                       \
            for (i = 0; i < ARRAY_SIZE(r->unpacked); i++) {             \
                result.unpacked[i] = b->packee[i];                      \
            }                                                           \
        } else {                                                        \
            for (i = ARRAY_SIZE(r->unpacked); i < ARRAY_SIZE(r->packee); \
                 i++) {                                                 \
                result.unpacked[i - ARRAY_SIZE(r->unpacked)] = b->packee[i]; \
            }                                                           \
        }                                                               \
        *r = result;                                                    \
    }
VUPK(hsb, s16, s8, UPKHI)
VUPK(hsh, s32, s16, UPKHI)
VUPK(lsb, s16, s8, UPKLO)
VUPK(lsh, s32, s16, UPKLO)
#undef VUPK
#undef UPKHI
#undef UPKLO

#undef DO_HANDLE_NAN
#undef HANDLE_NAN1
#undef HANDLE_NAN2
#undef HANDLE_NAN3
#undef VECTOR_FOR_INORDER_I
#undef HI_IDX
#undef LO_IDX

/*****************************************************************************/
/* SPE extension helpers */
/* Use a table to make this quicker */
static uint8_t hbrev[16] = {
    0x0, 0x8, 0x4, 0xC, 0x2, 0xA, 0x6, 0xE,
    0x1, 0x9, 0x5, 0xD, 0x3, 0xB, 0x7, 0xF,
};

static inline uint8_t byte_reverse(uint8_t val)
{
    return hbrev[val >> 4] | (hbrev[val & 0xF] << 4);
}

static inline uint32_t word_reverse(uint32_t val)
{
    return byte_reverse(val >> 24) | (byte_reverse(val >> 16) << 8) |
        (byte_reverse(val >> 8) << 16) | (byte_reverse(val) << 24);
}

#define MASKBITS 16 /* Random value - to be fixed (implementation dependent) */
target_ulong helper_brinc(target_ulong arg1, target_ulong arg2)
{
    uint32_t a, b, d, mask;

    mask = UINT32_MAX >> (32 - MASKBITS);
    a = arg1 & mask;
    b = arg2 & mask;
    d = word_reverse(1 + word_reverse(a | ~b));
    return (arg1 & ~mask) | (d & b);
}

uint32_t helper_cntlsw32(uint32_t val)
{
    if (val & 0x80000000) {
        return clz32(~val);
    } else {
        return clz32(val);
    }
}

uint32_t helper_cntlzw32(uint32_t val)
{
    return clz32(val);
}

/*****************************************************************************/
/* Softmmu support */
#if !defined(CONFIG_USER_ONLY)

#define MMUSUFFIX _mmu

#define SHIFT 0
#include "softmmu_template.h"

#define SHIFT 1
#include "softmmu_template.h"

#define SHIFT 2
#include "softmmu_template.h"

#define SHIFT 3
#include "softmmu_template.h"

/* try to fill the TLB and return an exception if error. If retaddr is
   NULL, it means that the function was called in C code (i.e. not
   from generated code or from helper.c) */
/* XXX: fix it to restore all registers */
void tlb_fill(CPUPPCState *env1, target_ulong addr, int is_write, int mmu_idx,
              uintptr_t retaddr)
{
    TranslationBlock *tb;
    CPUPPCState *saved_env;
    int ret;

    saved_env = env;
    env = env1;
    ret = cpu_ppc_handle_mmu_fault(env, addr, is_write, mmu_idx);
    if (unlikely(ret != 0)) {
        if (likely(retaddr)) {
            /* now we have a real cpu fault */
            tb = tb_find_pc(retaddr);
            if (likely(tb)) {
                /* the PC is inside the translated code. It means that we have
                   a virtual CPU fault */
                cpu_restore_state(tb, env, retaddr);
            }
        }
        helper_raise_exception_err(env, env->exception_index, env->error_code);
    }
    env = saved_env;
}

/* Segment registers load and store */
target_ulong helper_load_sr(target_ulong sr_num)
{
#if defined(TARGET_PPC64)
    if (env->mmu_model & POWERPC_MMU_64) {
        return ppc_load_sr(env, sr_num);
    }
#endif
    return env->sr[sr_num];
}

void helper_store_sr(target_ulong sr_num, target_ulong val)
{
    ppc_store_sr(env, sr_num, val);
}

/* SLB management */
#if defined(TARGET_PPC64)
void helper_store_slb(target_ulong rb, target_ulong rs)
{
    if (ppc_store_slb(env, rb, rs) < 0) {
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL);
    }
}

target_ulong helper_load_slb_esid(target_ulong rb)
{
    target_ulong rt;

    if (ppc_load_slb_esid(env, rb, &rt) < 0) {
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL);
    }
    return rt;
}

target_ulong helper_load_slb_vsid(target_ulong rb)
{
    target_ulong rt;

    if (ppc_load_slb_vsid(env, rb, &rt) < 0) {
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL);
    }
    return rt;
}

void helper_slbia(void)
{
    ppc_slb_invalidate_all(env);
}

void helper_slbie(target_ulong addr)
{
    ppc_slb_invalidate_one(env, addr);
}

#endif /* defined(TARGET_PPC64) */

/* TLB management */
void helper_tlbia(void)
{
    ppc_tlb_invalidate_all(env);
}

void helper_tlbie(target_ulong addr)
{
    ppc_tlb_invalidate_one(env, addr);
}

/* Software driven TLBs management */
/* PowerPC 602/603 software TLB load instructions helpers */
static void do_6xx_tlb(target_ulong new_EPN, int is_code)
{
    target_ulong RPN, CMP, EPN;
    int way;

    RPN = env->spr[SPR_RPA];
    if (is_code) {
        CMP = env->spr[SPR_ICMP];
        EPN = env->spr[SPR_IMISS];
    } else {
        CMP = env->spr[SPR_DCMP];
        EPN = env->spr[SPR_DMISS];
    }
    way = (env->spr[SPR_SRR1] >> 17) & 1;
    (void)EPN; /* avoid a compiler warning */
    LOG_SWTLB("%s: EPN " TARGET_FMT_lx " " TARGET_FMT_lx " PTE0 " TARGET_FMT_lx
              " PTE1 " TARGET_FMT_lx " way %d\n", __func__, new_EPN, EPN, CMP,
              RPN, way);
    /* Store this TLB */
    ppc6xx_tlb_store(env, (uint32_t)(new_EPN & TARGET_PAGE_MASK),
                     way, is_code, CMP, RPN);
}

void helper_6xx_tlbd(target_ulong EPN)
{
    do_6xx_tlb(EPN, 0);
}

void helper_6xx_tlbi(target_ulong EPN)
{
    do_6xx_tlb(EPN, 1);
}

/* PowerPC 74xx software TLB load instructions helpers */
static void do_74xx_tlb(target_ulong new_EPN, int is_code)
{
    target_ulong RPN, CMP, EPN;
    int way;

    RPN = env->spr[SPR_PTELO];
    CMP = env->spr[SPR_PTEHI];
    EPN = env->spr[SPR_TLBMISS] & ~0x3;
    way = env->spr[SPR_TLBMISS] & 0x3;
    (void)EPN; /* avoid a compiler warning */
    LOG_SWTLB("%s: EPN " TARGET_FMT_lx " " TARGET_FMT_lx " PTE0 " TARGET_FMT_lx
              " PTE1 " TARGET_FMT_lx " way %d\n", __func__, new_EPN, EPN, CMP,
              RPN, way);
    /* Store this TLB */
    ppc6xx_tlb_store(env, (uint32_t)(new_EPN & TARGET_PAGE_MASK),
                     way, is_code, CMP, RPN);
}

void helper_74xx_tlbd(target_ulong EPN)
{
    do_74xx_tlb(EPN, 0);
}

void helper_74xx_tlbi(target_ulong EPN)
{
    do_74xx_tlb(EPN, 1);
}

static inline target_ulong booke_tlb_to_page_size(int size)
{
    return 1024 << (2 * size);
}

static inline int booke_page_size_to_tlb(target_ulong page_size)
{
    int size;

    switch (page_size) {
    case 0x00000400UL:
        size = 0x0;
        break;
    case 0x00001000UL:
        size = 0x1;
        break;
    case 0x00004000UL:
        size = 0x2;
        break;
    case 0x00010000UL:
        size = 0x3;
        break;
    case 0x00040000UL:
        size = 0x4;
        break;
    case 0x00100000UL:
        size = 0x5;
        break;
    case 0x00400000UL:
        size = 0x6;
        break;
    case 0x01000000UL:
        size = 0x7;
        break;
    case 0x04000000UL:
        size = 0x8;
        break;
    case 0x10000000UL:
        size = 0x9;
        break;
    case 0x40000000UL:
        size = 0xA;
        break;
#if defined(TARGET_PPC64)
    case 0x000100000000ULL:
        size = 0xB;
        break;
    case 0x000400000000ULL:
        size = 0xC;
        break;
    case 0x001000000000ULL:
        size = 0xD;
        break;
    case 0x004000000000ULL:
        size = 0xE;
        break;
    case 0x010000000000ULL:
        size = 0xF;
        break;
#endif
    default:
        size = -1;
        break;
    }

    return size;
}

/* Helpers for 4xx TLB management */
#define PPC4XX_TLB_ENTRY_MASK       0x0000003f  /* Mask for 64 TLB entries */

#define PPC4XX_TLBHI_V              0x00000040
#define PPC4XX_TLBHI_E              0x00000020
#define PPC4XX_TLBHI_SIZE_MIN       0
#define PPC4XX_TLBHI_SIZE_MAX       7
#define PPC4XX_TLBHI_SIZE_DEFAULT   1
#define PPC4XX_TLBHI_SIZE_SHIFT     7
#define PPC4XX_TLBHI_SIZE_MASK      0x00000007

#define PPC4XX_TLBLO_EX             0x00000200
#define PPC4XX_TLBLO_WR             0x00000100
#define PPC4XX_TLBLO_ATTR_MASK      0x000000FF
#define PPC4XX_TLBLO_RPN_MASK       0xFFFFFC00

target_ulong helper_4xx_tlbre_hi(target_ulong entry)
{
    ppcemb_tlb_t *tlb;
    target_ulong ret;
    int size;

    entry &= PPC4XX_TLB_ENTRY_MASK;
    tlb = &env->tlb.tlbe[entry];
    ret = tlb->EPN;
    if (tlb->prot & PAGE_VALID) {
        ret |= PPC4XX_TLBHI_V;
    }
    size = booke_page_size_to_tlb(tlb->size);
    if (size < PPC4XX_TLBHI_SIZE_MIN || size > PPC4XX_TLBHI_SIZE_MAX) {
        size = PPC4XX_TLBHI_SIZE_DEFAULT;
    }
    ret |= size << PPC4XX_TLBHI_SIZE_SHIFT;
    env->spr[SPR_40x_PID] = tlb->PID;
    return ret;
}

target_ulong helper_4xx_tlbre_lo(target_ulong entry)
{
    ppcemb_tlb_t *tlb;
    target_ulong ret;

    entry &= PPC4XX_TLB_ENTRY_MASK;
    tlb = &env->tlb.tlbe[entry];
    ret = tlb->RPN;
    if (tlb->prot & PAGE_EXEC) {
        ret |= PPC4XX_TLBLO_EX;
    }
    if (tlb->prot & PAGE_WRITE) {
        ret |= PPC4XX_TLBLO_WR;
    }
    return ret;
}

void helper_4xx_tlbwe_hi(target_ulong entry, target_ulong val)
{
    ppcemb_tlb_t *tlb;
    target_ulong page, end;

    LOG_SWTLB("%s entry %d val " TARGET_FMT_lx "\n", __func__, (int)entry,
              val);
    entry &= PPC4XX_TLB_ENTRY_MASK;
    tlb = &env->tlb.tlbe[entry];
    /* Invalidate previous TLB (if it's valid) */
    if (tlb->prot & PAGE_VALID) {
        end = tlb->EPN + tlb->size;
        LOG_SWTLB("%s: invalidate old TLB %d start " TARGET_FMT_lx " end "
                  TARGET_FMT_lx "\n", __func__, (int)entry, tlb->EPN, end);
        for (page = tlb->EPN; page < end; page += TARGET_PAGE_SIZE) {
            tlb_flush_page(env, page);
        }
    }
    tlb->size = booke_tlb_to_page_size((val >> PPC4XX_TLBHI_SIZE_SHIFT)
                                       & PPC4XX_TLBHI_SIZE_MASK);
    /* We cannot handle TLB size < TARGET_PAGE_SIZE.
     * If this ever occurs, one should use the ppcemb target instead
     * of the ppc or ppc64 one
     */
    if ((val & PPC4XX_TLBHI_V) && tlb->size < TARGET_PAGE_SIZE) {
        cpu_abort(env, "TLB size " TARGET_FMT_lu " < %u "
                  "are not supported (%d)\n",
                  tlb->size, TARGET_PAGE_SIZE, (int)((val >> 7) & 0x7));
    }
    tlb->EPN = val & ~(tlb->size - 1);
    if (val & PPC4XX_TLBHI_V) {
        tlb->prot |= PAGE_VALID;
        if (val & PPC4XX_TLBHI_E) {
            /* XXX: TO BE FIXED */
            cpu_abort(env,
                      "Little-endian TLB entries are not supported by now\n");
        }
    } else {
        tlb->prot &= ~PAGE_VALID;
    }
    tlb->PID = env->spr[SPR_40x_PID]; /* PID */
    LOG_SWTLB("%s: set up TLB %d RPN " TARGET_FMT_plx " EPN " TARGET_FMT_lx
              " size " TARGET_FMT_lx " prot %c%c%c%c PID %d\n", __func__,
              (int)entry, tlb->RPN, tlb->EPN, tlb->size,
              tlb->prot & PAGE_READ ? 'r' : '-',
              tlb->prot & PAGE_WRITE ? 'w' : '-',
              tlb->prot & PAGE_EXEC ? 'x' : '-',
              tlb->prot & PAGE_VALID ? 'v' : '-', (int)tlb->PID);
    /* Invalidate new TLB (if valid) */
    if (tlb->prot & PAGE_VALID) {
        end = tlb->EPN + tlb->size;
        LOG_SWTLB("%s: invalidate TLB %d start " TARGET_FMT_lx " end "
                  TARGET_FMT_lx "\n", __func__, (int)entry, tlb->EPN, end);
        for (page = tlb->EPN; page < end; page += TARGET_PAGE_SIZE) {
            tlb_flush_page(env, page);
        }
    }
}

void helper_4xx_tlbwe_lo(target_ulong entry, target_ulong val)
{
    ppcemb_tlb_t *tlb;

    LOG_SWTLB("%s entry %i val " TARGET_FMT_lx "\n", __func__, (int)entry,
              val);
    entry &= PPC4XX_TLB_ENTRY_MASK;
    tlb = &env->tlb.tlbe[entry];
    tlb->attr = val & PPC4XX_TLBLO_ATTR_MASK;
    tlb->RPN = val & PPC4XX_TLBLO_RPN_MASK;
    tlb->prot = PAGE_READ;
    if (val & PPC4XX_TLBLO_EX) {
        tlb->prot |= PAGE_EXEC;
    }
    if (val & PPC4XX_TLBLO_WR) {
        tlb->prot |= PAGE_WRITE;
    }
    LOG_SWTLB("%s: set up TLB %d RPN " TARGET_FMT_plx " EPN " TARGET_FMT_lx
              " size " TARGET_FMT_lx " prot %c%c%c%c PID %d\n", __func__,
              (int)entry, tlb->RPN, tlb->EPN, tlb->size,
              tlb->prot & PAGE_READ ? 'r' : '-',
              tlb->prot & PAGE_WRITE ? 'w' : '-',
              tlb->prot & PAGE_EXEC ? 'x' : '-',
              tlb->prot & PAGE_VALID ? 'v' : '-', (int)tlb->PID);
}

target_ulong helper_4xx_tlbsx(target_ulong address)
{
    return ppcemb_tlb_search(env, address, env->spr[SPR_40x_PID]);
}

/* PowerPC 440 TLB management */
void helper_440_tlbwe(uint32_t word, target_ulong entry, target_ulong value)
{
    ppcemb_tlb_t *tlb;
    target_ulong EPN, RPN, size;
    int do_flush_tlbs;

    LOG_SWTLB("%s word %d entry %d value " TARGET_FMT_lx "\n",
              __func__, word, (int)entry, value);
    do_flush_tlbs = 0;
    entry &= 0x3F;
    tlb = &env->tlb.tlbe[entry];
    switch (word) {
    default:
        /* Just here to please gcc */
    case 0:
        EPN = value & 0xFFFFFC00;
        if ((tlb->prot & PAGE_VALID) && EPN != tlb->EPN) {
            do_flush_tlbs = 1;
        }
        tlb->EPN = EPN;
        size = booke_tlb_to_page_size((value >> 4) & 0xF);
        if ((tlb->prot & PAGE_VALID) && tlb->size < size) {
            do_flush_tlbs = 1;
        }
        tlb->size = size;
        tlb->attr &= ~0x1;
        tlb->attr |= (value >> 8) & 1;
        if (value & 0x200) {
            tlb->prot |= PAGE_VALID;
        } else {
            if (tlb->prot & PAGE_VALID) {
                tlb->prot &= ~PAGE_VALID;
                do_flush_tlbs = 1;
            }
        }
        tlb->PID = env->spr[SPR_440_MMUCR] & 0x000000FF;
        if (do_flush_tlbs) {
            tlb_flush(env, 1);
        }
        break;
    case 1:
        RPN = value & 0xFFFFFC0F;
        if ((tlb->prot & PAGE_VALID) && tlb->RPN != RPN) {
            tlb_flush(env, 1);
        }
        tlb->RPN = RPN;
        break;
    case 2:
        tlb->attr = (tlb->attr & 0x1) | (value & 0x0000FF00);
        tlb->prot = tlb->prot & PAGE_VALID;
        if (value & 0x1) {
            tlb->prot |= PAGE_READ << 4;
        }
        if (value & 0x2) {
            tlb->prot |= PAGE_WRITE << 4;
        }
        if (value & 0x4) {
            tlb->prot |= PAGE_EXEC << 4;
        }
        if (value & 0x8) {
            tlb->prot |= PAGE_READ;
        }
        if (value & 0x10) {
            tlb->prot |= PAGE_WRITE;
        }
        if (value & 0x20) {
            tlb->prot |= PAGE_EXEC;
        }
        break;
    }
}

target_ulong helper_440_tlbre(uint32_t word, target_ulong entry)
{
    ppcemb_tlb_t *tlb;
    target_ulong ret;
    int size;

    entry &= 0x3F;
    tlb = &env->tlb.tlbe[entry];
    switch (word) {
    default:
        /* Just here to please gcc */
    case 0:
        ret = tlb->EPN;
        size = booke_page_size_to_tlb(tlb->size);
        if (size < 0 || size > 0xF) {
            size = 1;
        }
        ret |= size << 4;
        if (tlb->attr & 0x1) {
            ret |= 0x100;
        }
        if (tlb->prot & PAGE_VALID) {
            ret |= 0x200;
        }
        env->spr[SPR_440_MMUCR] &= ~0x000000FF;
        env->spr[SPR_440_MMUCR] |= tlb->PID;
        break;
    case 1:
        ret = tlb->RPN;
        break;
    case 2:
        ret = tlb->attr & ~0x1;
        if (tlb->prot & (PAGE_READ << 4)) {
            ret |= 0x1;
        }
        if (tlb->prot & (PAGE_WRITE << 4)) {
            ret |= 0x2;
        }
        if (tlb->prot & (PAGE_EXEC << 4)) {
            ret |= 0x4;
        }
        if (tlb->prot & PAGE_READ) {
            ret |= 0x8;
        }
        if (tlb->prot & PAGE_WRITE) {
            ret |= 0x10;
        }
        if (tlb->prot & PAGE_EXEC) {
            ret |= 0x20;
        }
        break;
    }
    return ret;
}

target_ulong helper_440_tlbsx(target_ulong address)
{
    return ppcemb_tlb_search(env, address, env->spr[SPR_440_MMUCR] & 0xFF);
}

/* PowerPC BookE 2.06 TLB management */

static ppcmas_tlb_t *booke206_cur_tlb(CPUPPCState *env)
{
    uint32_t tlbncfg = 0;
    int esel = (env->spr[SPR_BOOKE_MAS0] & MAS0_ESEL_MASK) >> MAS0_ESEL_SHIFT;
    int ea = (env->spr[SPR_BOOKE_MAS2] & MAS2_EPN_MASK);
    int tlb;

    tlb = (env->spr[SPR_BOOKE_MAS0] & MAS0_TLBSEL_MASK) >> MAS0_TLBSEL_SHIFT;
    tlbncfg = env->spr[SPR_BOOKE_TLB0CFG + tlb];

    if ((tlbncfg & TLBnCFG_HES) && (env->spr[SPR_BOOKE_MAS0] & MAS0_HES)) {
        cpu_abort(env, "we don't support HES yet\n");
    }

    return booke206_get_tlbm(env, tlb, ea, esel);
}

void helper_booke_setpid(uint32_t pidn, target_ulong pid)
{
    env->spr[pidn] = pid;
    /* changing PIDs mean we're in a different address space now */
    tlb_flush(env, 1);
}

void helper_booke206_tlbwe(void)
{
    uint32_t tlbncfg, tlbn;
    ppcmas_tlb_t *tlb;
    uint32_t size_tlb, size_ps;

    switch (env->spr[SPR_BOOKE_MAS0] & MAS0_WQ_MASK) {
    case MAS0_WQ_ALWAYS:
        /* good to go, write that entry */
        break;
    case MAS0_WQ_COND:
        /* XXX check if reserved */
        if (0) {
            return;
        }
        break;
    case MAS0_WQ_CLR_RSRV:
        /* XXX clear entry */
        return;
    default:
        /* no idea what to do */
        return;
    }

    if (((env->spr[SPR_BOOKE_MAS0] & MAS0_ATSEL) == MAS0_ATSEL_LRAT) &&
        !msr_gs) {
        /* XXX we don't support direct LRAT setting yet */
        fprintf(stderr, "cpu: don't support LRAT setting yet\n");
        return;
    }

    tlbn = (env->spr[SPR_BOOKE_MAS0] & MAS0_TLBSEL_MASK) >> MAS0_TLBSEL_SHIFT;
    tlbncfg = env->spr[SPR_BOOKE_TLB0CFG + tlbn];

    tlb = booke206_cur_tlb(env);

    if (!tlb) {
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL |
                                   POWERPC_EXCP_INVAL_INVAL);
    }

    /* check that we support the targeted size */
    size_tlb = (env->spr[SPR_BOOKE_MAS1] & MAS1_TSIZE_MASK) >> MAS1_TSIZE_SHIFT;
    size_ps = booke206_tlbnps(env, tlbn);
    if ((env->spr[SPR_BOOKE_MAS1] & MAS1_VALID) && (tlbncfg & TLBnCFG_AVAIL) &&
        !(size_ps & (1 << size_tlb))) {
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL |
                                   POWERPC_EXCP_INVAL_INVAL);
    }

    if (msr_gs) {
        cpu_abort(env, "missing HV implementation\n");
    }
    tlb->mas7_3 = ((uint64_t)env->spr[SPR_BOOKE_MAS7] << 32) |
        env->spr[SPR_BOOKE_MAS3];
    tlb->mas1 = env->spr[SPR_BOOKE_MAS1];

    /* MAV 1.0 only */
    if (!(tlbncfg & TLBnCFG_AVAIL)) {
        /* force !AVAIL TLB entries to correct page size */
        tlb->mas1 &= ~MAS1_TSIZE_MASK;
        /* XXX can be configured in MMUCSR0 */
        tlb->mas1 |= (tlbncfg & TLBnCFG_MINSIZE) >> 12;
    }

    /* XXX needs to change when supporting 64-bit e500 */
    tlb->mas2 = env->spr[SPR_BOOKE_MAS2] & 0xffffffff;

    if (!(tlbncfg & TLBnCFG_IPROT)) {
        /* no IPROT supported by TLB */
        tlb->mas1 &= ~MAS1_IPROT;
    }

    if (booke206_tlb_to_page_size(env, tlb) == TARGET_PAGE_SIZE) {
        tlb_flush_page(env, tlb->mas2 & MAS2_EPN_MASK);
    } else {
        tlb_flush(env, 1);
    }
}

static inline void booke206_tlb_to_mas(CPUPPCState *env, ppcmas_tlb_t *tlb)
{
    int tlbn = booke206_tlbm_to_tlbn(env, tlb);
    int way = booke206_tlbm_to_way(env, tlb);

    env->spr[SPR_BOOKE_MAS0] = tlbn << MAS0_TLBSEL_SHIFT;
    env->spr[SPR_BOOKE_MAS0] |= way << MAS0_ESEL_SHIFT;
    env->spr[SPR_BOOKE_MAS0] |= env->last_way << MAS0_NV_SHIFT;

    env->spr[SPR_BOOKE_MAS1] = tlb->mas1;
    env->spr[SPR_BOOKE_MAS2] = tlb->mas2;
    env->spr[SPR_BOOKE_MAS3] = tlb->mas7_3;
    env->spr[SPR_BOOKE_MAS7] = tlb->mas7_3 >> 32;
}

void helper_booke206_tlbre(void)
{
    ppcmas_tlb_t *tlb = NULL;

    tlb = booke206_cur_tlb(env);
    if (!tlb) {
        env->spr[SPR_BOOKE_MAS1] = 0;
    } else {
        booke206_tlb_to_mas(env, tlb);
    }
}

void helper_booke206_tlbsx(target_ulong address)
{
    ppcmas_tlb_t *tlb = NULL;
    int i, j;
    target_phys_addr_t raddr;
    uint32_t spid, sas;

    spid = (env->spr[SPR_BOOKE_MAS6] & MAS6_SPID_MASK) >> MAS6_SPID_SHIFT;
    sas = env->spr[SPR_BOOKE_MAS6] & MAS6_SAS;

    for (i = 0; i < BOOKE206_MAX_TLBN; i++) {
        int ways = booke206_tlb_ways(env, i);

        for (j = 0; j < ways; j++) {
            tlb = booke206_get_tlbm(env, i, address, j);

            if (!tlb) {
                continue;
            }

            if (ppcmas_tlb_check(env, tlb, &raddr, address, spid)) {
                continue;
            }

            if (sas != ((tlb->mas1 & MAS1_TS) >> MAS1_TS_SHIFT)) {
                continue;
            }

            booke206_tlb_to_mas(env, tlb);
            return;
        }
    }

    /* no entry found, fill with defaults */
    env->spr[SPR_BOOKE_MAS0] = env->spr[SPR_BOOKE_MAS4] & MAS4_TLBSELD_MASK;
    env->spr[SPR_BOOKE_MAS1] = env->spr[SPR_BOOKE_MAS4] & MAS4_TSIZED_MASK;
    env->spr[SPR_BOOKE_MAS2] = env->spr[SPR_BOOKE_MAS4] & MAS4_WIMGED_MASK;
    env->spr[SPR_BOOKE_MAS3] = 0;
    env->spr[SPR_BOOKE_MAS7] = 0;

    if (env->spr[SPR_BOOKE_MAS6] & MAS6_SAS) {
        env->spr[SPR_BOOKE_MAS1] |= MAS1_TS;
    }

    env->spr[SPR_BOOKE_MAS1] |= (env->spr[SPR_BOOKE_MAS6] >> 16)
        << MAS1_TID_SHIFT;

    /* next victim logic */
    env->spr[SPR_BOOKE_MAS0] |= env->last_way << MAS0_ESEL_SHIFT;
    env->last_way++;
    env->last_way &= booke206_tlb_ways(env, 0) - 1;
    env->spr[SPR_BOOKE_MAS0] |= env->last_way << MAS0_NV_SHIFT;
}

static inline void booke206_invalidate_ea_tlb(CPUPPCState *env, int tlbn,
                                              uint32_t ea)
{
    int i;
    int ways = booke206_tlb_ways(env, tlbn);
    target_ulong mask;

    for (i = 0; i < ways; i++) {
        ppcmas_tlb_t *tlb = booke206_get_tlbm(env, tlbn, ea, i);
        if (!tlb) {
            continue;
        }
        mask = ~(booke206_tlb_to_page_size(env, tlb) - 1);
        if (((tlb->mas2 & MAS2_EPN_MASK) == (ea & mask)) &&
            !(tlb->mas1 & MAS1_IPROT)) {
            tlb->mas1 &= ~MAS1_VALID;
        }
    }
}

void helper_booke206_tlbivax(target_ulong address)
{
    if (address & 0x4) {
        /* flush all entries */
        if (address & 0x8) {
            /* flush all of TLB1 */
            booke206_flush_tlb(env, BOOKE206_FLUSH_TLB1, 1);
        } else {
            /* flush all of TLB0 */
            booke206_flush_tlb(env, BOOKE206_FLUSH_TLB0, 0);
        }
        return;
    }

    if (address & 0x8) {
        /* flush TLB1 entries */
        booke206_invalidate_ea_tlb(env, 1, address);
        tlb_flush(env, 1);
    } else {
        /* flush TLB0 entries */
        booke206_invalidate_ea_tlb(env, 0, address);
        tlb_flush_page(env, address & MAS2_EPN_MASK);
    }
}

void helper_booke206_tlbilx0(target_ulong address)
{
    /* XXX missing LPID handling */
    booke206_flush_tlb(env, -1, 1);
}

void helper_booke206_tlbilx1(target_ulong address)
{
    int i, j;
    int tid = (env->spr[SPR_BOOKE_MAS6] & MAS6_SPID);
    ppcmas_tlb_t *tlb = env->tlb.tlbm;
    int tlb_size;

    /* XXX missing LPID handling */
    for (i = 0; i < BOOKE206_MAX_TLBN; i++) {
        tlb_size = booke206_tlb_size(env, i);
        for (j = 0; j < tlb_size; j++) {
            if (!(tlb[j].mas1 & MAS1_IPROT) &&
                ((tlb[j].mas1 & MAS1_TID_MASK) == tid)) {
                tlb[j].mas1 &= ~MAS1_VALID;
            }
        }
        tlb += booke206_tlb_size(env, i);
    }
    tlb_flush(env, 1);
}

void helper_booke206_tlbilx3(target_ulong address)
{
    int i, j;
    ppcmas_tlb_t *tlb;
    int tid = (env->spr[SPR_BOOKE_MAS6] & MAS6_SPID);
    int pid = tid >> MAS6_SPID_SHIFT;
    int sgs = env->spr[SPR_BOOKE_MAS5] & MAS5_SGS;
    int ind = (env->spr[SPR_BOOKE_MAS6] & MAS6_SIND) ? MAS1_IND : 0;
    /* XXX check for unsupported isize and raise an invalid opcode then */
    int size = env->spr[SPR_BOOKE_MAS6] & MAS6_ISIZE_MASK;
    /* XXX implement MAV2 handling */
    bool mav2 = false;

    /* XXX missing LPID handling */
    /* flush by pid and ea */
    for (i = 0; i < BOOKE206_MAX_TLBN; i++) {
        int ways = booke206_tlb_ways(env, i);

        for (j = 0; j < ways; j++) {
            tlb = booke206_get_tlbm(env, i, address, j);
            if (!tlb) {
                continue;
            }
            if ((ppcmas_tlb_check(env, tlb, NULL, address, pid) != 0) ||
                (tlb->mas1 & MAS1_IPROT) ||
                ((tlb->mas1 & MAS1_IND) != ind) ||
                ((tlb->mas8 & MAS8_TGS) != sgs)) {
                continue;
            }
            if (mav2 && ((tlb->mas1 & MAS1_TSIZE_MASK) != size)) {
                /* XXX only check when MMUCFG[TWC] || TLBnCFG[HES] */
                continue;
            }
            /* XXX e500mc doesn't match SAS, but other cores might */
            tlb->mas1 &= ~MAS1_VALID;
        }
    }
    tlb_flush(env, 1);
}

void helper_booke206_tlbflush(uint32_t type)
{
    int flags = 0;

    if (type & 2) {
        flags |= BOOKE206_FLUSH_TLB1;
    }

    if (type & 4) {
        flags |= BOOKE206_FLUSH_TLB0;
    }

    booke206_flush_tlb(env, flags, 1);
}
#endif /* !CONFIG_USER_ONLY */
