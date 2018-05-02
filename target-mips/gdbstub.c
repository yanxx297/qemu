/*
 * MIPS gdb server stub
 *
 * Copyright (c) 2003-2005 Fabrice Bellard
 * Copyright (c) 2013 SUSE LINUX Products GmbH
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

static int cpu_gdb_read_register(CPUMIPSState *env, uint8_t *mem_buf, int n)
{
    if (n < 32) {
        GET_REGL(env->active_tc.gpr[n]);
    }
    if (env->CP0_Config1 & (1 << CP0C1_FP)) {
        if (n >= 38 && n < 70) {
            if (env->CP0_Status & (1 << CP0St_FR)) {
                GET_REGL(env->active_fpu.fpr[n - 38].d);
            } else {
                GET_REGL(env->active_fpu.fpr[n - 38].w[FP_ENDIAN_IDX]);
            }
        }
        switch (n) {
        case 70:
            GET_REGL((int32_t)env->active_fpu.fcr31);
        case 71:
            GET_REGL((int32_t)env->active_fpu.fcr0);
        }
    }
    switch (n) {
    case 32:
        GET_REGL((int32_t)env->CP0_Status);
    case 33:
        GET_REGL(env->active_tc.LO[0]);
    case 34:
        GET_REGL(env->active_tc.HI[0]);
    case 35:
        GET_REGL(env->CP0_BadVAddr);
    case 36:
        GET_REGL((int32_t)env->CP0_Cause);
    case 37:
        GET_REGL(env->active_tc.PC | !!(env->hflags & MIPS_HFLAG_M16));
    case 72:
        GET_REGL(0); /* fp */
    case 89:
        GET_REGL((int32_t)env->CP0_PRid);
    }
    if (n >= 73 && n <= 88) {
        /* 16 embedded regs.  */
        GET_REGL(0);
    }

    return 0;
}

/* convert MIPS rounding mode in FCR31 to IEEE library */
static unsigned int ieee_rm[] = {
    float_round_nearest_even,
    float_round_to_zero,
    float_round_up,
    float_round_down
};
#define RESTORE_ROUNDING_MODE \
    set_float_rounding_mode(ieee_rm[env->active_fpu.fcr31 & 3], \
                            &env->active_fpu.fp_status)

static int cpu_gdb_write_register(CPUMIPSState *env, uint8_t *mem_buf, int n)
{
    target_ulong tmp;

    tmp = ldtul_p(mem_buf);

    if (n < 32) {
        env->active_tc.gpr[n] = tmp;
        return sizeof(target_ulong);
    }
    if (env->CP0_Config1 & (1 << CP0C1_FP)
            && n >= 38 && n < 73) {
        if (n < 70) {
            if (env->CP0_Status & (1 << CP0St_FR)) {
                env->active_fpu.fpr[n - 38].d = tmp;
            } else {
                env->active_fpu.fpr[n - 38].w[FP_ENDIAN_IDX] = tmp;
            }
        }
        switch (n) {
        case 70:
            env->active_fpu.fcr31 = tmp & 0xFF83FFFF;
            /* set rounding mode */
            RESTORE_ROUNDING_MODE;
            break;
        case 71:
            env->active_fpu.fcr0 = tmp;
            break;
        }
        return sizeof(target_ulong);
    }
    switch (n) {
    case 32:
        env->CP0_Status = tmp;
        break;
    case 33:
        env->active_tc.LO[0] = tmp;
        break;
    case 34:
        env->active_tc.HI[0] = tmp;
        break;
    case 35:
        env->CP0_BadVAddr = tmp;
        break;
    case 36:
        env->CP0_Cause = tmp;
        break;
    case 37:
        env->active_tc.PC = tmp & ~(target_ulong)1;
        if (tmp & 1) {
            env->hflags |= MIPS_HFLAG_M16;
        } else {
            env->hflags &= ~(MIPS_HFLAG_M16);
        }
        break;
    case 72: /* fp, ignored */
        break;
    default:
        if (n > 89) {
            return 0;
        }
        /* Other registers are readonly.  Ignore writes.  */
        break;
    }

    return sizeof(target_ulong);
}
