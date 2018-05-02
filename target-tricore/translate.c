/*
 *  TriCore emulation for qemu: main translation routines.
 *
 *  Copyright (c) 2013-2014 Bastian Koppelmann C-Lab/University Paderborn
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


#include "cpu.h"
#include "disas/disas.h"
#include "tcg-op.h"
#include "exec/cpu_ldst.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

#include "tricore-opcodes.h"

/*
 * TCG registers
 */
static TCGv cpu_PC;
static TCGv cpu_PCXI;
static TCGv cpu_PSW;
static TCGv cpu_ICR;
/* GPR registers */
static TCGv cpu_gpr_a[16];
static TCGv cpu_gpr_d[16];
/* PSW Flag cache */
static TCGv cpu_PSW_C;
static TCGv cpu_PSW_V;
static TCGv cpu_PSW_SV;
static TCGv cpu_PSW_AV;
static TCGv cpu_PSW_SAV;
/* CPU env */
static TCGv_ptr cpu_env;

#include "exec/gen-icount.h"

static const char *regnames_a[] = {
      "a0"  , "a1"  , "a2"  , "a3" , "a4"  , "a5" ,
      "a6"  , "a7"  , "a8"  , "a9" , "sp" , "a11" ,
      "a12" , "a13" , "a14" , "a15",
    };

static const char *regnames_d[] = {
      "d0"  , "d1"  , "d2"  , "d3" , "d4"  , "d5"  ,
      "d6"  , "d7"  , "d8"  , "d9" , "d10" , "d11" ,
      "d12" , "d13" , "d14" , "d15",
    };

typedef struct DisasContext {
    struct TranslationBlock *tb;
    target_ulong pc, saved_pc, next_pc;
    uint32_t opcode;
    int singlestep_enabled;
    /* Routine used to access memory */
    int mem_idx;
    uint32_t hflags, saved_hflags;
    int bstate;
} DisasContext;

enum {

    BS_NONE   = 0,
    BS_STOP   = 1,
    BS_BRANCH = 2,
    BS_EXCP   = 3,
};

void tricore_cpu_dump_state(CPUState *cs, FILE *f,
                            fprintf_function cpu_fprintf, int flags)
{
    TriCoreCPU *cpu = TRICORE_CPU(cs);
    CPUTriCoreState *env = &cpu->env;
    int i;

    cpu_fprintf(f, "PC=%08x\n", env->PC);
    for (i = 0; i < 16; ++i) {
        if ((i & 3) == 0) {
            cpu_fprintf(f, "GPR A%02d:", i);
        }
        cpu_fprintf(f, " %s " TARGET_FMT_lx, regnames_a[i], env->gpr_a[i]);
    }
    for (i = 0; i < 16; ++i) {
        if ((i & 3) == 0) {
            cpu_fprintf(f, "GPR D%02d:", i);
        }
        cpu_fprintf(f, " %s " TARGET_FMT_lx, regnames_d[i], env->gpr_d[i]);
    }

}

/*
 * Functions to generate micro-ops
 */

/* Functions for arithmetic instructions  */

static inline void gen_add_d(TCGv ret, TCGv r1, TCGv r2)
{
    TCGv t0 = tcg_temp_new_i32();
    TCGv result = tcg_temp_new_i32();
    /* Addition and set V/SV bits */
    tcg_gen_add_tl(result, r1, r2);
    /* calc V bit */
    tcg_gen_xor_tl(cpu_PSW_V, result, r1);
    tcg_gen_xor_tl(t0, r1, r2);
    tcg_gen_andc_tl(cpu_PSW_V, cpu_PSW_V, t0);
    /* Calc SV bit */
    tcg_gen_or_tl(cpu_PSW_SV, cpu_PSW_SV, cpu_PSW_V);
    /* Calc AV/SAV bits */
    tcg_gen_add_tl(cpu_PSW_AV, result, result);
    tcg_gen_xor_tl(cpu_PSW_AV, result, cpu_PSW_AV);
    /* calc SAV */
    tcg_gen_or_tl(cpu_PSW_SAV, cpu_PSW_SAV, cpu_PSW_AV);
    /* write back result */
    tcg_gen_mov_tl(ret, result);

    tcg_temp_free(result);
    tcg_temp_free(t0);
}

static inline void gen_addi_d(TCGv ret, TCGv r1, target_ulong r2)
{
    TCGv temp = tcg_const_i32(r2);
    gen_add_d(ret, r1, temp);
    tcg_temp_free(temp);
}

static inline void gen_cond_add(TCGCond cond, TCGv r1, TCGv r2, TCGv r3,
                                TCGv r4)
{
    TCGv temp = tcg_temp_new();
    TCGv temp2 = tcg_temp_new();
    TCGv result = tcg_temp_new();
    TCGv mask = tcg_temp_new();
    TCGv t0 = tcg_const_i32(0);

    /* create mask for sticky bits */
    tcg_gen_setcond_tl(cond, mask, r4, t0);
    tcg_gen_shli_tl(mask, mask, 31);

    tcg_gen_add_tl(result, r1, r2);
    /* Calc PSW_V */
    tcg_gen_xor_tl(temp, result, r1);
    tcg_gen_xor_tl(temp2, r1, r2);
    tcg_gen_andc_tl(temp, temp, temp2);
    tcg_gen_movcond_tl(cond, cpu_PSW_V, r4, t0, temp, cpu_PSW_V);
    /* Set PSW_SV */
    tcg_gen_and_tl(temp, temp, mask);
    tcg_gen_or_tl(cpu_PSW_SV, temp, cpu_PSW_SV);
    /* calc AV bit */
    tcg_gen_add_tl(temp, result, result);
    tcg_gen_xor_tl(temp, temp, result);
    tcg_gen_movcond_tl(cond, cpu_PSW_AV, r4, t0, temp, cpu_PSW_AV);
    /* calc SAV bit */
    tcg_gen_and_tl(temp, temp, mask);
    tcg_gen_or_tl(cpu_PSW_SAV, temp, cpu_PSW_SAV);
    /* write back result */
    tcg_gen_movcond_tl(cond, r3, r4, t0, result, r3);

    tcg_temp_free(t0);
    tcg_temp_free(temp);
    tcg_temp_free(temp2);
    tcg_temp_free(result);
    tcg_temp_free(mask);
}

static inline void gen_condi_add(TCGCond cond, TCGv r1, int32_t r2,
                                 TCGv r3, TCGv r4)
{
    TCGv temp = tcg_const_i32(r2);
    gen_cond_add(cond, r1, temp, r3, r4);
    tcg_temp_free(temp);
}

static void gen_shi(TCGv ret, TCGv r1, int32_t shift_count)
{
    if (shift_count == -32) {
        tcg_gen_movi_tl(ret, 0);
    } else if (shift_count >= 0) {
        tcg_gen_shli_tl(ret, r1, shift_count);
    } else {
        tcg_gen_shri_tl(ret, r1, -shift_count);
    }
}

static void gen_shaci(TCGv ret, TCGv r1, int32_t shift_count)
{
    uint32_t msk, msk_start;
    TCGv temp = tcg_temp_new();
    TCGv temp2 = tcg_temp_new();
    TCGv t_0 = tcg_const_i32(0);

    if (shift_count == 0) {
        /* Clear PSW.C and PSW.V */
        tcg_gen_movi_tl(cpu_PSW_C, 0);
        tcg_gen_mov_tl(cpu_PSW_V, cpu_PSW_C);
        tcg_gen_mov_tl(ret, r1);
    } else if (shift_count == -32) {
        /* set PSW.C */
        tcg_gen_mov_tl(cpu_PSW_C, r1);
        /* fill ret completly with sign bit */
        tcg_gen_sari_tl(ret, r1, 31);
        /* clear PSW.V */
        tcg_gen_movi_tl(cpu_PSW_V, 0);
    } else if (shift_count > 0) {
        TCGv t_max = tcg_const_i32(0x7FFFFFFF >> shift_count);
        TCGv t_min = tcg_const_i32(((int32_t) -0x80000000) >> shift_count);

        /* calc carry */
        msk_start = 32 - shift_count;
        msk = ((1 << shift_count) - 1) << msk_start;
        tcg_gen_andi_tl(cpu_PSW_C, r1, msk);
        /* calc v/sv bits */
        tcg_gen_setcond_tl(TCG_COND_GT, temp, r1, t_max);
        tcg_gen_setcond_tl(TCG_COND_LT, temp2, r1, t_min);
        tcg_gen_or_tl(cpu_PSW_V, temp, temp2);
        tcg_gen_shli_tl(cpu_PSW_V, cpu_PSW_V, 31);
        /* calc sv */
        tcg_gen_or_tl(cpu_PSW_SV, cpu_PSW_V, cpu_PSW_SV);
        /* do shift */
        tcg_gen_shli_tl(ret, r1, shift_count);

        tcg_temp_free(t_max);
        tcg_temp_free(t_min);
    } else {
        /* clear PSW.V */
        tcg_gen_movi_tl(cpu_PSW_V, 0);
        /* calc carry */
        msk = (1 << -shift_count) - 1;
        tcg_gen_andi_tl(cpu_PSW_C, r1, msk);
        /* do shift */
        tcg_gen_sari_tl(ret, r1, -shift_count);
    }
    /* calc av overflow bit */
    tcg_gen_add_tl(cpu_PSW_AV, ret, ret);
    tcg_gen_xor_tl(cpu_PSW_AV, ret, cpu_PSW_AV);
    /* calc sav overflow bit */
    tcg_gen_or_tl(cpu_PSW_SAV, cpu_PSW_SAV, cpu_PSW_AV);

    tcg_temp_free(temp);
    tcg_temp_free(temp2);
    tcg_temp_free(t_0);
}

/*
 * Functions for decoding instructions
 */

static void decode_src_opc(DisasContext *ctx, int op1)
{
    int r1;
    int32_t const4;
    TCGv temp, temp2;

    r1 = MASK_OP_SRC_S1D(ctx->opcode);
    const4 = MASK_OP_SRC_CONST4_SEXT(ctx->opcode);

    switch (op1) {
    case OPC1_16_SRC_ADD:
        gen_addi_d(cpu_gpr_d[r1], cpu_gpr_d[r1], const4);
        break;
    case OPC1_16_SRC_ADD_A15:
        gen_addi_d(cpu_gpr_d[r1], cpu_gpr_d[15], const4);
        break;
    case OPC1_16_SRC_ADD_15A:
        gen_addi_d(cpu_gpr_d[15], cpu_gpr_d[r1], const4);
        break;
    case OPC1_16_SRC_ADD_A:
        tcg_gen_addi_tl(cpu_gpr_a[r1], cpu_gpr_a[r1], const4);
        break;
    case OPC1_16_SRC_CADD:
        gen_condi_add(TCG_COND_NE, cpu_gpr_d[r1], const4, cpu_gpr_d[r1],
                      cpu_gpr_d[15]);
        break;
    case OPC1_16_SRC_CADDN:
        gen_condi_add(TCG_COND_EQ, cpu_gpr_d[r1], const4, cpu_gpr_d[r1],
                      cpu_gpr_d[15]);
        break;
    case OPC1_16_SRC_CMOV:
        temp = tcg_const_tl(0);
        temp2 = tcg_const_tl(const4);
        tcg_gen_movcond_tl(TCG_COND_NE, cpu_gpr_d[r1], cpu_gpr_d[15], temp,
                           temp2, cpu_gpr_d[r1]);
        tcg_temp_free(temp);
        tcg_temp_free(temp2);
        break;
    case OPC1_16_SRC_CMOVN:
        temp = tcg_const_tl(0);
        temp2 = tcg_const_tl(const4);
        tcg_gen_movcond_tl(TCG_COND_EQ, cpu_gpr_d[r1], cpu_gpr_d[15], temp,
                           temp2, cpu_gpr_d[r1]);
        tcg_temp_free(temp);
        tcg_temp_free(temp2);
        break;
    case OPC1_16_SRC_EQ:
        tcg_gen_setcondi_tl(TCG_COND_EQ, cpu_gpr_d[15], cpu_gpr_d[r1],
                            const4);
        break;
    case OPC1_16_SRC_LT:
        tcg_gen_setcondi_tl(TCG_COND_LT, cpu_gpr_d[15], cpu_gpr_d[r1],
                            const4);
        break;
    case OPC1_16_SRC_MOV:
        tcg_gen_movi_tl(cpu_gpr_d[r1], const4);
        break;
    case OPC1_16_SRC_MOV_A:
        const4 = MASK_OP_SRC_CONST4(ctx->opcode);
        tcg_gen_movi_tl(cpu_gpr_a[r1], const4);
        break;
    case OPC1_16_SRC_SH:
        gen_shi(cpu_gpr_d[r1], cpu_gpr_d[r1], const4);
        break;
    case OPC1_16_SRC_SHA:
        gen_shaci(cpu_gpr_d[r1], cpu_gpr_d[r1], const4);
        break;
    }
}

static void decode_16Bit_opc(CPUTriCoreState *env, DisasContext *ctx)
{
    int op1;

    op1 = MASK_OP_MAJOR(ctx->opcode);

    switch (op1) {
    case OPC1_16_SRC_ADD:
    case OPC1_16_SRC_ADD_A15:
    case OPC1_16_SRC_ADD_15A:
    case OPC1_16_SRC_ADD_A:
    case OPC1_16_SRC_CADD:
    case OPC1_16_SRC_CADDN:
    case OPC1_16_SRC_CMOV:
    case OPC1_16_SRC_CMOVN:
    case OPC1_16_SRC_EQ:
    case OPC1_16_SRC_LT:
    case OPC1_16_SRC_MOV:
    case OPC1_16_SRC_MOV_A:
    case OPC1_16_SRC_SH:
    case OPC1_16_SRC_SHA:
        decode_src_opc(ctx, op1);
        break;
    }
}

static void decode_32Bit_opc(CPUTriCoreState *env, DisasContext *ctx)
{
}

static void decode_opc(CPUTriCoreState *env, DisasContext *ctx, int *is_branch)
{
    /* 16-Bit Instruction */
    if ((ctx->opcode & 0x1) == 0) {
        ctx->next_pc = ctx->pc + 2;
        decode_16Bit_opc(env, ctx);
    /* 32-Bit Instruction */
    } else {
        ctx->next_pc = ctx->pc + 4;
        decode_32Bit_opc(env, ctx);
    }
}

static inline void
gen_intermediate_code_internal(TriCoreCPU *cpu, struct TranslationBlock *tb,
                              int search_pc)
{
    CPUState *cs = CPU(cpu);
    CPUTriCoreState *env = &cpu->env;
    DisasContext ctx;
    target_ulong pc_start;
    int num_insns;
    uint16_t *gen_opc_end;

    if (search_pc) {
        qemu_log("search pc %d\n", search_pc);
    }

    num_insns = 0;
    pc_start = tb->pc;
    gen_opc_end = tcg_ctx.gen_opc_buf + OPC_MAX_SIZE;
    ctx.pc = pc_start;
    ctx.saved_pc = -1;
    ctx.tb = tb;
    ctx.singlestep_enabled = cs->singlestep_enabled;
    ctx.bstate = BS_NONE;
    ctx.mem_idx = cpu_mmu_index(env);

    tcg_clear_temp_count();
    gen_tb_start();
    while (ctx.bstate == BS_NONE) {
        ctx.opcode = cpu_ldl_code(env, ctx.pc);
        decode_opc(env, &ctx, 0);

        num_insns++;

        if (tcg_ctx.gen_opc_ptr >= gen_opc_end) {
            break;
        }
        if (singlestep) {
            break;
        }
        ctx.pc = ctx.next_pc;
    }

    gen_tb_end(tb, num_insns);
    *tcg_ctx.gen_opc_ptr = INDEX_op_end;
    if (search_pc) {
        printf("done_generating search pc\n");
    } else {
        tb->size = ctx.pc - pc_start;
        tb->icount = num_insns;
    }
    if (tcg_check_temp_count()) {
        printf("LEAK at %08x\n", env->PC);
    }

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)) {
        qemu_log("IN: %s\n", lookup_symbol(pc_start));
        log_target_disas(env, pc_start, ctx.pc - pc_start, 0);
        qemu_log("\n");
    }
#endif
}

void
gen_intermediate_code(CPUTriCoreState *env, struct TranslationBlock *tb)
{
    gen_intermediate_code_internal(tricore_env_get_cpu(env), tb, false);
}

void
gen_intermediate_code_pc(CPUTriCoreState *env, struct TranslationBlock *tb)
{
    gen_intermediate_code_internal(tricore_env_get_cpu(env), tb, true);
}

void
restore_state_to_opc(CPUTriCoreState *env, TranslationBlock *tb, int pc_pos)
{
    env->PC = tcg_ctx.gen_opc_pc[pc_pos];
}
/*
 *
 * Initialization
 *
 */

void cpu_state_reset(CPUTriCoreState *env)
{
    /* Reset Regs to Default Value */
    env->PSW = 0xb80;
}

static void tricore_tcg_init_csfr(void)
{
    cpu_PCXI = tcg_global_mem_new(TCG_AREG0,
                          offsetof(CPUTriCoreState, PCXI), "PCXI");
    cpu_PSW = tcg_global_mem_new(TCG_AREG0,
                          offsetof(CPUTriCoreState, PSW), "PSW");
    cpu_PC = tcg_global_mem_new(TCG_AREG0,
                          offsetof(CPUTriCoreState, PC), "PC");
    cpu_ICR = tcg_global_mem_new(TCG_AREG0,
                          offsetof(CPUTriCoreState, ICR), "ICR");
}

void tricore_tcg_init(void)
{
    int i;
    static int inited;
    if (inited) {
        return;
    }
    cpu_env = tcg_global_reg_new_ptr(TCG_AREG0, "env");
    /* reg init */
    for (i = 0 ; i < 16 ; i++) {
        cpu_gpr_a[i] = tcg_global_mem_new(TCG_AREG0,
                                          offsetof(CPUTriCoreState, gpr_a[i]),
                                          regnames_a[i]);
    }
    for (i = 0 ; i < 16 ; i++) {
        cpu_gpr_d[i] = tcg_global_mem_new(TCG_AREG0,
                                  offsetof(CPUTriCoreState, gpr_d[i]),
                                           regnames_d[i]);
    }
    tricore_tcg_init_csfr();
    /* init PSW flag cache */
    cpu_PSW_C = tcg_global_mem_new(TCG_AREG0,
                                   offsetof(CPUTriCoreState, PSW_USB_C),
                                   "PSW_C");
    cpu_PSW_V = tcg_global_mem_new(TCG_AREG0,
                                   offsetof(CPUTriCoreState, PSW_USB_V),
                                   "PSW_V");
    cpu_PSW_SV = tcg_global_mem_new(TCG_AREG0,
                                    offsetof(CPUTriCoreState, PSW_USB_SV),
                                    "PSW_SV");
    cpu_PSW_AV = tcg_global_mem_new(TCG_AREG0,
                                    offsetof(CPUTriCoreState, PSW_USB_AV),
                                    "PSW_AV");
    cpu_PSW_SAV = tcg_global_mem_new(TCG_AREG0,
                                     offsetof(CPUTriCoreState, PSW_USB_SAV),
                                     "PSW_SAV");
}
