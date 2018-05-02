/*
 * ARM Generic Interrupt Controller v3
 *
 * Copyright (c) 2016 Linaro Limited
 * Written by Peter Maydell
 *
 * This code is licensed under the GPL, version 2 or (at your option)
 * any later version.
 */

/* This file contains the code for the system register interface
 * portions of the GICv3.
 */

#include "qemu/osdep.h"
#include "trace.h"
#include "gicv3_internal.h"
#include "cpu.h"

static GICv3CPUState *icc_cs_from_env(CPUARMState *env)
{
    /* Given the CPU, find the right GICv3CPUState struct.
     * Since we registered the CPU interface with the EL change hook as
     * the opaque pointer, we can just directly get from the CPU to it.
     */
    return arm_get_el_change_hook_opaque(arm_env_get_cpu(env));
}

static bool gicv3_use_ns_bank(CPUARMState *env)
{
    /* Return true if we should use the NonSecure bank for a banked GIC
     * CPU interface register. Note that this differs from the
     * access_secure_reg() function because GICv3 banked registers are
     * banked even for AArch64, unlike the other CPU system registers.
     */
    return !arm_is_secure_below_el3(env);
}

static uint64_t icc_pmr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint32_t value = cs->icc_pmr_el1;

    if (arm_feature(env, ARM_FEATURE_EL3) && !arm_is_secure(env) &&
        (env->cp15.scr_el3 & SCR_FIQ)) {
        /* NS access and Group 0 is inaccessible to NS: return the
         * NS view of the current priority
         */
        if (value & 0x80) {
            /* Secure priorities not visible to NS */
            value = 0;
        } else if (value != 0xff) {
            value = (value << 1) & 0xff;
        }
    }

    trace_gicv3_icc_pmr_read(gicv3_redist_affid(cs), value);

    return value;
}

static void icc_pmr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);

    trace_gicv3_icc_pmr_write(gicv3_redist_affid(cs), value);

    value &= 0xff;

    if (arm_feature(env, ARM_FEATURE_EL3) && !arm_is_secure(env) &&
        (env->cp15.scr_el3 & SCR_FIQ)) {
        /* NS access and Group 0 is inaccessible to NS: return the
         * NS view of the current priority
         */
        if (!(cs->icc_pmr_el1 & 0x80)) {
            /* Current PMR in the secure range, don't allow NS to change it */
            return;
        }
        value = (value >> 1) & 0x80;
    }
    cs->icc_pmr_el1 = value;
    gicv3_cpuif_update(cs);
}

static uint64_t icc_bpr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int grp = (ri->crm == 8) ? GICV3_G0 : GICV3_G1;
    bool satinc = false;
    uint64_t bpr;

    if (grp == GICV3_G1 && gicv3_use_ns_bank(env)) {
        grp = GICV3_G1NS;
    }

    if (grp == GICV3_G1 && !arm_is_el3_or_mon(env) &&
        (cs->icc_ctlr_el1[GICV3_S] & ICC_CTLR_EL1_CBPR)) {
        /* CBPR_EL1S means secure EL1 or AArch32 EL3 !Mon BPR1 accesses
         * modify BPR0
         */
        grp = GICV3_G0;
    }

    if (grp == GICV3_G1NS && arm_current_el(env) < 3 &&
        (cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_CBPR)) {
        /* reads return bpr0 + 1 sat to 7, writes ignored */
        grp = GICV3_G0;
        satinc = true;
    }

    bpr = cs->icc_bpr[grp];
    if (satinc) {
        bpr++;
        bpr = MIN(bpr, 7);
    }

    trace_gicv3_icc_bpr_read(gicv3_redist_affid(cs), bpr);

    return bpr;
}

static void icc_bpr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int grp = (ri->crm == 8) ? GICV3_G0 : GICV3_G1;

    trace_gicv3_icc_pmr_write(gicv3_redist_affid(cs), value);

    if (grp == GICV3_G1 && gicv3_use_ns_bank(env)) {
        grp = GICV3_G1NS;
    }

    if (grp == GICV3_G1 && !arm_is_el3_or_mon(env) &&
        (cs->icc_ctlr_el1[GICV3_S] & ICC_CTLR_EL1_CBPR)) {
        /* CBPR_EL1S means secure EL1 or AArch32 EL3 !Mon BPR1 accesses
         * modify BPR0
         */
        grp = GICV3_G0;
    }

    if (grp == GICV3_G1NS && arm_current_el(env) < 3 &&
        (cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_CBPR)) {
        /* reads return bpr0 + 1 sat to 7, writes ignored */
        return;
    }

    cs->icc_bpr[grp] = value & 7;
    gicv3_cpuif_update(cs);
}

static uint64_t icc_ap_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint64_t value;

    int regno = ri->opc2 & 3;
    int grp = ri->crm & 1 ? GICV3_G0 : GICV3_G1;

    if (grp == GICV3_G1 && gicv3_use_ns_bank(env)) {
        grp = GICV3_G1NS;
    }

    value = cs->icc_apr[grp][regno];

    trace_gicv3_icc_ap_read(regno, gicv3_redist_affid(cs), value);
    return value;
}

static void icc_ap_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);

    int regno = ri->opc2 & 3;
    int grp = ri->crm & 1 ? GICV3_G0 : GICV3_G1;

    trace_gicv3_icc_ap_write(regno, gicv3_redist_affid(cs), value);

    if (grp == GICV3_G1 && gicv3_use_ns_bank(env)) {
        grp = GICV3_G1NS;
    }

    /* It's not possible to claim that a Non-secure interrupt is active
     * at a priority outside the Non-secure range (128..255), since this
     * would otherwise allow malicious NS code to block delivery of S interrupts
     * by writing a bad value to these registers.
     */
    if (grp == GICV3_G1NS && regno < 2 && arm_feature(env, ARM_FEATURE_EL3)) {
        return;
    }

    cs->icc_apr[grp][regno] = value & 0xFFFFFFFFU;
    gicv3_cpuif_update(cs);
}

static uint64_t icc_igrpen_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int grp = ri->opc2 & 1 ? GICV3_G1 : GICV3_G0;
    uint64_t value;

    if (grp == GICV3_G1 && gicv3_use_ns_bank(env)) {
        grp = GICV3_G1NS;
    }

    value = cs->icc_igrpen[grp];
    trace_gicv3_icc_igrpen_read(gicv3_redist_affid(cs), value);
    return value;
}

static void icc_igrpen_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int grp = ri->opc2 & 1 ? GICV3_G1 : GICV3_G0;

    trace_gicv3_icc_igrpen_write(gicv3_redist_affid(cs), value);

    if (grp == GICV3_G1 && gicv3_use_ns_bank(env)) {
        grp = GICV3_G1NS;
    }

    cs->icc_igrpen[grp] = value & ICC_IGRPEN_ENABLE;
    gicv3_cpuif_update(cs);
}

static uint64_t icc_igrpen1_el3_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);

    /* IGRPEN1_EL3 bits 0 and 1 are r/w aliases into IGRPEN1_EL1 NS and S */
    return cs->icc_igrpen[GICV3_G1NS] | (cs->icc_igrpen[GICV3_G1] << 1);
}

static void icc_igrpen1_el3_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                  uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);

    trace_gicv3_icc_igrpen1_el3_write(gicv3_redist_affid(cs), value);

    /* IGRPEN1_EL3 bits 0 and 1 are r/w aliases into IGRPEN1_EL1 NS and S */
    cs->icc_igrpen[GICV3_G1NS] = extract32(value, 0, 1);
    cs->icc_igrpen[GICV3_G1] = extract32(value, 1, 1);
    gicv3_cpuif_update(cs);
}

static uint64_t icc_ctlr_el1_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int bank = gicv3_use_ns_bank(env) ? GICV3_NS : GICV3_S;
    uint64_t value;

    value = cs->icc_ctlr_el1[bank];
    trace_gicv3_icc_ctlr_read(gicv3_redist_affid(cs), value);
    return value;
}

static void icc_ctlr_el1_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int bank = gicv3_use_ns_bank(env) ? GICV3_NS : GICV3_S;
    uint64_t mask;

    trace_gicv3_icc_ctlr_write(gicv3_redist_affid(cs), value);

    /* Only CBPR and EOIMODE can be RW;
     * for us PMHE is RAZ/WI (we don't implement 1-of-N interrupts or
     * the asseciated priority-based routing of them);
     * if EL3 is implemented and GICD_CTLR.DS == 0, then PMHE and CBPR are RO.
     */
    if (arm_feature(env, ARM_FEATURE_EL3) &&
        ((cs->gic->gicd_ctlr & GICD_CTLR_DS) == 0)) {
        mask = ICC_CTLR_EL1_EOIMODE;
    } else {
        mask = ICC_CTLR_EL1_CBPR | ICC_CTLR_EL1_EOIMODE;
    }

    cs->icc_ctlr_el1[bank] &= ~mask;
    cs->icc_ctlr_el1[bank] |= (value & mask);
    gicv3_cpuif_update(cs);
}


static uint64_t icc_ctlr_el3_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint64_t value;

    value = cs->icc_ctlr_el3;
    if (cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_EOIMODE) {
        value |= ICC_CTLR_EL3_EOIMODE_EL1NS;
    }
    if (cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_CBPR) {
        value |= ICC_CTLR_EL3_CBPR_EL1NS;
    }
    if (cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_EOIMODE) {
        value |= ICC_CTLR_EL3_EOIMODE_EL1S;
    }
    if (cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_CBPR) {
        value |= ICC_CTLR_EL3_CBPR_EL1S;
    }

    trace_gicv3_icc_ctlr_el3_read(gicv3_redist_affid(cs), value);
    return value;
}

static void icc_ctlr_el3_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint64_t mask;

    trace_gicv3_icc_ctlr_el3_write(gicv3_redist_affid(cs), value);

    /* *_EL1NS and *_EL1S bits are aliases into the ICC_CTLR_EL1 bits. */
    cs->icc_ctlr_el1[GICV3_NS] &= (ICC_CTLR_EL1_CBPR | ICC_CTLR_EL1_EOIMODE);
    if (value & ICC_CTLR_EL3_EOIMODE_EL1NS) {
        cs->icc_ctlr_el1[GICV3_NS] |= ICC_CTLR_EL1_EOIMODE;
    }
    if (value & ICC_CTLR_EL3_CBPR_EL1NS) {
        cs->icc_ctlr_el1[GICV3_NS] |= ICC_CTLR_EL1_CBPR;
    }

    cs->icc_ctlr_el1[GICV3_S] &= (ICC_CTLR_EL1_CBPR | ICC_CTLR_EL1_EOIMODE);
    if (value & ICC_CTLR_EL3_EOIMODE_EL1S) {
        cs->icc_ctlr_el1[GICV3_S] |= ICC_CTLR_EL1_EOIMODE;
    }
    if (value & ICC_CTLR_EL3_CBPR_EL1S) {
        cs->icc_ctlr_el1[GICV3_S] |= ICC_CTLR_EL1_CBPR;
    }

    /* The only bit stored in icc_ctlr_el3 which is writeable is EOIMODE_EL3: */
    mask = ICC_CTLR_EL3_EOIMODE_EL3;

    cs->icc_ctlr_el3 &= ~mask;
    cs->icc_ctlr_el3 |= (value & mask);
    gicv3_cpuif_update(cs);
}

static CPAccessResult gicv3_irqfiq_access(CPUARMState *env,
                                          const ARMCPRegInfo *ri, bool isread)
{
    CPAccessResult r = CP_ACCESS_OK;

    if ((env->cp15.scr_el3 & (SCR_FIQ | SCR_IRQ)) == (SCR_FIQ | SCR_IRQ)) {
        switch (arm_current_el(env)) {
        case 1:
            if (arm_is_secure_below_el3(env) ||
                ((env->cp15.hcr_el2 & (HCR_IMO | HCR_FMO)) == 0)) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        case 2:
            r = CP_ACCESS_TRAP_EL3;
            break;
        case 3:
            if (!is_a64(env) && !arm_is_el3_or_mon(env)) {
                r = CP_ACCESS_TRAP_EL3;
            }
        default:
            g_assert_not_reached();
        }
    }

    if (r == CP_ACCESS_TRAP_EL3 && !arm_el_is_aa64(env, 3)) {
        r = CP_ACCESS_TRAP;
    }
    return r;
}

static CPAccessResult gicv3_fiq_access(CPUARMState *env,
                                       const ARMCPRegInfo *ri, bool isread)
{
    CPAccessResult r = CP_ACCESS_OK;

    if (env->cp15.scr_el3 & SCR_FIQ) {
        switch (arm_current_el(env)) {
        case 1:
            if (arm_is_secure_below_el3(env) ||
                ((env->cp15.hcr_el2 & HCR_FMO) == 0)) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        case 2:
            r = CP_ACCESS_TRAP_EL3;
            break;
        case 3:
            if (!is_a64(env) && !arm_is_el3_or_mon(env)) {
                r = CP_ACCESS_TRAP_EL3;
            }
        default:
            g_assert_not_reached();
        }
    }

    if (r == CP_ACCESS_TRAP_EL3 && !arm_el_is_aa64(env, 3)) {
        r = CP_ACCESS_TRAP;
    }
    return r;
}

static CPAccessResult gicv3_irq_access(CPUARMState *env,
                                       const ARMCPRegInfo *ri, bool isread)
{
    CPAccessResult r = CP_ACCESS_OK;

    if (env->cp15.scr_el3 & SCR_IRQ) {
        switch (arm_current_el(env)) {
        case 1:
            if (arm_is_secure_below_el3(env) ||
                ((env->cp15.hcr_el2 & HCR_IMO) == 0)) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        case 2:
            r = CP_ACCESS_TRAP_EL3;
            break;
        case 3:
            if (!is_a64(env) && !arm_is_el3_or_mon(env)) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        default:
            g_assert_not_reached();
        }
    }

    if (r == CP_ACCESS_TRAP_EL3 && !arm_el_is_aa64(env, 3)) {
        r = CP_ACCESS_TRAP;
    }
    return r;
}

static void icc_reset(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);

    cs->icc_ctlr_el1[GICV3_S] = ICC_CTLR_EL1_A3V |
        (1 << ICC_CTLR_EL1_IDBITS_SHIFT) |
        (7 << ICC_CTLR_EL1_PRIBITS_SHIFT);
    cs->icc_ctlr_el1[GICV3_NS] = ICC_CTLR_EL1_A3V |
        (1 << ICC_CTLR_EL1_IDBITS_SHIFT) |
        (7 << ICC_CTLR_EL1_PRIBITS_SHIFT);
    cs->icc_pmr_el1 = 0;
    cs->icc_bpr[GICV3_G0] = GIC_MIN_BPR;
    cs->icc_bpr[GICV3_G1] = GIC_MIN_BPR;
    if (arm_feature(env, ARM_FEATURE_EL3)) {
        cs->icc_bpr[GICV3_G1NS] = GIC_MIN_BPR_NS;
    } else {
        cs->icc_bpr[GICV3_G1NS] = GIC_MIN_BPR;
    }
    memset(cs->icc_apr, 0, sizeof(cs->icc_apr));
    memset(cs->icc_igrpen, 0, sizeof(cs->icc_igrpen));
    cs->icc_ctlr_el3 = ICC_CTLR_EL3_NDS | ICC_CTLR_EL3_A3V |
        (1 << ICC_CTLR_EL3_IDBITS_SHIFT) |
        (7 << ICC_CTLR_EL3_PRIBITS_SHIFT);
}

static const ARMCPRegInfo gicv3_cpuif_reginfo[] = {
    { .name = "ICC_PMR_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 4, .crm = 6, .opc2 = 0,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irqfiq_access,
      .readfn = icc_pmr_read,
      .writefn = icc_pmr_write,
      /* We hang the whole cpu interface reset routine off here
       * rather than parcelling it out into one little function
       * per register
       */
      .resetfn = icc_reset,
    },
    { .name = "ICC_BPR0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 3,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_fiq_access,
      .fieldoffset = offsetof(GICv3CPUState, icc_bpr[GICV3_G0]),
      .writefn = icc_bpr_write,
    },
    { .name = "ICC_AP0R0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 4,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_fiq_access,
      .fieldoffset = offsetof(GICv3CPUState, icc_apr[GICV3_G0][0]),
      .writefn = icc_ap_write,
    },
    { .name = "ICC_AP0R1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 5,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_fiq_access,
      .fieldoffset = offsetof(GICv3CPUState, icc_apr[GICV3_G0][1]),
      .writefn = icc_ap_write,
    },
    { .name = "ICC_AP0R2_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 6,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_fiq_access,
      .fieldoffset = offsetof(GICv3CPUState, icc_apr[GICV3_G0][2]),
      .writefn = icc_ap_write,
    },
    { .name = "ICC_AP0R3_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 7,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_fiq_access,
      .fieldoffset = offsetof(GICv3CPUState, icc_apr[GICV3_G0][3]),
      .writefn = icc_ap_write,
    },
    /* All the ICC_AP1R*_EL1 registers are banked */
    { .name = "ICC_AP1R0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 9, .opc2 = 0,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irq_access,
      .readfn = icc_ap_read,
      .writefn = icc_ap_write,
    },
    { .name = "ICC_AP1R1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 9, .opc2 = 1,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irq_access,
      .readfn = icc_ap_read,
      .writefn = icc_ap_write,
    },
    { .name = "ICC_AP1R2_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 9, .opc2 = 2,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irq_access,
      .readfn = icc_ap_read,
      .writefn = icc_ap_write,
    },
    { .name = "ICC_AP1R3_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 9, .opc2 = 3,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irq_access,
      .readfn = icc_ap_read,
      .writefn = icc_ap_write,
    },
    /* This register is banked */
    { .name = "ICC_BPR1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 3,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irq_access,
      .readfn = icc_bpr_read,
      .writefn = icc_bpr_write,
    },
    /* This register is banked */
    { .name = "ICC_CTLR_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 4,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irqfiq_access,
      .readfn = icc_ctlr_el1_read,
      .writefn = icc_ctlr_el1_write,
    },
    { .name = "ICC_SRE_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 5,
      .type = ARM_CP_NO_RAW | ARM_CP_CONST,
      .access = PL1_RW,
      /* We don't support IRQ/FIQ bypass and system registers are
       * always enabled, so all our bits are RAZ/WI or RAO/WI.
       * This register is banked but since it's constant we don't
       * need to do anything special.
       */
      .resetvalue = 0x7,
    },
    { .name = "ICC_IGRPEN0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 6,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_fiq_access,
      .fieldoffset = offsetof(GICv3CPUState, icc_igrpen[GICV3_G0]),
      .writefn = icc_igrpen_write,
    },
    /* This register is banked */
    { .name = "ICC_IGRPEN1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 7,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irq_access,
      .readfn = icc_igrpen_read,
      .writefn = icc_igrpen_write,
    },
    { .name = "ICC_SRE_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 12, .crm = 9, .opc2 = 5,
      .type = ARM_CP_NO_RAW | ARM_CP_CONST,
      .access = PL2_RW,
      /* We don't support IRQ/FIQ bypass and system registers are
       * always enabled, so all our bits are RAZ/WI or RAO/WI.
       */
      .resetvalue = 0xf,
    },
    { .name = "ICC_CTLR_EL3", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 6, .crn = 12, .crm = 12, .opc2 = 4,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL3_RW,
      .fieldoffset = offsetof(GICv3CPUState, icc_ctlr_el3),
      .readfn = icc_ctlr_el3_read,
      .writefn = icc_ctlr_el3_write,
    },
    { .name = "ICC_SRE_EL3", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 6, .crn = 12, .crm = 12, .opc2 = 5,
      .type = ARM_CP_NO_RAW | ARM_CP_CONST,
      .access = PL3_RW,
      /* We don't support IRQ/FIQ bypass and system registers are
       * always enabled, so all our bits are RAZ/WI or RAO/WI.
       */
      .resetvalue = 0xf,
    },
    { .name = "ICC_IGRPEN1_EL3", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 6, .crn = 12, .crm = 12, .opc2 = 7,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL3_RW,
      .readfn = icc_igrpen1_el3_read,
      .writefn = icc_igrpen1_el3_write,
    },
    REGINFO_SENTINEL
};

static void gicv3_cpuif_el_change_hook(ARMCPU *cpu, void *opaque)
{
    /* Do nothing for now. */
}

void gicv3_init_cpuif(GICv3State *s)
{
    /* Called from the GICv3 realize function; register our system
     * registers with the CPU
     */
    int i;

    for (i = 0; i < s->num_cpu; i++) {
        ARMCPU *cpu = ARM_CPU(qemu_get_cpu(i));
        GICv3CPUState *cs = &s->cpu[i];

        /* Note that we can't just use the GICv3CPUState as an opaque pointer
         * in define_arm_cp_regs_with_opaque(), because when we're called back
         * it might be with code translated by CPU 0 but run by CPU 1, in
         * which case we'd get the wrong value.
         * So instead we define the regs with no ri->opaque info, and
         * get back to the GICv3CPUState from the ARMCPU by reading back
         * the opaque pointer from the el_change_hook, which we're going
         * to need to register anyway.
         */
        define_arm_cp_regs(cpu, gicv3_cpuif_reginfo);
        arm_register_el_change_hook(cpu, gicv3_cpuif_el_change_hook, cs);
    }
}
