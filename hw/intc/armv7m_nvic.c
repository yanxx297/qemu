/*
 * ARM Nested Vectored Interrupt Controller
 *
 * Copyright (c) 2006-2007 CodeSourcery.
 * Written by Paul Brook
 *
 * This code is licensed under the GPL.
 *
 * The ARMv7M System controller is fairly tightly tied in with the
 * NVIC.  Much of that is also implemented here.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/sysbus.h"
#include "qemu/timer.h"
#include "hw/arm/arm.h"
#include "hw/intc/armv7m_nvic.h"
#include "target/arm/cpu.h"
#include "exec/exec-all.h"
#include "qemu/log.h"
#include "trace.h"

/* IRQ number counting:
 *
 * the num-irq property counts the number of external IRQ lines
 *
 * NVICState::num_irq counts the total number of exceptions
 * (external IRQs, the 15 internal exceptions including reset,
 * and one for the unused exception number 0).
 *
 * NVIC_MAX_IRQ is the highest permitted number of external IRQ lines.
 *
 * NVIC_MAX_VECTORS is the highest permitted number of exceptions.
 *
 * Iterating through all exceptions should typically be done with
 * for (i = 1; i < s->num_irq; i++) to avoid the unused slot 0.
 *
 * The external qemu_irq lines are the NVIC's external IRQ lines,
 * so line 0 is exception 16.
 *
 * In the terminology of the architecture manual, "interrupts" are
 * a subcategory of exception referring to the external interrupts
 * (which are exception numbers NVIC_FIRST_IRQ and upward).
 * For historical reasons QEMU tends to use "interrupt" and
 * "exception" more or less interchangeably.
 */
#define NVIC_FIRST_IRQ NVIC_INTERNAL_VECTORS
#define NVIC_MAX_IRQ (NVIC_MAX_VECTORS - NVIC_FIRST_IRQ)

/* Effective running priority of the CPU when no exception is active
 * (higher than the highest possible priority value)
 */
#define NVIC_NOEXC_PRIO 0x100
/* Maximum priority of non-secure exceptions when AIRCR.PRIS is set */
#define NVIC_NS_PRIO_LIMIT 0x80

static const uint8_t nvic_id[] = {
    0x00, 0xb0, 0x1b, 0x00, 0x0d, 0xe0, 0x05, 0xb1
};

static int nvic_pending_prio(NVICState *s)
{
    /* return the group priority of the current pending interrupt,
     * or NVIC_NOEXC_PRIO if no interrupt is pending
     */
    return s->vectpending_prio;
}

/* Return the value of the ISCR RETTOBASE bit:
 * 1 if there is exactly one active exception
 * 0 if there is more than one active exception
 * UNKNOWN if there are no active exceptions (we choose 1,
 * which matches the choice Cortex-M3 is documented as making).
 *
 * NB: some versions of the documentation talk about this
 * counting "active exceptions other than the one shown by IPSR";
 * this is only different in the obscure corner case where guest
 * code has manually deactivated an exception and is about
 * to fail an exception-return integrity check. The definition
 * above is the one from the v8M ARM ARM and is also in line
 * with the behaviour documented for the Cortex-M3.
 */
static bool nvic_rettobase(NVICState *s)
{
    int irq, nhand = 0;
    bool check_sec = arm_feature(&s->cpu->env, ARM_FEATURE_M_SECURITY);

    for (irq = ARMV7M_EXCP_RESET; irq < s->num_irq; irq++) {
        if (s->vectors[irq].active ||
            (check_sec && irq < NVIC_INTERNAL_VECTORS &&
             s->sec_vectors[irq].active)) {
            nhand++;
            if (nhand == 2) {
                return 0;
            }
        }
    }

    return 1;
}

/* Return the value of the ISCR ISRPENDING bit:
 * 1 if an external interrupt is pending
 * 0 if no external interrupt is pending
 */
static bool nvic_isrpending(NVICState *s)
{
    int irq;

    /* We can shortcut if the highest priority pending interrupt
     * happens to be external or if there is nothing pending.
     */
    if (s->vectpending > NVIC_FIRST_IRQ) {
        return true;
    }
    if (s->vectpending == 0) {
        return false;
    }

    for (irq = NVIC_FIRST_IRQ; irq < s->num_irq; irq++) {
        if (s->vectors[irq].pending) {
            return true;
        }
    }
    return false;
}

static bool exc_is_banked(int exc)
{
    /* Return true if this is one of the limited set of exceptions which
     * are banked (and thus have state in sec_vectors[])
     */
    return exc == ARMV7M_EXCP_HARD ||
        exc == ARMV7M_EXCP_MEM ||
        exc == ARMV7M_EXCP_USAGE ||
        exc == ARMV7M_EXCP_SVC ||
        exc == ARMV7M_EXCP_PENDSV ||
        exc == ARMV7M_EXCP_SYSTICK;
}

/* Return a mask word which clears the subpriority bits from
 * a priority value for an M-profile exception, leaving only
 * the group priority.
 */
static inline uint32_t nvic_gprio_mask(NVICState *s, bool secure)
{
    return ~0U << (s->prigroup[secure] + 1);
}

static bool exc_targets_secure(NVICState *s, int exc)
{
    /* Return true if this non-banked exception targets Secure state. */
    if (!arm_feature(&s->cpu->env, ARM_FEATURE_M_SECURITY)) {
        return false;
    }

    if (exc >= NVIC_FIRST_IRQ) {
        return !s->itns[exc];
    }

    /* Function shouldn't be called for banked exceptions. */
    assert(!exc_is_banked(exc));

    switch (exc) {
    case ARMV7M_EXCP_NMI:
    case ARMV7M_EXCP_BUS:
        return !(s->cpu->env.v7m.aircr & R_V7M_AIRCR_BFHFNMINS_MASK);
    case ARMV7M_EXCP_SECURE:
        return true;
    case ARMV7M_EXCP_DEBUG:
        /* TODO: controlled by DEMCR.SDME, which we don't yet implement */
        return false;
    default:
        /* reset, and reserved (unused) low exception numbers.
         * We'll get called by code that loops through all the exception
         * numbers, but it doesn't matter what we return here as these
         * non-existent exceptions will never be pended or active.
         */
        return true;
    }
}

static int exc_group_prio(NVICState *s, int rawprio, bool targets_secure)
{
    /* Return the group priority for this exception, given its raw
     * (group-and-subgroup) priority value and whether it is targeting
     * secure state or not.
     */
    if (rawprio < 0) {
        return rawprio;
    }
    rawprio &= nvic_gprio_mask(s, targets_secure);
    /* AIRCR.PRIS causes us to squash all NS priorities into the
     * lower half of the total range
     */
    if (!targets_secure &&
        (s->cpu->env.v7m.aircr & R_V7M_AIRCR_PRIS_MASK)) {
        rawprio = (rawprio >> 1) + NVIC_NS_PRIO_LIMIT;
    }
    return rawprio;
}

/* Recompute vectpending and exception_prio for a CPU which implements
 * the Security extension
 */
static void nvic_recompute_state_secure(NVICState *s)
{
    int i, bank;
    int pend_prio = NVIC_NOEXC_PRIO;
    int active_prio = NVIC_NOEXC_PRIO;
    int pend_irq = 0;
    bool pending_is_s_banked = false;

    /* R_CQRV: precedence is by:
     *  - lowest group priority; if both the same then
     *  - lowest subpriority; if both the same then
     *  - lowest exception number; if both the same (ie banked) then
     *  - secure exception takes precedence
     * Compare pseudocode RawExecutionPriority.
     * Annoyingly, now we have two prigroup values (for S and NS)
     * we can't do the loop comparison on raw priority values.
     */
    for (i = 1; i < s->num_irq; i++) {
        for (bank = M_REG_S; bank >= M_REG_NS; bank--) {
            VecInfo *vec;
            int prio;
            bool targets_secure;

            if (bank == M_REG_S) {
                if (!exc_is_banked(i)) {
                    continue;
                }
                vec = &s->sec_vectors[i];
                targets_secure = true;
            } else {
                vec = &s->vectors[i];
                targets_secure = !exc_is_banked(i) && exc_targets_secure(s, i);
            }

            prio = exc_group_prio(s, vec->prio, targets_secure);
            if (vec->enabled && vec->pending && prio < pend_prio) {
                pend_prio = prio;
                pend_irq = i;
                pending_is_s_banked = (bank == M_REG_S);
            }
            if (vec->active && prio < active_prio) {
                active_prio = prio;
            }
        }
    }

    s->vectpending_is_s_banked = pending_is_s_banked;
    s->vectpending = pend_irq;
    s->vectpending_prio = pend_prio;
    s->exception_prio = active_prio;

    trace_nvic_recompute_state_secure(s->vectpending,
                                      s->vectpending_is_s_banked,
                                      s->vectpending_prio,
                                      s->exception_prio);
}

/* Recompute vectpending and exception_prio */
static void nvic_recompute_state(NVICState *s)
{
    int i;
    int pend_prio = NVIC_NOEXC_PRIO;
    int active_prio = NVIC_NOEXC_PRIO;
    int pend_irq = 0;

    /* In theory we could write one function that handled both
     * the "security extension present" and "not present"; however
     * the security related changes significantly complicate the
     * recomputation just by themselves and mixing both cases together
     * would be even worse, so we retain a separate non-secure-only
     * version for CPUs which don't implement the security extension.
     */
    if (arm_feature(&s->cpu->env, ARM_FEATURE_M_SECURITY)) {
        nvic_recompute_state_secure(s);
        return;
    }

    for (i = 1; i < s->num_irq; i++) {
        VecInfo *vec = &s->vectors[i];

        if (vec->enabled && vec->pending && vec->prio < pend_prio) {
            pend_prio = vec->prio;
            pend_irq = i;
        }
        if (vec->active && vec->prio < active_prio) {
            active_prio = vec->prio;
        }
    }

    if (active_prio > 0) {
        active_prio &= nvic_gprio_mask(s, false);
    }

    if (pend_prio > 0) {
        pend_prio &= nvic_gprio_mask(s, false);
    }

    s->vectpending = pend_irq;
    s->vectpending_prio = pend_prio;
    s->exception_prio = active_prio;

    trace_nvic_recompute_state(s->vectpending,
                               s->vectpending_prio,
                               s->exception_prio);
}

/* Return the current execution priority of the CPU
 * (equivalent to the pseudocode ExecutionPriority function).
 * This is a value between -2 (NMI priority) and NVIC_NOEXC_PRIO.
 */
static inline int nvic_exec_prio(NVICState *s)
{
    CPUARMState *env = &s->cpu->env;
    int running;

    if (env->v7m.faultmask[env->v7m.secure]) {
        running = -1;
    } else if (env->v7m.primask[env->v7m.secure]) {
        running = 0;
    } else if (env->v7m.basepri[env->v7m.secure] > 0) {
        running = env->v7m.basepri[env->v7m.secure] &
            nvic_gprio_mask(s, env->v7m.secure);
    } else {
        running = NVIC_NOEXC_PRIO; /* lower than any possible priority */
    }
    /* consider priority of active handler */
    return MIN(running, s->exception_prio);
}

bool armv7m_nvic_can_take_pending_exception(void *opaque)
{
    NVICState *s = opaque;

    return nvic_exec_prio(s) > nvic_pending_prio(s);
}

int armv7m_nvic_raw_execution_priority(void *opaque)
{
    NVICState *s = opaque;

    return s->exception_prio;
}

/* caller must call nvic_irq_update() after this.
 * secure indicates the bank to use for banked exceptions (we assert if
 * we are passed secure=true for a non-banked exception).
 */
static void set_prio(NVICState *s, unsigned irq, bool secure, uint8_t prio)
{
    assert(irq > ARMV7M_EXCP_NMI); /* only use for configurable prios */
    assert(irq < s->num_irq);

    if (secure) {
        assert(exc_is_banked(irq));
        s->sec_vectors[irq].prio = prio;
    } else {
        s->vectors[irq].prio = prio;
    }

    trace_nvic_set_prio(irq, secure, prio);
}

/* Return the current raw priority register value.
 * secure indicates the bank to use for banked exceptions (we assert if
 * we are passed secure=true for a non-banked exception).
 */
static int get_prio(NVICState *s, unsigned irq, bool secure)
{
    assert(irq > ARMV7M_EXCP_NMI); /* only use for configurable prios */
    assert(irq < s->num_irq);

    if (secure) {
        assert(exc_is_banked(irq));
        return s->sec_vectors[irq].prio;
    } else {
        return s->vectors[irq].prio;
    }
}

/* Recompute state and assert irq line accordingly.
 * Must be called after changes to:
 *  vec->active, vec->enabled, vec->pending or vec->prio for any vector
 *  prigroup
 */
static void nvic_irq_update(NVICState *s)
{
    int lvl;
    int pend_prio;

    nvic_recompute_state(s);
    pend_prio = nvic_pending_prio(s);

    /* Raise NVIC output if this IRQ would be taken, except that we
     * ignore the effects of the BASEPRI, FAULTMASK and PRIMASK (which
     * will be checked for in arm_v7m_cpu_exec_interrupt()); changes
     * to those CPU registers don't cause us to recalculate the NVIC
     * pending info.
     */
    lvl = (pend_prio < s->exception_prio);
    trace_nvic_irq_update(s->vectpending, pend_prio, s->exception_prio, lvl);
    qemu_set_irq(s->excpout, lvl);
}

/**
 * armv7m_nvic_clear_pending: mark the specified exception as not pending
 * @opaque: the NVIC
 * @irq: the exception number to mark as not pending
 * @secure: false for non-banked exceptions or for the nonsecure
 * version of a banked exception, true for the secure version of a banked
 * exception.
 *
 * Marks the specified exception as not pending. Note that we will assert()
 * if @secure is true and @irq does not specify one of the fixed set
 * of architecturally banked exceptions.
 */
static void armv7m_nvic_clear_pending(void *opaque, int irq, bool secure)
{
    NVICState *s = (NVICState *)opaque;
    VecInfo *vec;

    assert(irq > ARMV7M_EXCP_RESET && irq < s->num_irq);

    if (secure) {
        assert(exc_is_banked(irq));
        vec = &s->sec_vectors[irq];
    } else {
        vec = &s->vectors[irq];
    }
    trace_nvic_clear_pending(irq, secure, vec->enabled, vec->prio);
    if (vec->pending) {
        vec->pending = 0;
        nvic_irq_update(s);
    }
}

void armv7m_nvic_set_pending(void *opaque, int irq, bool secure)
{
    NVICState *s = (NVICState *)opaque;
    bool banked = exc_is_banked(irq);
    VecInfo *vec;

    assert(irq > ARMV7M_EXCP_RESET && irq < s->num_irq);
    assert(!secure || banked);

    vec = (banked && secure) ? &s->sec_vectors[irq] : &s->vectors[irq];

    trace_nvic_set_pending(irq, secure, vec->enabled, vec->prio);

    if (irq >= ARMV7M_EXCP_HARD && irq < ARMV7M_EXCP_PENDSV) {
        /* If a synchronous exception is pending then it may be
         * escalated to HardFault if:
         *  * it is equal or lower priority to current execution
         *  * it is disabled
         * (ie we need to take it immediately but we can't do so).
         * Asynchronous exceptions (and interrupts) simply remain pending.
         *
         * For QEMU, we don't have any imprecise (asynchronous) faults,
         * so we can assume that PREFETCH_ABORT and DATA_ABORT are always
         * synchronous.
         * Debug exceptions are awkward because only Debug exceptions
         * resulting from the BKPT instruction should be escalated,
         * but we don't currently implement any Debug exceptions other
         * than those that result from BKPT, so we treat all debug exceptions
         * as needing escalation.
         *
         * This all means we can identify whether to escalate based only on
         * the exception number and don't (yet) need the caller to explicitly
         * tell us whether this exception is synchronous or not.
         */
        int running = nvic_exec_prio(s);
        bool escalate = false;

        if (exc_group_prio(s, vec->prio, secure) >= running) {
            trace_nvic_escalate_prio(irq, vec->prio, running);
            escalate = true;
        } else if (!vec->enabled) {
            trace_nvic_escalate_disabled(irq);
            escalate = true;
        }

        if (escalate) {

            /* We need to escalate this exception to a synchronous HardFault.
             * If BFHFNMINS is set then we escalate to the banked HF for
             * the target security state of the original exception; otherwise
             * we take a Secure HardFault.
             */
            irq = ARMV7M_EXCP_HARD;
            if (arm_feature(&s->cpu->env, ARM_FEATURE_M_SECURITY) &&
                (secure ||
                 !(s->cpu->env.v7m.aircr & R_V7M_AIRCR_BFHFNMINS_MASK))) {
                vec = &s->sec_vectors[irq];
            } else {
                vec = &s->vectors[irq];
            }
            if (running <= vec->prio) {
                /* We want to escalate to HardFault but we can't take the
                 * synchronous HardFault at this point either. This is a
                 * Lockup condition due to a guest bug. We don't model
                 * Lockup, so report via cpu_abort() instead.
                 */
                cpu_abort(&s->cpu->parent_obj,
                          "Lockup: can't escalate %d to HardFault "
                          "(current priority %d)\n", irq, running);
            }

            /* HF may be banked but there is only one shared HFSR */
            s->cpu->env.v7m.hfsr |= R_V7M_HFSR_FORCED_MASK;
        }
    }

    if (!vec->pending) {
        vec->pending = 1;
        nvic_irq_update(s);
    }
}

/* Make pending IRQ active.  */
void armv7m_nvic_acknowledge_irq(void *opaque)
{
    NVICState *s = (NVICState *)opaque;
    CPUARMState *env = &s->cpu->env;
    const int pending = s->vectpending;
    const int running = nvic_exec_prio(s);
    VecInfo *vec;

    assert(pending > ARMV7M_EXCP_RESET && pending < s->num_irq);

    vec = &s->vectors[pending];

    assert(vec->enabled);
    assert(vec->pending);

    assert(s->vectpending_prio < running);

    trace_nvic_acknowledge_irq(pending, s->vectpending_prio);

    vec->active = 1;
    vec->pending = 0;

    env->v7m.exception = s->vectpending;

    nvic_irq_update(s);
}

int armv7m_nvic_complete_irq(void *opaque, int irq)
{
    NVICState *s = (NVICState *)opaque;
    VecInfo *vec;
    int ret;

    assert(irq > ARMV7M_EXCP_RESET && irq < s->num_irq);

    vec = &s->vectors[irq];

    trace_nvic_complete_irq(irq);

    if (!vec->active) {
        /* Tell the caller this was an illegal exception return */
        return -1;
    }

    ret = nvic_rettobase(s);

    vec->active = 0;
    if (vec->level) {
        /* Re-pend the exception if it's still held high; only
         * happens for extenal IRQs
         */
        assert(irq >= NVIC_FIRST_IRQ);
        vec->pending = 1;
    }

    nvic_irq_update(s);

    return ret;
}

/* callback when external interrupt line is changed */
static void set_irq_level(void *opaque, int n, int level)
{
    NVICState *s = opaque;
    VecInfo *vec;

    n += NVIC_FIRST_IRQ;

    assert(n >= NVIC_FIRST_IRQ && n < s->num_irq);

    trace_nvic_set_irq_level(n, level);

    /* The pending status of an external interrupt is
     * latched on rising edge and exception handler return.
     *
     * Pulsing the IRQ will always run the handler
     * once, and the handler will re-run until the
     * level is low when the handler completes.
     */
    vec = &s->vectors[n];
    if (level != vec->level) {
        vec->level = level;
        if (level) {
            armv7m_nvic_set_pending(s, n, false);
        }
    }
}

static uint32_t nvic_readl(NVICState *s, uint32_t offset, MemTxAttrs attrs)
{
    ARMCPU *cpu = s->cpu;
    uint32_t val;

    switch (offset) {
    case 4: /* Interrupt Control Type.  */
        return ((s->num_irq - NVIC_FIRST_IRQ) / 32) - 1;
    case 0x380 ... 0x3bf: /* NVIC_ITNS<n> */
    {
        int startvec = 32 * (offset - 0x380) + NVIC_FIRST_IRQ;
        int i;

        if (!arm_feature(&cpu->env, ARM_FEATURE_V8)) {
            goto bad_offset;
        }
        if (!attrs.secure) {
            return 0;
        }
        val = 0;
        for (i = 0; i < 32 && startvec + i < s->num_irq; i++) {
            if (s->itns[startvec + i]) {
                val |= (1 << i);
            }
        }
        return val;
    }
    case 0xd00: /* CPUID Base.  */
        return cpu->midr;
    case 0xd04: /* Interrupt Control State.  */
        /* VECTACTIVE */
        val = cpu->env.v7m.exception;
        /* VECTPENDING */
        val |= (s->vectpending & 0xff) << 12;
        /* ISRPENDING - set if any external IRQ is pending */
        if (nvic_isrpending(s)) {
            val |= (1 << 22);
        }
        /* RETTOBASE - set if only one handler is active */
        if (nvic_rettobase(s)) {
            val |= (1 << 11);
        }
        /* PENDSTSET */
        if (s->vectors[ARMV7M_EXCP_SYSTICK].pending) {
            val |= (1 << 26);
        }
        /* PENDSVSET */
        if (s->vectors[ARMV7M_EXCP_PENDSV].pending) {
            val |= (1 << 28);
        }
        /* NMIPENDSET */
        if (s->vectors[ARMV7M_EXCP_NMI].pending) {
            val |= (1 << 31);
        }
        /* ISRPREEMPT not implemented */
        return val;
    case 0xd08: /* Vector Table Offset.  */
        return cpu->env.v7m.vecbase[attrs.secure];
    case 0xd0c: /* Application Interrupt/Reset Control (AIRCR) */
        val = 0xfa050000 | (s->prigroup[attrs.secure] << 8);
        if (attrs.secure) {
            /* s->aircr stores PRIS, BFHFNMINS, SYSRESETREQS */
            val |= cpu->env.v7m.aircr;
        } else {
            if (arm_feature(&cpu->env, ARM_FEATURE_V8)) {
                /* BFHFNMINS is R/O from NS; other bits are RAZ/WI. If
                 * security isn't supported then BFHFNMINS is RAO (and
                 * the bit in env.v7m.aircr is always set).
                 */
                val |= cpu->env.v7m.aircr & R_V7M_AIRCR_BFHFNMINS_MASK;
            }
        }
        return val;
    case 0xd10: /* System Control.  */
        /* TODO: Implement SLEEPONEXIT.  */
        return 0;
    case 0xd14: /* Configuration Control.  */
        /* The BFHFNMIGN bit is the only non-banked bit; we
         * keep it in the non-secure copy of the register.
         */
        val = cpu->env.v7m.ccr[attrs.secure];
        val |= cpu->env.v7m.ccr[M_REG_NS] & R_V7M_CCR_BFHFNMIGN_MASK;
        return val;
    case 0xd24: /* System Handler Status.  */
        val = 0;
        if (s->vectors[ARMV7M_EXCP_MEM].active) {
            val |= (1 << 0);
        }
        if (s->vectors[ARMV7M_EXCP_BUS].active) {
            val |= (1 << 1);
        }
        if (s->vectors[ARMV7M_EXCP_USAGE].active) {
            val |= (1 << 3);
        }
        if (s->vectors[ARMV7M_EXCP_SVC].active) {
            val |= (1 << 7);
        }
        if (s->vectors[ARMV7M_EXCP_DEBUG].active) {
            val |= (1 << 8);
        }
        if (s->vectors[ARMV7M_EXCP_PENDSV].active) {
            val |= (1 << 10);
        }
        if (s->vectors[ARMV7M_EXCP_SYSTICK].active) {
            val |= (1 << 11);
        }
        if (s->vectors[ARMV7M_EXCP_USAGE].pending) {
            val |= (1 << 12);
        }
        if (s->vectors[ARMV7M_EXCP_MEM].pending) {
            val |= (1 << 13);
        }
        if (s->vectors[ARMV7M_EXCP_BUS].pending) {
            val |= (1 << 14);
        }
        if (s->vectors[ARMV7M_EXCP_SVC].pending) {
            val |= (1 << 15);
        }
        if (s->vectors[ARMV7M_EXCP_MEM].enabled) {
            val |= (1 << 16);
        }
        if (s->vectors[ARMV7M_EXCP_BUS].enabled) {
            val |= (1 << 17);
        }
        if (s->vectors[ARMV7M_EXCP_USAGE].enabled) {
            val |= (1 << 18);
        }
        return val;
    case 0xd28: /* Configurable Fault Status.  */
        /* The BFSR bits [15:8] are shared between security states
         * and we store them in the NS copy
         */
        val = cpu->env.v7m.cfsr[attrs.secure];
        val |= cpu->env.v7m.cfsr[M_REG_NS] & R_V7M_CFSR_BFSR_MASK;
        return val;
    case 0xd2c: /* Hard Fault Status.  */
        return cpu->env.v7m.hfsr;
    case 0xd30: /* Debug Fault Status.  */
        return cpu->env.v7m.dfsr;
    case 0xd34: /* MMFAR MemManage Fault Address */
        return cpu->env.v7m.mmfar[attrs.secure];
    case 0xd38: /* Bus Fault Address.  */
        return cpu->env.v7m.bfar;
    case 0xd3c: /* Aux Fault Status.  */
        /* TODO: Implement fault status registers.  */
        qemu_log_mask(LOG_UNIMP,
                      "Aux Fault status registers unimplemented\n");
        return 0;
    case 0xd40: /* PFR0.  */
        return 0x00000030;
    case 0xd44: /* PRF1.  */
        return 0x00000200;
    case 0xd48: /* DFR0.  */
        return 0x00100000;
    case 0xd4c: /* AFR0.  */
        return 0x00000000;
    case 0xd50: /* MMFR0.  */
        return 0x00000030;
    case 0xd54: /* MMFR1.  */
        return 0x00000000;
    case 0xd58: /* MMFR2.  */
        return 0x00000000;
    case 0xd5c: /* MMFR3.  */
        return 0x00000000;
    case 0xd60: /* ISAR0.  */
        return 0x01141110;
    case 0xd64: /* ISAR1.  */
        return 0x02111000;
    case 0xd68: /* ISAR2.  */
        return 0x21112231;
    case 0xd6c: /* ISAR3.  */
        return 0x01111110;
    case 0xd70: /* ISAR4.  */
        return 0x01310102;
    /* TODO: Implement debug registers.  */
    case 0xd90: /* MPU_TYPE */
        /* Unified MPU; if the MPU is not present this value is zero */
        return cpu->pmsav7_dregion << 8;
        break;
    case 0xd94: /* MPU_CTRL */
        return cpu->env.v7m.mpu_ctrl[attrs.secure];
    case 0xd98: /* MPU_RNR */
        return cpu->env.pmsav7.rnr[attrs.secure];
    case 0xd9c: /* MPU_RBAR */
    case 0xda4: /* MPU_RBAR_A1 */
    case 0xdac: /* MPU_RBAR_A2 */
    case 0xdb4: /* MPU_RBAR_A3 */
    {
        int region = cpu->env.pmsav7.rnr[attrs.secure];

        if (arm_feature(&cpu->env, ARM_FEATURE_V8)) {
            /* PMSAv8M handling of the aliases is different from v7M:
             * aliases A1, A2, A3 override the low two bits of the region
             * number in MPU_RNR, and there is no 'region' field in the
             * RBAR register.
             */
            int aliasno = (offset - 0xd9c) / 8; /* 0..3 */
            if (aliasno) {
                region = deposit32(region, 0, 2, aliasno);
            }
            if (region >= cpu->pmsav7_dregion) {
                return 0;
            }
            return cpu->env.pmsav8.rbar[attrs.secure][region];
        }

        if (region >= cpu->pmsav7_dregion) {
            return 0;
        }
        return (cpu->env.pmsav7.drbar[region] & 0x1f) | (region & 0xf);
    }
    case 0xda0: /* MPU_RASR (v7M), MPU_RLAR (v8M) */
    case 0xda8: /* MPU_RASR_A1 (v7M), MPU_RLAR_A1 (v8M) */
    case 0xdb0: /* MPU_RASR_A2 (v7M), MPU_RLAR_A2 (v8M) */
    case 0xdb8: /* MPU_RASR_A3 (v7M), MPU_RLAR_A3 (v8M) */
    {
        int region = cpu->env.pmsav7.rnr[attrs.secure];

        if (arm_feature(&cpu->env, ARM_FEATURE_V8)) {
            /* PMSAv8M handling of the aliases is different from v7M:
             * aliases A1, A2, A3 override the low two bits of the region
             * number in MPU_RNR.
             */
            int aliasno = (offset - 0xda0) / 8; /* 0..3 */
            if (aliasno) {
                region = deposit32(region, 0, 2, aliasno);
            }
            if (region >= cpu->pmsav7_dregion) {
                return 0;
            }
            return cpu->env.pmsav8.rlar[attrs.secure][region];
        }

        if (region >= cpu->pmsav7_dregion) {
            return 0;
        }
        return ((cpu->env.pmsav7.dracr[region] & 0xffff) << 16) |
            (cpu->env.pmsav7.drsr[region] & 0xffff);
    }
    case 0xdc0: /* MPU_MAIR0 */
        if (!arm_feature(&cpu->env, ARM_FEATURE_V8)) {
            goto bad_offset;
        }
        return cpu->env.pmsav8.mair0[attrs.secure];
    case 0xdc4: /* MPU_MAIR1 */
        if (!arm_feature(&cpu->env, ARM_FEATURE_V8)) {
            goto bad_offset;
        }
        return cpu->env.pmsav8.mair1[attrs.secure];
    default:
    bad_offset:
        qemu_log_mask(LOG_GUEST_ERROR, "NVIC: Bad read offset 0x%x\n", offset);
        return 0;
    }
}

static void nvic_writel(NVICState *s, uint32_t offset, uint32_t value,
                        MemTxAttrs attrs)
{
    ARMCPU *cpu = s->cpu;

    switch (offset) {
    case 0x380 ... 0x3bf: /* NVIC_ITNS<n> */
    {
        int startvec = 32 * (offset - 0x380) + NVIC_FIRST_IRQ;
        int i;

        if (!arm_feature(&cpu->env, ARM_FEATURE_V8)) {
            goto bad_offset;
        }
        if (!attrs.secure) {
            break;
        }
        for (i = 0; i < 32 && startvec + i < s->num_irq; i++) {
            s->itns[startvec + i] = (value >> i) & 1;
        }
        nvic_irq_update(s);
        break;
    }
    case 0xd04: /* Interrupt Control State.  */
        if (value & (1 << 31)) {
            armv7m_nvic_set_pending(s, ARMV7M_EXCP_NMI, false);
        }
        if (value & (1 << 28)) {
            armv7m_nvic_set_pending(s, ARMV7M_EXCP_PENDSV, attrs.secure);
        } else if (value & (1 << 27)) {
            armv7m_nvic_clear_pending(s, ARMV7M_EXCP_PENDSV, attrs.secure);
        }
        if (value & (1 << 26)) {
            armv7m_nvic_set_pending(s, ARMV7M_EXCP_SYSTICK, attrs.secure);
        } else if (value & (1 << 25)) {
            armv7m_nvic_clear_pending(s, ARMV7M_EXCP_SYSTICK, attrs.secure);
        }
        break;
    case 0xd08: /* Vector Table Offset.  */
        cpu->env.v7m.vecbase[attrs.secure] = value & 0xffffff80;
        break;
    case 0xd0c: /* Application Interrupt/Reset Control (AIRCR) */
        if ((value >> R_V7M_AIRCR_VECTKEY_SHIFT) == 0x05fa) {
            if (value & R_V7M_AIRCR_SYSRESETREQ_MASK) {
                if (attrs.secure ||
                    !(cpu->env.v7m.aircr & R_V7M_AIRCR_SYSRESETREQS_MASK)) {
                    qemu_irq_pulse(s->sysresetreq);
                }
            }
            if (value & R_V7M_AIRCR_VECTCLRACTIVE_MASK) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "Setting VECTCLRACTIVE when not in DEBUG mode "
                              "is UNPREDICTABLE\n");
            }
            if (value & R_V7M_AIRCR_VECTRESET_MASK) {
                /* NB: this bit is RES0 in v8M */
                qemu_log_mask(LOG_GUEST_ERROR,
                              "Setting VECTRESET when not in DEBUG mode "
                              "is UNPREDICTABLE\n");
            }
            s->prigroup[attrs.secure] = extract32(value,
                                                  R_V7M_AIRCR_PRIGROUP_SHIFT,
                                                  R_V7M_AIRCR_PRIGROUP_LENGTH);
            if (attrs.secure) {
                /* These bits are only writable by secure */
                cpu->env.v7m.aircr = value &
                    (R_V7M_AIRCR_SYSRESETREQS_MASK |
                     R_V7M_AIRCR_BFHFNMINS_MASK |
                     R_V7M_AIRCR_PRIS_MASK);
                /* BFHFNMINS changes the priority of Secure HardFault, and
                 * allows a pending Non-secure HardFault to preempt (which
                 * we implement by marking it enabled).
                 */
                if (cpu->env.v7m.aircr & R_V7M_AIRCR_BFHFNMINS_MASK) {
                    s->sec_vectors[ARMV7M_EXCP_HARD].prio = -3;
                    s->vectors[ARMV7M_EXCP_HARD].enabled = 1;
                } else {
                    s->sec_vectors[ARMV7M_EXCP_HARD].prio = -1;
                    s->vectors[ARMV7M_EXCP_HARD].enabled = 0;
                }
            }
            nvic_irq_update(s);
        }
        break;
    case 0xd10: /* System Control.  */
        /* TODO: Implement control registers.  */
        qemu_log_mask(LOG_UNIMP, "NVIC: SCR unimplemented\n");
        break;
    case 0xd14: /* Configuration Control.  */
        /* Enforce RAZ/WI on reserved and must-RAZ/WI bits */
        value &= (R_V7M_CCR_STKALIGN_MASK |
                  R_V7M_CCR_BFHFNMIGN_MASK |
                  R_V7M_CCR_DIV_0_TRP_MASK |
                  R_V7M_CCR_UNALIGN_TRP_MASK |
                  R_V7M_CCR_USERSETMPEND_MASK |
                  R_V7M_CCR_NONBASETHRDENA_MASK);

        if (arm_feature(&cpu->env, ARM_FEATURE_V8)) {
            /* v8M makes NONBASETHRDENA and STKALIGN be RES1 */
            value |= R_V7M_CCR_NONBASETHRDENA_MASK
                | R_V7M_CCR_STKALIGN_MASK;
        }
        if (attrs.secure) {
            /* the BFHFNMIGN bit is not banked; keep that in the NS copy */
            cpu->env.v7m.ccr[M_REG_NS] =
                (cpu->env.v7m.ccr[M_REG_NS] & ~R_V7M_CCR_BFHFNMIGN_MASK)
                | (value & R_V7M_CCR_BFHFNMIGN_MASK);
            value &= ~R_V7M_CCR_BFHFNMIGN_MASK;
        }

        cpu->env.v7m.ccr[attrs.secure] = value;
        break;
    case 0xd24: /* System Handler Control.  */
        s->vectors[ARMV7M_EXCP_MEM].active = (value & (1 << 0)) != 0;
        s->vectors[ARMV7M_EXCP_BUS].active = (value & (1 << 1)) != 0;
        s->vectors[ARMV7M_EXCP_USAGE].active = (value & (1 << 3)) != 0;
        s->vectors[ARMV7M_EXCP_SVC].active = (value & (1 << 7)) != 0;
        s->vectors[ARMV7M_EXCP_DEBUG].active = (value & (1 << 8)) != 0;
        s->vectors[ARMV7M_EXCP_PENDSV].active = (value & (1 << 10)) != 0;
        s->vectors[ARMV7M_EXCP_SYSTICK].active = (value & (1 << 11)) != 0;
        s->vectors[ARMV7M_EXCP_USAGE].pending = (value & (1 << 12)) != 0;
        s->vectors[ARMV7M_EXCP_MEM].pending = (value & (1 << 13)) != 0;
        s->vectors[ARMV7M_EXCP_BUS].pending = (value & (1 << 14)) != 0;
        s->vectors[ARMV7M_EXCP_SVC].pending = (value & (1 << 15)) != 0;
        s->vectors[ARMV7M_EXCP_MEM].enabled = (value & (1 << 16)) != 0;
        s->vectors[ARMV7M_EXCP_BUS].enabled = (value & (1 << 17)) != 0;
        s->vectors[ARMV7M_EXCP_USAGE].enabled = (value & (1 << 18)) != 0;
        nvic_irq_update(s);
        break;
    case 0xd28: /* Configurable Fault Status.  */
        cpu->env.v7m.cfsr[attrs.secure] &= ~value; /* W1C */
        if (attrs.secure) {
            /* The BFSR bits [15:8] are shared between security states
             * and we store them in the NS copy.
             */
            cpu->env.v7m.cfsr[M_REG_NS] &= ~(value & R_V7M_CFSR_BFSR_MASK);
        }
        break;
    case 0xd2c: /* Hard Fault Status.  */
        cpu->env.v7m.hfsr &= ~value; /* W1C */
        break;
    case 0xd30: /* Debug Fault Status.  */
        cpu->env.v7m.dfsr &= ~value; /* W1C */
        break;
    case 0xd34: /* Mem Manage Address.  */
        cpu->env.v7m.mmfar[attrs.secure] = value;
        return;
    case 0xd38: /* Bus Fault Address.  */
        cpu->env.v7m.bfar = value;
        return;
    case 0xd3c: /* Aux Fault Status.  */
        qemu_log_mask(LOG_UNIMP,
                      "NVIC: Aux fault status registers unimplemented\n");
        break;
    case 0xd90: /* MPU_TYPE */
        return; /* RO */
    case 0xd94: /* MPU_CTRL */
        if ((value &
             (R_V7M_MPU_CTRL_HFNMIENA_MASK | R_V7M_MPU_CTRL_ENABLE_MASK))
            == R_V7M_MPU_CTRL_HFNMIENA_MASK) {
            qemu_log_mask(LOG_GUEST_ERROR, "MPU_CTRL: HFNMIENA and !ENABLE is "
                          "UNPREDICTABLE\n");
        }
        cpu->env.v7m.mpu_ctrl[attrs.secure]
            = value & (R_V7M_MPU_CTRL_ENABLE_MASK |
                       R_V7M_MPU_CTRL_HFNMIENA_MASK |
                       R_V7M_MPU_CTRL_PRIVDEFENA_MASK);
        tlb_flush(CPU(cpu));
        break;
    case 0xd98: /* MPU_RNR */
        if (value >= cpu->pmsav7_dregion) {
            qemu_log_mask(LOG_GUEST_ERROR, "MPU region out of range %"
                          PRIu32 "/%" PRIu32 "\n",
                          value, cpu->pmsav7_dregion);
        } else {
            cpu->env.pmsav7.rnr[attrs.secure] = value;
        }
        break;
    case 0xd9c: /* MPU_RBAR */
    case 0xda4: /* MPU_RBAR_A1 */
    case 0xdac: /* MPU_RBAR_A2 */
    case 0xdb4: /* MPU_RBAR_A3 */
    {
        int region;

        if (arm_feature(&cpu->env, ARM_FEATURE_V8)) {
            /* PMSAv8M handling of the aliases is different from v7M:
             * aliases A1, A2, A3 override the low two bits of the region
             * number in MPU_RNR, and there is no 'region' field in the
             * RBAR register.
             */
            int aliasno = (offset - 0xd9c) / 8; /* 0..3 */

            region = cpu->env.pmsav7.rnr[attrs.secure];
            if (aliasno) {
                region = deposit32(region, 0, 2, aliasno);
            }
            if (region >= cpu->pmsav7_dregion) {
                return;
            }
            cpu->env.pmsav8.rbar[attrs.secure][region] = value;
            tlb_flush(CPU(cpu));
            return;
        }

        if (value & (1 << 4)) {
            /* VALID bit means use the region number specified in this
             * value and also update MPU_RNR.REGION with that value.
             */
            region = extract32(value, 0, 4);
            if (region >= cpu->pmsav7_dregion) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "MPU region out of range %u/%" PRIu32 "\n",
                              region, cpu->pmsav7_dregion);
                return;
            }
            cpu->env.pmsav7.rnr[attrs.secure] = region;
        } else {
            region = cpu->env.pmsav7.rnr[attrs.secure];
        }

        if (region >= cpu->pmsav7_dregion) {
            return;
        }

        cpu->env.pmsav7.drbar[region] = value & ~0x1f;
        tlb_flush(CPU(cpu));
        break;
    }
    case 0xda0: /* MPU_RASR (v7M), MPU_RLAR (v8M) */
    case 0xda8: /* MPU_RASR_A1 (v7M), MPU_RLAR_A1 (v8M) */
    case 0xdb0: /* MPU_RASR_A2 (v7M), MPU_RLAR_A2 (v8M) */
    case 0xdb8: /* MPU_RASR_A3 (v7M), MPU_RLAR_A3 (v8M) */
    {
        int region = cpu->env.pmsav7.rnr[attrs.secure];

        if (arm_feature(&cpu->env, ARM_FEATURE_V8)) {
            /* PMSAv8M handling of the aliases is different from v7M:
             * aliases A1, A2, A3 override the low two bits of the region
             * number in MPU_RNR.
             */
            int aliasno = (offset - 0xd9c) / 8; /* 0..3 */

            region = cpu->env.pmsav7.rnr[attrs.secure];
            if (aliasno) {
                region = deposit32(region, 0, 2, aliasno);
            }
            if (region >= cpu->pmsav7_dregion) {
                return;
            }
            cpu->env.pmsav8.rlar[attrs.secure][region] = value;
            tlb_flush(CPU(cpu));
            return;
        }

        if (region >= cpu->pmsav7_dregion) {
            return;
        }

        cpu->env.pmsav7.drsr[region] = value & 0xff3f;
        cpu->env.pmsav7.dracr[region] = (value >> 16) & 0x173f;
        tlb_flush(CPU(cpu));
        break;
    }
    case 0xdc0: /* MPU_MAIR0 */
        if (!arm_feature(&cpu->env, ARM_FEATURE_V8)) {
            goto bad_offset;
        }
        if (cpu->pmsav7_dregion) {
            /* Register is RES0 if no MPU regions are implemented */
            cpu->env.pmsav8.mair0[attrs.secure] = value;
        }
        /* We don't need to do anything else because memory attributes
         * only affect cacheability, and we don't implement caching.
         */
        break;
    case 0xdc4: /* MPU_MAIR1 */
        if (!arm_feature(&cpu->env, ARM_FEATURE_V8)) {
            goto bad_offset;
        }
        if (cpu->pmsav7_dregion) {
            /* Register is RES0 if no MPU regions are implemented */
            cpu->env.pmsav8.mair1[attrs.secure] = value;
        }
        /* We don't need to do anything else because memory attributes
         * only affect cacheability, and we don't implement caching.
         */
        break;
    case 0xf00: /* Software Triggered Interrupt Register */
    {
        int excnum = (value & 0x1ff) + NVIC_FIRST_IRQ;
        if (excnum < s->num_irq) {
            armv7m_nvic_set_pending(s, excnum, false);
        }
        break;
    }
    default:
    bad_offset:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "NVIC: Bad write offset 0x%x\n", offset);
    }
}

static bool nvic_user_access_ok(NVICState *s, hwaddr offset, MemTxAttrs attrs)
{
    /* Return true if unprivileged access to this register is permitted. */
    switch (offset) {
    case 0xf00: /* STIR: accessible only if CCR.USERSETMPEND permits */
        /* For access via STIR_NS it is the NS CCR.USERSETMPEND that
         * controls access even though the CPU is in Secure state (I_QDKX).
         */
        return s->cpu->env.v7m.ccr[attrs.secure] & R_V7M_CCR_USERSETMPEND_MASK;
    default:
        /* All other user accesses cause a BusFault unconditionally */
        return false;
    }
}

static int shpr_bank(NVICState *s, int exc, MemTxAttrs attrs)
{
    /* Behaviour for the SHPR register field for this exception:
     * return M_REG_NS to use the nonsecure vector (including for
     * non-banked exceptions), M_REG_S for the secure version of
     * a banked exception, and -1 if this field should RAZ/WI.
     */
    switch (exc) {
    case ARMV7M_EXCP_MEM:
    case ARMV7M_EXCP_USAGE:
    case ARMV7M_EXCP_SVC:
    case ARMV7M_EXCP_PENDSV:
    case ARMV7M_EXCP_SYSTICK:
        /* Banked exceptions */
        return attrs.secure;
    case ARMV7M_EXCP_BUS:
        /* Not banked, RAZ/WI from nonsecure if BFHFNMINS is zero */
        if (!attrs.secure &&
            !(s->cpu->env.v7m.aircr & R_V7M_AIRCR_BFHFNMINS_MASK)) {
            return -1;
        }
        return M_REG_NS;
    case ARMV7M_EXCP_SECURE:
        /* Not banked, RAZ/WI from nonsecure */
        if (!attrs.secure) {
            return -1;
        }
        return M_REG_NS;
    case ARMV7M_EXCP_DEBUG:
        /* Not banked. TODO should RAZ/WI if DEMCR.SDME is set */
        return M_REG_NS;
    case 8 ... 10:
    case 13:
        /* RES0 */
        return -1;
    default:
        /* Not reachable due to decode of SHPR register addresses */
        g_assert_not_reached();
    }
}

static MemTxResult nvic_sysreg_read(void *opaque, hwaddr addr,
                                    uint64_t *data, unsigned size,
                                    MemTxAttrs attrs)
{
    NVICState *s = (NVICState *)opaque;
    uint32_t offset = addr;
    unsigned i, startvec, end;
    uint32_t val;

    if (attrs.user && !nvic_user_access_ok(s, addr, attrs)) {
        /* Generate BusFault for unprivileged accesses */
        return MEMTX_ERROR;
    }

    switch (offset) {
    /* reads of set and clear both return the status */
    case 0x100 ... 0x13f: /* NVIC Set enable */
        offset += 0x80;
        /* fall through */
    case 0x180 ... 0x1bf: /* NVIC Clear enable */
        val = 0;
        startvec = offset - 0x180 + NVIC_FIRST_IRQ; /* vector # */

        for (i = 0, end = size * 8; i < end && startvec + i < s->num_irq; i++) {
            if (s->vectors[startvec + i].enabled &&
                (attrs.secure || s->itns[startvec + i])) {
                val |= (1 << i);
            }
        }
        break;
    case 0x200 ... 0x23f: /* NVIC Set pend */
        offset += 0x80;
        /* fall through */
    case 0x280 ... 0x2bf: /* NVIC Clear pend */
        val = 0;
        startvec = offset - 0x280 + NVIC_FIRST_IRQ; /* vector # */
        for (i = 0, end = size * 8; i < end && startvec + i < s->num_irq; i++) {
            if (s->vectors[startvec + i].pending &&
                (attrs.secure || s->itns[startvec + i])) {
                val |= (1 << i);
            }
        }
        break;
    case 0x300 ... 0x33f: /* NVIC Active */
        val = 0;
        startvec = offset - 0x300 + NVIC_FIRST_IRQ; /* vector # */

        for (i = 0, end = size * 8; i < end && startvec + i < s->num_irq; i++) {
            if (s->vectors[startvec + i].active &&
                (attrs.secure || s->itns[startvec + i])) {
                val |= (1 << i);
            }
        }
        break;
    case 0x400 ... 0x5ef: /* NVIC Priority */
        val = 0;
        startvec = offset - 0x400 + NVIC_FIRST_IRQ; /* vector # */

        for (i = 0; i < size && startvec + i < s->num_irq; i++) {
            if (attrs.secure || s->itns[startvec + i]) {
                val |= s->vectors[startvec + i].prio << (8 * i);
            }
        }
        break;
    case 0xd18 ... 0xd23: /* System Handler Priority (SHPR1, SHPR2, SHPR3) */
        val = 0;
        for (i = 0; i < size; i++) {
            unsigned hdlidx = (offset - 0xd14) + i;
            int sbank = shpr_bank(s, hdlidx, attrs);

            if (sbank < 0) {
                continue;
            }
            val = deposit32(val, i * 8, 8, get_prio(s, hdlidx, sbank));
        }
        break;
    case 0xfe0 ... 0xfff: /* ID.  */
        if (offset & 3) {
            val = 0;
        } else {
            val = nvic_id[(offset - 0xfe0) >> 2];
        }
        break;
    default:
        if (size == 4) {
            val = nvic_readl(s, offset, attrs);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "NVIC: Bad read of size %d at offset 0x%x\n",
                          size, offset);
            val = 0;
        }
    }

    trace_nvic_sysreg_read(addr, val, size);
    *data = val;
    return MEMTX_OK;
}

static MemTxResult nvic_sysreg_write(void *opaque, hwaddr addr,
                                     uint64_t value, unsigned size,
                                     MemTxAttrs attrs)
{
    NVICState *s = (NVICState *)opaque;
    uint32_t offset = addr;
    unsigned i, startvec, end;
    unsigned setval = 0;

    trace_nvic_sysreg_write(addr, value, size);

    if (attrs.user && !nvic_user_access_ok(s, addr, attrs)) {
        /* Generate BusFault for unprivileged accesses */
        return MEMTX_ERROR;
    }

    switch (offset) {
    case 0x100 ... 0x13f: /* NVIC Set enable */
        offset += 0x80;
        setval = 1;
        /* fall through */
    case 0x180 ... 0x1bf: /* NVIC Clear enable */
        startvec = 8 * (offset - 0x180) + NVIC_FIRST_IRQ;

        for (i = 0, end = size * 8; i < end && startvec + i < s->num_irq; i++) {
            if (value & (1 << i) &&
                (attrs.secure || s->itns[startvec + i])) {
                s->vectors[startvec + i].enabled = setval;
            }
        }
        nvic_irq_update(s);
        return MEMTX_OK;
    case 0x200 ... 0x23f: /* NVIC Set pend */
        /* the special logic in armv7m_nvic_set_pending()
         * is not needed since IRQs are never escalated
         */
        offset += 0x80;
        setval = 1;
        /* fall through */
    case 0x280 ... 0x2bf: /* NVIC Clear pend */
        startvec = 8 * (offset - 0x280) + NVIC_FIRST_IRQ; /* vector # */

        for (i = 0, end = size * 8; i < end && startvec + i < s->num_irq; i++) {
            if (value & (1 << i) &&
                (attrs.secure || s->itns[startvec + i])) {
                s->vectors[startvec + i].pending = setval;
            }
        }
        nvic_irq_update(s);
        return MEMTX_OK;
    case 0x300 ... 0x33f: /* NVIC Active */
        return MEMTX_OK; /* R/O */
    case 0x400 ... 0x5ef: /* NVIC Priority */
        startvec = 8 * (offset - 0x400) + NVIC_FIRST_IRQ; /* vector # */

        for (i = 0; i < size && startvec + i < s->num_irq; i++) {
            if (attrs.secure || s->itns[startvec + i]) {
                set_prio(s, startvec + i, false, (value >> (i * 8)) & 0xff);
            }
        }
        nvic_irq_update(s);
        return MEMTX_OK;
    case 0xd18 ... 0xd23: /* System Handler Priority (SHPR1, SHPR2, SHPR3) */
        for (i = 0; i < size; i++) {
            unsigned hdlidx = (offset - 0xd14) + i;
            int newprio = extract32(value, i * 8, 8);
            int sbank = shpr_bank(s, hdlidx, attrs);

            if (sbank < 0) {
                continue;
            }
            set_prio(s, hdlidx, sbank, newprio);
        }
        nvic_irq_update(s);
        return MEMTX_OK;
    }
    if (size == 4) {
        nvic_writel(s, offset, value, attrs);
        return MEMTX_OK;
    }
    qemu_log_mask(LOG_GUEST_ERROR,
                  "NVIC: Bad write of size %d at offset 0x%x\n", size, offset);
    /* This is UNPREDICTABLE; treat as RAZ/WI */
    return MEMTX_OK;
}

static const MemoryRegionOps nvic_sysreg_ops = {
    .read_with_attrs = nvic_sysreg_read,
    .write_with_attrs = nvic_sysreg_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static MemTxResult nvic_sysreg_ns_write(void *opaque, hwaddr addr,
                                        uint64_t value, unsigned size,
                                        MemTxAttrs attrs)
{
    if (attrs.secure) {
        /* S accesses to the alias act like NS accesses to the real region */
        attrs.secure = 0;
        return nvic_sysreg_write(opaque, addr, value, size, attrs);
    } else {
        /* NS attrs are RAZ/WI for privileged, and BusFault for user */
        if (attrs.user) {
            return MEMTX_ERROR;
        }
        return MEMTX_OK;
    }
}

static MemTxResult nvic_sysreg_ns_read(void *opaque, hwaddr addr,
                                       uint64_t *data, unsigned size,
                                       MemTxAttrs attrs)
{
    if (attrs.secure) {
        /* S accesses to the alias act like NS accesses to the real region */
        attrs.secure = 0;
        return nvic_sysreg_read(opaque, addr, data, size, attrs);
    } else {
        /* NS attrs are RAZ/WI for privileged, and BusFault for user */
        if (attrs.user) {
            return MEMTX_ERROR;
        }
        *data = 0;
        return MEMTX_OK;
    }
}

static const MemoryRegionOps nvic_sysreg_ns_ops = {
    .read_with_attrs = nvic_sysreg_ns_read,
    .write_with_attrs = nvic_sysreg_ns_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static int nvic_post_load(void *opaque, int version_id)
{
    NVICState *s = opaque;
    unsigned i;
    int resetprio;

    /* Check for out of range priority settings */
    resetprio = arm_feature(&s->cpu->env, ARM_FEATURE_V8) ? -4 : -3;

    if (s->vectors[ARMV7M_EXCP_RESET].prio != resetprio ||
        s->vectors[ARMV7M_EXCP_NMI].prio != -2 ||
        s->vectors[ARMV7M_EXCP_HARD].prio != -1) {
        return 1;
    }
    for (i = ARMV7M_EXCP_MEM; i < s->num_irq; i++) {
        if (s->vectors[i].prio & ~0xff) {
            return 1;
        }
    }

    nvic_recompute_state(s);

    return 0;
}

static const VMStateDescription vmstate_VecInfo = {
    .name = "armv7m_nvic_info",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_INT16(prio, VecInfo),
        VMSTATE_UINT8(enabled, VecInfo),
        VMSTATE_UINT8(pending, VecInfo),
        VMSTATE_UINT8(active, VecInfo),
        VMSTATE_UINT8(level, VecInfo),
        VMSTATE_END_OF_LIST()
    }
};

static bool nvic_security_needed(void *opaque)
{
    NVICState *s = opaque;

    return arm_feature(&s->cpu->env, ARM_FEATURE_M_SECURITY);
}

static int nvic_security_post_load(void *opaque, int version_id)
{
    NVICState *s = opaque;
    int i;

    /* Check for out of range priority settings */
    if (s->sec_vectors[ARMV7M_EXCP_HARD].prio != -1
        && s->sec_vectors[ARMV7M_EXCP_HARD].prio != -3) {
        /* We can't cross-check against AIRCR.BFHFNMINS as we don't know
         * if the CPU state has been migrated yet; a mismatch won't
         * cause the emulation to blow up, though.
         */
        return 1;
    }
    for (i = ARMV7M_EXCP_MEM; i < ARRAY_SIZE(s->sec_vectors); i++) {
        if (s->sec_vectors[i].prio & ~0xff) {
            return 1;
        }
    }
    return 0;
}

static const VMStateDescription vmstate_nvic_security = {
    .name = "nvic/m-security",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = nvic_security_needed,
    .post_load = &nvic_security_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_STRUCT_ARRAY(sec_vectors, NVICState, NVIC_INTERNAL_VECTORS, 1,
                             vmstate_VecInfo, VecInfo),
        VMSTATE_UINT32(prigroup[M_REG_S], NVICState),
        VMSTATE_BOOL_ARRAY(itns, NVICState, NVIC_MAX_VECTORS),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_nvic = {
    .name = "armv7m_nvic",
    .version_id = 4,
    .minimum_version_id = 4,
    .post_load = &nvic_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_STRUCT_ARRAY(vectors, NVICState, NVIC_MAX_VECTORS, 1,
                             vmstate_VecInfo, VecInfo),
        VMSTATE_UINT32(prigroup[M_REG_NS], NVICState),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription*[]) {
        &vmstate_nvic_security,
        NULL
    }
};

static Property props_nvic[] = {
    /* Number of external IRQ lines (so excluding the 16 internal exceptions) */
    DEFINE_PROP_UINT32("num-irq", NVICState, num_irq, 64),
    DEFINE_PROP_END_OF_LIST()
};

static void armv7m_nvic_reset(DeviceState *dev)
{
    int resetprio;
    NVICState *s = NVIC(dev);

    s->vectors[ARMV7M_EXCP_NMI].enabled = 1;
    /* MEM, BUS, and USAGE are enabled through
     * the System Handler Control register
     */
    s->vectors[ARMV7M_EXCP_SVC].enabled = 1;
    s->vectors[ARMV7M_EXCP_DEBUG].enabled = 1;
    s->vectors[ARMV7M_EXCP_PENDSV].enabled = 1;
    s->vectors[ARMV7M_EXCP_SYSTICK].enabled = 1;

    resetprio = arm_feature(&s->cpu->env, ARM_FEATURE_V8) ? -4 : -3;
    s->vectors[ARMV7M_EXCP_RESET].prio = resetprio;
    s->vectors[ARMV7M_EXCP_NMI].prio = -2;
    s->vectors[ARMV7M_EXCP_HARD].prio = -1;

    if (arm_feature(&s->cpu->env, ARM_FEATURE_M_SECURITY)) {
        s->sec_vectors[ARMV7M_EXCP_HARD].enabled = 1;
        s->sec_vectors[ARMV7M_EXCP_SVC].enabled = 1;
        s->sec_vectors[ARMV7M_EXCP_PENDSV].enabled = 1;
        s->sec_vectors[ARMV7M_EXCP_SYSTICK].enabled = 1;

        /* AIRCR.BFHFNMINS resets to 0 so Secure HF is priority -1 (R_CMTC) */
        s->sec_vectors[ARMV7M_EXCP_HARD].prio = -1;
        /* If AIRCR.BFHFNMINS is 0 then NS HF is (effectively) disabled */
        s->vectors[ARMV7M_EXCP_HARD].enabled = 0;
    } else {
        s->vectors[ARMV7M_EXCP_HARD].enabled = 1;
    }

    /* Strictly speaking the reset handler should be enabled.
     * However, we don't simulate soft resets through the NVIC,
     * and the reset vector should never be pended.
     * So we leave it disabled to catch logic errors.
     */

    s->exception_prio = NVIC_NOEXC_PRIO;
    s->vectpending = 0;
    s->vectpending_is_s_banked = false;
    s->vectpending_prio = NVIC_NOEXC_PRIO;

    if (arm_feature(&s->cpu->env, ARM_FEATURE_M_SECURITY)) {
        memset(s->itns, 0, sizeof(s->itns));
    } else {
        /* This state is constant and not guest accessible in a non-security
         * NVIC; we set the bits to true to avoid having to do a feature
         * bit check in the NVIC enable/pend/etc register accessors.
         */
        int i;

        for (i = NVIC_FIRST_IRQ; i < ARRAY_SIZE(s->itns); i++) {
            s->itns[i] = true;
        }
    }
}

static void nvic_systick_trigger(void *opaque, int n, int level)
{
    NVICState *s = opaque;

    if (level) {
        /* SysTick just asked us to pend its exception.
         * (This is different from an external interrupt line's
         * behaviour.)
         * TODO: when we implement the banked systicks we must make
         * this pend the correct banked exception.
         */
        armv7m_nvic_set_pending(s, ARMV7M_EXCP_SYSTICK, false);
    }
}

static void armv7m_nvic_realize(DeviceState *dev, Error **errp)
{
    NVICState *s = NVIC(dev);
    SysBusDevice *systick_sbd;
    Error *err = NULL;
    int regionlen;

    s->cpu = ARM_CPU(qemu_get_cpu(0));
    assert(s->cpu);

    if (s->num_irq > NVIC_MAX_IRQ) {
        error_setg(errp, "num-irq %d exceeds NVIC maximum", s->num_irq);
        return;
    }

    qdev_init_gpio_in(dev, set_irq_level, s->num_irq);

    /* include space for internal exception vectors */
    s->num_irq += NVIC_FIRST_IRQ;

    object_property_set_bool(OBJECT(&s->systick), true, "realized", &err);
    if (err != NULL) {
        error_propagate(errp, err);
        return;
    }
    systick_sbd = SYS_BUS_DEVICE(&s->systick);
    sysbus_connect_irq(systick_sbd, 0,
                       qdev_get_gpio_in_named(dev, "systick-trigger", 0));

    /* The NVIC and System Control Space (SCS) starts at 0xe000e000
     * and looks like this:
     *  0x004 - ICTR
     *  0x010 - 0xff - systick
     *  0x100..0x7ec - NVIC
     *  0x7f0..0xcff - Reserved
     *  0xd00..0xd3c - SCS registers
     *  0xd40..0xeff - Reserved or Not implemented
     *  0xf00 - STIR
     *
     * Some registers within this space are banked between security states.
     * In v8M there is a second range 0xe002e000..0xe002efff which is the
     * NonSecure alias SCS; secure accesses to this behave like NS accesses
     * to the main SCS range, and non-secure accesses (including when
     * the security extension is not implemented) are RAZ/WI.
     * Note that both the main SCS range and the alias range are defined
     * to be exempt from memory attribution (R_BLJT) and so the memory
     * transaction attribute always matches the current CPU security
     * state (attrs.secure == env->v7m.secure). In the nvic_sysreg_ns_ops
     * wrappers we change attrs.secure to indicate the NS access; so
     * generally code determining which banked register to use should
     * use attrs.secure; code determining actual behaviour of the system
     * should use env->v7m.secure.
     */
    regionlen = arm_feature(&s->cpu->env, ARM_FEATURE_V8) ? 0x21000 : 0x1000;
    memory_region_init(&s->container, OBJECT(s), "nvic", regionlen);
    /* The system register region goes at the bottom of the priority
     * stack as it covers the whole page.
     */
    memory_region_init_io(&s->sysregmem, OBJECT(s), &nvic_sysreg_ops, s,
                          "nvic_sysregs", 0x1000);
    memory_region_add_subregion(&s->container, 0, &s->sysregmem);
    memory_region_add_subregion_overlap(&s->container, 0x10,
                                        sysbus_mmio_get_region(systick_sbd, 0),
                                        1);

    if (arm_feature(&s->cpu->env, ARM_FEATURE_V8)) {
        memory_region_init_io(&s->sysreg_ns_mem, OBJECT(s),
                              &nvic_sysreg_ns_ops, s,
                              "nvic_sysregs_ns", 0x1000);
        memory_region_add_subregion(&s->container, 0x20000, &s->sysreg_ns_mem);
    }

    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->container);
}

static void armv7m_nvic_instance_init(Object *obj)
{
    /* We have a different default value for the num-irq property
     * than our superclass. This function runs after qdev init
     * has set the defaults from the Property array and before
     * any user-specified property setting, so just modify the
     * value in the GICState struct.
     */
    DeviceState *dev = DEVICE(obj);
    NVICState *nvic = NVIC(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    object_initialize(&nvic->systick, sizeof(nvic->systick), TYPE_SYSTICK);
    qdev_set_parent_bus(DEVICE(&nvic->systick), sysbus_get_default());

    sysbus_init_irq(sbd, &nvic->excpout);
    qdev_init_gpio_out_named(dev, &nvic->sysresetreq, "SYSRESETREQ", 1);
    qdev_init_gpio_in_named(dev, nvic_systick_trigger, "systick-trigger", 1);
}

static void armv7m_nvic_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->vmsd  = &vmstate_nvic;
    dc->props = props_nvic;
    dc->reset = armv7m_nvic_reset;
    dc->realize = armv7m_nvic_realize;
}

static const TypeInfo armv7m_nvic_info = {
    .name          = TYPE_NVIC,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_init = armv7m_nvic_instance_init,
    .instance_size = sizeof(NVICState),
    .class_init    = armv7m_nvic_class_init,
    .class_size    = sizeof(SysBusDeviceClass),
};

static void armv7m_nvic_register_types(void)
{
    type_register_static(&armv7m_nvic_info);
}

type_init(armv7m_nvic_register_types)
