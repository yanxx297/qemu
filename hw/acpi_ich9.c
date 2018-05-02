/*
 * ACPI implementation
 *
 * Copyright (c) 2006 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */
/*
 *  Copyright (c) 2009 Isaku Yamahata <yamahata at valinux co jp>
 *                     VA Linux Systems Japan K.K.
 *  Copyright (C) 2012 Jason Baron <jbaron@redhat.com>
 *
 *  This is based on acpi.c.
 */
#include "hw.h"
#include "pc.h"
#include "pci.h"
#include "qemu-timer.h"
#include "sysemu.h"
#include "acpi.h"
#include "kvm.h"
#include "exec-memory.h"

#include "ich9.h"

//#define DEBUG

#ifdef DEBUG
#define ICH9_DEBUG(fmt, ...) \
do { printf("%s "fmt, __func__, ## __VA_ARGS__); } while (0)
#else
#define ICH9_DEBUG(fmt, ...)    do { } while (0)
#endif

static void pm_ioport_write_fallback(void *opaque, uint32_t addr, int len,
                                     uint32_t val);
static uint32_t pm_ioport_read_fallback(void *opaque, uint32_t addr, int len);

static void pm_update_sci(ICH9LPCPMRegs *pm)
{
    int sci_level, pm1a_sts;

    pm1a_sts = acpi_pm1_evt_get_sts(&pm->acpi_regs);

    sci_level = (((pm1a_sts & pm->acpi_regs.pm1.evt.en) &
                  (ACPI_BITMASK_RT_CLOCK_ENABLE |
                   ACPI_BITMASK_POWER_BUTTON_ENABLE |
                   ACPI_BITMASK_GLOBAL_LOCK_ENABLE |
                   ACPI_BITMASK_TIMER_ENABLE)) != 0);
    qemu_set_irq(pm->irq, sci_level);

    /* schedule a timer interruption if needed */
    acpi_pm_tmr_update(&pm->acpi_regs,
                       (pm->acpi_regs.pm1.evt.en & ACPI_BITMASK_TIMER_ENABLE) &&
                       !(pm1a_sts & ACPI_BITMASK_TIMER_STATUS));
}

static void ich9_pm_update_sci_fn(ACPIREGS *regs)
{
    ICH9LPCPMRegs *pm = container_of(regs, ICH9LPCPMRegs, acpi_regs);
    pm_update_sci(pm);
}

static void pm_ioport_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    switch (addr & ICH9_PMIO_MASK) {
    default:
        break;
    }

    ICH9_DEBUG("port=0x%04x val=0x%04x\n", addr, val);
}

static uint32_t pm_ioport_readb(void *opaque, uint32_t addr)
{
    uint32_t val = 0;

    switch (addr & ICH9_PMIO_MASK) {
    default:
        val = 0;
        break;
    }
    ICH9_DEBUG("port=0x%04x val=0x%04x\n", addr, val);
    return val;
}

static void pm_ioport_writew(void *opaque, uint32_t addr, uint32_t val)
{
    switch (addr & ICH9_PMIO_MASK) {
    default:
        pm_ioport_write_fallback(opaque, addr, 2, val);
        break;
    }
    ICH9_DEBUG("port=0x%04x val=0x%04x\n", addr, val);
}

static uint32_t pm_ioport_readw(void *opaque, uint32_t addr)
{
    uint32_t val;

    switch (addr & ICH9_PMIO_MASK) {
    default:
        val = pm_ioport_read_fallback(opaque, addr, 2);
        break;
    }
    ICH9_DEBUG("port=0x%04x val=0x%04x\n", addr, val);
    return val;
}

static void pm_ioport_writel(void *opaque, uint32_t addr, uint32_t val)
{
    ICH9LPCPMRegs *pm = opaque;

    switch (addr & ICH9_PMIO_MASK) {
    case ICH9_PMIO_SMI_EN:
        pm->smi_en = val;
        break;
    default:
        pm_ioport_write_fallback(opaque, addr, 4, val);
        break;
    }
    ICH9_DEBUG("port=0x%04x val=0x%08x\n", addr, val);
}

static uint32_t pm_ioport_readl(void *opaque, uint32_t addr)
{
    ICH9LPCPMRegs *pm = opaque;
    uint32_t val;

    switch (addr & ICH9_PMIO_MASK) {
    case ICH9_PMIO_SMI_EN:
        val = pm->smi_en;
        break;

    default:
        val = pm_ioport_read_fallback(opaque, addr, 4);
        break;
    }
    ICH9_DEBUG("port=0x%04x val=0x%08x\n", addr, val);
    return val;
}

static void pm_ioport_write_fallback(void *opaque, uint32_t addr, int len,
                                     uint32_t val)
 {
    int subsize = (len == 4) ? 2 : 1;
    IOPortWriteFunc *ioport_write =
        (subsize == 2) ? pm_ioport_writew : pm_ioport_writeb;

    int i;

    for (i = 0; i < len; i += subsize) {
        ioport_write(opaque, addr, val);
        val >>= 8 * subsize;
    }
}

static uint32_t pm_ioport_read_fallback(void *opaque, uint32_t addr, int len)
{
    int subsize = (len == 4) ? 2 : 1;
    IOPortReadFunc *ioport_read =
        (subsize == 2) ? pm_ioport_readw : pm_ioport_readb;

    uint32_t val;
    int i;

    val = 0;
    for (i = 0; i < len; i += subsize) {
        val <<= 8 * subsize;
        val |= ioport_read(opaque, addr);
    }

    return val;
}

static const MemoryRegionOps pm_io_ops = {
    .old_portio = (MemoryRegionPortio[]) {
        { .offset = 0, .len = ICH9_PMIO_SIZE, .size = 1,
          .read = pm_ioport_readb, .write = pm_ioport_writeb },
        { .offset = 0, .len = ICH9_PMIO_SIZE, .size = 2,
          .read = pm_ioport_readw, .write = pm_ioport_writew },
        { .offset = 0, .len = ICH9_PMIO_SIZE, .size = 4,
          .read = pm_ioport_readl, .write = pm_ioport_writel },
        PORTIO_END_OF_LIST(),
    },
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static uint64_t ich9_gpe_readb(void *opaque, hwaddr addr, unsigned width)
{
    ICH9LPCPMRegs *pm = opaque;
    return acpi_gpe_ioport_readb(&pm->acpi_regs, addr);
}

static void ich9_gpe_writeb(void *opaque, hwaddr addr, uint64_t val,
                            unsigned width)
{
    ICH9LPCPMRegs *pm = opaque;
    acpi_gpe_ioport_writeb(&pm->acpi_regs, addr, val);
}

static const MemoryRegionOps ich9_gpe_ops = {
    .read = ich9_gpe_readb,
    .write = ich9_gpe_writeb,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 1,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

void ich9_pm_iospace_update(ICH9LPCPMRegs *pm, uint32_t pm_io_base)
{
    ICH9_DEBUG("to 0x%x\n", pm_io_base);

    assert((pm_io_base & ICH9_PMIO_MASK) == 0);

    pm->pm_io_base = pm_io_base;
    memory_region_transaction_begin();
    memory_region_set_enabled(&pm->io, pm->pm_io_base != 0);
    memory_region_set_address(&pm->io, pm->pm_io_base);
    memory_region_transaction_commit();
}

static int ich9_pm_post_load(void *opaque, int version_id)
{
    ICH9LPCPMRegs *pm = opaque;
    uint32_t pm_io_base = pm->pm_io_base;
    pm->pm_io_base = 0;
    ich9_pm_iospace_update(pm, pm_io_base);
    return 0;
}

#define VMSTATE_GPE_ARRAY(_field, _state)                            \
 {                                                                   \
     .name       = (stringify(_field)),                              \
     .version_id = 0,                                                \
     .num        = ICH9_PMIO_GPE0_LEN,                               \
     .info       = &vmstate_info_uint8,                              \
     .size       = sizeof(uint8_t),                                  \
     .flags      = VMS_ARRAY | VMS_POINTER,                          \
     .offset     = vmstate_offset_pointer(_state, _field, uint8_t),  \
 }

const VMStateDescription vmstate_ich9_pm = {
    .name = "ich9_pm",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .post_load = ich9_pm_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT16(acpi_regs.pm1.evt.sts, ICH9LPCPMRegs),
        VMSTATE_UINT16(acpi_regs.pm1.evt.en, ICH9LPCPMRegs),
        VMSTATE_UINT16(acpi_regs.pm1.cnt.cnt, ICH9LPCPMRegs),
        VMSTATE_TIMER(acpi_regs.tmr.timer, ICH9LPCPMRegs),
        VMSTATE_INT64(acpi_regs.tmr.overflow_time, ICH9LPCPMRegs),
        VMSTATE_GPE_ARRAY(acpi_regs.gpe.sts, ICH9LPCPMRegs),
        VMSTATE_GPE_ARRAY(acpi_regs.gpe.en, ICH9LPCPMRegs),
        VMSTATE_UINT32(smi_en, ICH9LPCPMRegs),
        VMSTATE_UINT32(smi_sts, ICH9LPCPMRegs),
        VMSTATE_END_OF_LIST()
    }
};

static void pm_reset(void *opaque)
{
    ICH9LPCPMRegs *pm = opaque;
    ich9_pm_iospace_update(pm, 0);

    acpi_pm1_evt_reset(&pm->acpi_regs);
    acpi_pm1_cnt_reset(&pm->acpi_regs);
    acpi_pm_tmr_reset(&pm->acpi_regs);
    acpi_gpe_reset(&pm->acpi_regs);

    if (kvm_enabled()) {
        /* Mark SMM as already inited to prevent SMM from running. KVM does not
         * support SMM mode. */
        pm->smi_en |= ICH9_PMIO_SMI_EN_APMC_EN;
    }

    pm_update_sci(pm);
}

static void pm_powerdown_req(Notifier *n, void *opaque)
{
    ICH9LPCPMRegs *pm = container_of(n, ICH9LPCPMRegs, powerdown_notifier);

    acpi_pm1_evt_power_down(&pm->acpi_regs);
}

void ich9_pm_init(ICH9LPCPMRegs *pm, qemu_irq sci_irq, qemu_irq cmos_s3)
{
    memory_region_init_io(&pm->io, &pm_io_ops, pm, "ich9-pm", ICH9_PMIO_SIZE);
    memory_region_set_enabled(&pm->io, false);
    memory_region_add_subregion(get_system_io(), 0, &pm->io);

    acpi_pm_tmr_init(&pm->acpi_regs, ich9_pm_update_sci_fn, &pm->io);
    acpi_pm1_evt_init(&pm->acpi_regs, ich9_pm_update_sci_fn, &pm->io);
    acpi_pm1_cnt_init(&pm->acpi_regs, &pm->io);

    acpi_gpe_init(&pm->acpi_regs, ICH9_PMIO_GPE0_LEN);
    acpi_gpe_blk(&pm->acpi_regs, 0);
    memory_region_init_io(&pm->io_gpe, &ich9_gpe_ops, pm, "apci-gpe0",
                          ICH9_PMIO_GPE0_LEN);
    memory_region_add_subregion(&pm->io, ICH9_PMIO_GPE0_STS, &pm->io_gpe);

    pm->irq = sci_irq;
    qemu_register_reset(pm_reset, pm);
    pm->powerdown_notifier.notify = pm_powerdown_req;
    qemu_register_powerdown_notifier(&pm->powerdown_notifier);
}
