/*
 * Xen basic APIC support
 *
 * Copyright (c) 2012 Citrix
 *
 * Authors:
 *  Wei Liu <wei.liu2@citrix.com>
 *
 * This work is licensed under the terms of the GNU GPL version 2 or
 * later. See the COPYING file in the top-level directory.
 */
#include "hw/i386/apic_internal.h"
#include "hw/pci/msi.h"
#include "hw/xen/xen.h"

static uint64_t xen_apic_mem_read(void *opaque, hwaddr addr,
                                  unsigned size)
{
    return ~(uint64_t)0;
}

static void xen_apic_mem_write(void *opaque, hwaddr addr,
                               uint64_t data, unsigned size)
{
    if (size != sizeof(uint32_t)) {
        fprintf(stderr, "Xen: APIC write data size = %d, invalid\n", size);
        return;
    }

    xen_hvm_inject_msi(addr, data);
}

static const MemoryRegionOps xen_apic_io_ops = {
    .read = xen_apic_mem_read,
    .write = xen_apic_mem_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void xen_apic_init(APICCommonState *s)
{
    memory_region_init_io(&s->io_memory, &xen_apic_io_ops, s, "xen-apic-msi",
                          MSI_SPACE_SIZE);

#if defined(CONFIG_XEN_CTRL_INTERFACE_VERSION) \
    && CONFIG_XEN_CTRL_INTERFACE_VERSION >= 420
    msi_supported = true;
#endif
}

static void xen_apic_set_base(APICCommonState *s, uint64_t val)
{
}

static void xen_apic_set_tpr(APICCommonState *s, uint8_t val)
{
}

static uint8_t xen_apic_get_tpr(APICCommonState *s)
{
    return 0;
}

static void xen_apic_vapic_base_update(APICCommonState *s)
{
}

static void xen_apic_external_nmi(APICCommonState *s)
{
}

static void xen_apic_class_init(ObjectClass *klass, void *data)
{
    APICCommonClass *k = APIC_COMMON_CLASS(klass);

    k->init = xen_apic_init;
    k->set_base = xen_apic_set_base;
    k->set_tpr = xen_apic_set_tpr;
    k->get_tpr = xen_apic_get_tpr;
    k->vapic_base_update = xen_apic_vapic_base_update;
    k->external_nmi = xen_apic_external_nmi;
}

static const TypeInfo xen_apic_info = {
    .name = "xen-apic",
    .parent = TYPE_APIC_COMMON,
    .instance_size = sizeof(APICCommonState),
    .class_init = xen_apic_class_init,
};

static void xen_apic_register_types(void)
{
    type_register_static(&xen_apic_info);
}

type_init(xen_apic_register_types)
