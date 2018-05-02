/*
 * virtio ccw machine
 *
 * Copyright 2012 IBM Corp.
 * Copyright (c) 2009 Alexander Graf <agraf@suse.de>
 * Author(s): Cornelia Huck <cornelia.huck@de.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"
#include "s390-virtio.h"
#include "hw/s390x/sclp.h"
#include "hw/s390x/s390_flic.h"
#include "hw/s390x/ioinst.h"
#include "hw/s390x/css.h"
#include "virtio-ccw.h"
#include "qemu/config-file.h"
#include "s390-pci-bus.h"
#include "hw/s390x/storage-keys.h"
#include "hw/s390x/storage-attributes.h"
#include "hw/compat.h"
#include "ipl.h"
#include "hw/s390x/s390-virtio-ccw.h"
#include "hw/s390x/css-bridge.h"
#include "migration/register.h"
#include "cpu_models.h"
#include "qapi/qmp/qerror.h"
#include "hw/nmi.h"

static S390CPU **cpu_states;

S390CPU *s390_cpu_addr2state(uint16_t cpu_addr)
{
    if (cpu_addr >= max_cpus) {
        return NULL;
    }

    /* Fast lookup via CPU ID */
    return cpu_states[cpu_addr];
}

static void s390_init_cpus(MachineState *machine)
{
    int i;
    gchar *name;

    if (machine->cpu_model == NULL) {
        machine->cpu_model = s390_default_cpu_model_name();
    }

    cpu_states = g_new0(S390CPU *, max_cpus);

    for (i = 0; i < max_cpus; i++) {
        name = g_strdup_printf("cpu[%i]", i);
        object_property_add_link(OBJECT(machine), name, TYPE_S390_CPU,
                                 (Object **) &cpu_states[i],
                                 object_property_allow_set_link,
                                 OBJ_PROP_LINK_UNREF_ON_RELEASE,
                                 &error_abort);
        g_free(name);
    }

    for (i = 0; i < smp_cpus; i++) {
        s390x_new_cpu(machine->cpu_model, i, &error_fatal);
    }
}

static const char *const reset_dev_types[] = {
    TYPE_VIRTUAL_CSS_BRIDGE,
    "s390-sclp-event-facility",
    "s390-flic",
    "diag288",
};

void subsystem_reset(void)
{
    DeviceState *dev;
    int i;

    for (i = 0; i < ARRAY_SIZE(reset_dev_types); i++) {
        dev = DEVICE(object_resolve_path_type("", reset_dev_types[i], NULL));
        if (dev) {
            qdev_reset_all(dev);
        }
    }
}

static int virtio_ccw_hcall_notify(const uint64_t *args)
{
    uint64_t subch_id = args[0];
    uint64_t queue = args[1];
    SubchDev *sch;
    int cssid, ssid, schid, m;

    if (ioinst_disassemble_sch_ident(subch_id, &m, &cssid, &ssid, &schid)) {
        return -EINVAL;
    }
    sch = css_find_subch(m, cssid, ssid, schid);
    if (!sch || !css_subch_visible(sch)) {
        return -EINVAL;
    }
    if (queue >= VIRTIO_QUEUE_MAX) {
        return -EINVAL;
    }
    virtio_queue_notify(virtio_ccw_get_vdev(sch), queue);
    return 0;

}

static int virtio_ccw_hcall_early_printk(const uint64_t *args)
{
    uint64_t mem = args[0];

    if (mem < ram_size) {
        /* Early printk */
        return 0;
    }
    return -EINVAL;
}

static void virtio_ccw_register_hcalls(void)
{
    s390_register_virtio_hypercall(KVM_S390_VIRTIO_CCW_NOTIFY,
                                   virtio_ccw_hcall_notify);
    /* Tolerate early printk. */
    s390_register_virtio_hypercall(KVM_S390_VIRTIO_NOTIFY,
                                   virtio_ccw_hcall_early_printk);
}

static void s390_memory_init(ram_addr_t mem_size)
{
    MemoryRegion *sysmem = get_system_memory();
    MemoryRegion *ram = g_new(MemoryRegion, 1);

    /* allocate RAM for core */
    memory_region_allocate_system_memory(ram, NULL, "s390.ram", mem_size);
    memory_region_add_subregion(sysmem, 0, ram);

    /* Initialize storage key device */
    s390_skeys_init();
    /* Initialize storage attributes device */
    s390_stattrib_init();
}

#define S390_TOD_CLOCK_VALUE_MISSING    0x00
#define S390_TOD_CLOCK_VALUE_PRESENT    0x01

static void gtod_save(QEMUFile *f, void *opaque)
{
    uint64_t tod_low;
    uint8_t tod_high;
    int r;

    r = s390_get_clock(&tod_high, &tod_low);
    if (r) {
        warn_report("Unable to get guest clock for migration: %s",
                    strerror(-r));
        error_printf("Guest clock will not be migrated "
                     "which could cause the guest to hang.");
        qemu_put_byte(f, S390_TOD_CLOCK_VALUE_MISSING);
        return;
    }

    qemu_put_byte(f, S390_TOD_CLOCK_VALUE_PRESENT);
    qemu_put_byte(f, tod_high);
    qemu_put_be64(f, tod_low);
}

static int gtod_load(QEMUFile *f, void *opaque, int version_id)
{
    uint64_t tod_low;
    uint8_t tod_high;
    int r;

    if (qemu_get_byte(f) == S390_TOD_CLOCK_VALUE_MISSING) {
        warn_report("Guest clock was not migrated. This could "
                    "cause the guest to hang.");
        return 0;
    }

    tod_high = qemu_get_byte(f);
    tod_low = qemu_get_be64(f);

    r = s390_set_clock(&tod_high, &tod_low);
    if (r) {
        warn_report("Unable to set guest clock for migration: %s",
                    strerror(-r));
        error_printf("Guest clock will not be restored "
                     "which could cause the guest to hang.");
    }

    return 0;
}

static SaveVMHandlers savevm_gtod = {
    .save_state = gtod_save,
    .load_state = gtod_load,
};

static void s390_init_ipl_dev(const char *kernel_filename,
                              const char *kernel_cmdline,
                              const char *initrd_filename, const char *firmware,
                              const char *netboot_fw, bool enforce_bios)
{
    Object *new = object_new(TYPE_S390_IPL);
    DeviceState *dev = DEVICE(new);

    if (kernel_filename) {
        qdev_prop_set_string(dev, "kernel", kernel_filename);
    }
    if (initrd_filename) {
        qdev_prop_set_string(dev, "initrd", initrd_filename);
    }
    qdev_prop_set_string(dev, "cmdline", kernel_cmdline);
    qdev_prop_set_string(dev, "firmware", firmware);
    qdev_prop_set_string(dev, "netboot_fw", netboot_fw);
    qdev_prop_set_bit(dev, "enforce_bios", enforce_bios);
    object_property_add_child(qdev_get_machine(), TYPE_S390_IPL,
                              new, NULL);
    object_unref(new);
    qdev_init_nofail(dev);
}

static void s390_create_virtio_net(BusState *bus, const char *name)
{
    int i;

    for (i = 0; i < nb_nics; i++) {
        NICInfo *nd = &nd_table[i];
        DeviceState *dev;

        if (!nd->model) {
            nd->model = g_strdup("virtio");
        }

        qemu_check_nic_model(nd, "virtio");

        dev = qdev_create(bus, name);
        qdev_set_nic_properties(dev, nd);
        qdev_init_nofail(dev);
    }
}

static void ccw_init(MachineState *machine)
{
    int ret;
    VirtualCssBus *css_bus;

    s390_sclp_init();
    s390_memory_init(machine->ram_size);

    /* init CPUs (incl. CPU model) early so s390_has_feature() works */
    s390_init_cpus(machine);

    s390_flic_init();

    /* get a BUS */
    css_bus = virtual_css_bus_init();
    s390_init_ipl_dev(machine->kernel_filename, machine->kernel_cmdline,
                      machine->initrd_filename, "s390-ccw.img",
                      "s390-netboot.img", true);

    if (s390_has_feat(S390_FEAT_ZPCI)) {
        DeviceState *dev = qdev_create(NULL, TYPE_S390_PCI_HOST_BRIDGE);
        object_property_add_child(qdev_get_machine(),
                                  TYPE_S390_PCI_HOST_BRIDGE,
                                  OBJECT(dev), NULL);
        qdev_init_nofail(dev);
    }

    /* register hypercalls */
    virtio_ccw_register_hcalls();

    s390_enable_css_support(s390_cpu_addr2state(0));
    /*
     * Non mcss-e enabled guests only see the devices from the default
     * css, which is determined by the value of the squash_mcss property.
     * Note: we must not squash non virtual devices to css 0xFE.
     */
    if (css_bus->squash_mcss) {
        ret = css_create_css_image(0, true);
    } else {
        ret = css_create_css_image(VIRTUAL_CSSID, true);
    }
    assert(ret == 0);

    /* Create VirtIO network adapters */
    s390_create_virtio_net(BUS(css_bus), "virtio-net-ccw");

    /* Register savevm handler for guest TOD clock */
    register_savevm_live(NULL, "todclock", 0, 1, &savevm_gtod, NULL);
}

static void s390_cpu_plug(HotplugHandler *hotplug_dev,
                        DeviceState *dev, Error **errp)
{
    gchar *name;
    S390CPU *cpu = S390_CPU(dev);
    CPUState *cs = CPU(dev);

    name = g_strdup_printf("cpu[%i]", cpu->env.cpu_num);
    object_property_set_link(OBJECT(hotplug_dev), OBJECT(cs), name,
                             errp);
    g_free(name);
}

static void s390_machine_reset(void)
{
    S390CPU *ipl_cpu = S390_CPU(qemu_get_cpu(0));

    s390_cmma_reset();
    qemu_devices_reset();
    s390_crypto_reset();

    /* all cpus are stopped - configure and start the ipl cpu only */
    s390_ipl_prepare_cpu(ipl_cpu);
    s390_cpu_set_state(CPU_STATE_OPERATING, ipl_cpu);
}

static void s390_machine_device_plug(HotplugHandler *hotplug_dev,
                                     DeviceState *dev, Error **errp)
{
    if (object_dynamic_cast(OBJECT(dev), TYPE_CPU)) {
        s390_cpu_plug(hotplug_dev, dev, errp);
    }
}

static HotplugHandler *s390_get_hotplug_handler(MachineState *machine,
                                                DeviceState *dev)
{
    if (object_dynamic_cast(OBJECT(dev), TYPE_CPU)) {
        return HOTPLUG_HANDLER(machine);
    }
    return NULL;
}

static void s390_hot_add_cpu(const int64_t id, Error **errp)
{
    MachineState *machine = MACHINE(qdev_get_machine());

    s390x_new_cpu(machine->cpu_model, id, errp);
}

static void s390_nmi(NMIState *n, int cpu_index, Error **errp)
{
    CPUState *cs = qemu_get_cpu(cpu_index);

    if (s390_cpu_restart(S390_CPU(cs))) {
        error_setg(errp, QERR_UNSUPPORTED);
    }
}

static void ccw_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    NMIClass *nc = NMI_CLASS(oc);
    HotplugHandlerClass *hc = HOTPLUG_HANDLER_CLASS(oc);
    S390CcwMachineClass *s390mc = S390_MACHINE_CLASS(mc);

    s390mc->ri_allowed = true;
    s390mc->cpu_model_allowed = true;
    s390mc->css_migration_enabled = true;
    s390mc->gs_allowed = true;
    mc->init = ccw_init;
    mc->reset = s390_machine_reset;
    mc->hot_add_cpu = s390_hot_add_cpu;
    mc->block_default_type = IF_VIRTIO;
    mc->no_cdrom = 1;
    mc->no_floppy = 1;
    mc->no_serial = 1;
    mc->no_parallel = 1;
    mc->no_sdcard = 1;
    mc->use_sclp = 1;
    mc->max_cpus = 248;
    mc->get_hotplug_handler = s390_get_hotplug_handler;
    hc->plug = s390_machine_device_plug;
    nc->nmi_monitor_handler = s390_nmi;
}

static inline bool machine_get_aes_key_wrap(Object *obj, Error **errp)
{
    S390CcwMachineState *ms = S390_CCW_MACHINE(obj);

    return ms->aes_key_wrap;
}

static inline void machine_set_aes_key_wrap(Object *obj, bool value,
                                            Error **errp)
{
    S390CcwMachineState *ms = S390_CCW_MACHINE(obj);

    ms->aes_key_wrap = value;
}

static inline bool machine_get_dea_key_wrap(Object *obj, Error **errp)
{
    S390CcwMachineState *ms = S390_CCW_MACHINE(obj);

    return ms->dea_key_wrap;
}

static inline void machine_set_dea_key_wrap(Object *obj, bool value,
                                            Error **errp)
{
    S390CcwMachineState *ms = S390_CCW_MACHINE(obj);

    ms->dea_key_wrap = value;
}

static S390CcwMachineClass *current_mc;

static S390CcwMachineClass *get_machine_class(void)
{
    if (unlikely(!current_mc)) {
        /*
        * No s390 ccw machine was instantiated, we are likely to
        * be called for the 'none' machine. The properties will
        * have their after-initialization values.
        */
        current_mc = S390_MACHINE_CLASS(
                     object_class_by_name(TYPE_S390_CCW_MACHINE));
    }
    return current_mc;
}

bool ri_allowed(void)
{
    /* for "none" machine this results in true */
    return get_machine_class()->ri_allowed;
}

bool cpu_model_allowed(void)
{
    /* for "none" machine this results in true */
    return get_machine_class()->cpu_model_allowed;
}

bool gs_allowed(void)
{
    /* for "none" machine this results in true */
    return get_machine_class()->gs_allowed;
}

static char *machine_get_loadparm(Object *obj, Error **errp)
{
    S390CcwMachineState *ms = S390_CCW_MACHINE(obj);

    return g_memdup(ms->loadparm, sizeof(ms->loadparm));
}

static void machine_set_loadparm(Object *obj, const char *val, Error **errp)
{
    S390CcwMachineState *ms = S390_CCW_MACHINE(obj);
    int i;

    for (i = 0; i < sizeof(ms->loadparm) && val[i]; i++) {
        uint8_t c = qemu_toupper(val[i]); /* mimic HMC */

        if (('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || (c == '.') ||
            (c == ' ')) {
            ms->loadparm[i] = c;
        } else {
            error_setg(errp, "LOADPARM: invalid character '%c' (ASCII 0x%02x)",
                       c, c);
            return;
        }
    }

    for (; i < sizeof(ms->loadparm); i++) {
        ms->loadparm[i] = ' '; /* pad right with spaces */
    }
}
static inline bool machine_get_squash_mcss(Object *obj, Error **errp)
{
    S390CcwMachineState *ms = S390_CCW_MACHINE(obj);

    return ms->s390_squash_mcss;
}

static inline void machine_set_squash_mcss(Object *obj, bool value,
                                           Error **errp)
{
    S390CcwMachineState *ms = S390_CCW_MACHINE(obj);

    ms->s390_squash_mcss = value;
}

static inline void s390_machine_initfn(Object *obj)
{
    object_property_add_bool(obj, "aes-key-wrap",
                             machine_get_aes_key_wrap,
                             machine_set_aes_key_wrap, NULL);
    object_property_set_description(obj, "aes-key-wrap",
            "enable/disable AES key wrapping using the CPACF wrapping key",
            NULL);
    object_property_set_bool(obj, true, "aes-key-wrap", NULL);

    object_property_add_bool(obj, "dea-key-wrap",
                             machine_get_dea_key_wrap,
                             machine_set_dea_key_wrap, NULL);
    object_property_set_description(obj, "dea-key-wrap",
            "enable/disable DEA key wrapping using the CPACF wrapping key",
            NULL);
    object_property_set_bool(obj, true, "dea-key-wrap", NULL);
    object_property_add_str(obj, "loadparm",
            machine_get_loadparm, machine_set_loadparm, NULL);
    object_property_set_description(obj, "loadparm",
            "Up to 8 chars in set of [A-Za-z0-9. ] (lower case chars converted"
            " to upper case) to pass to machine loader, boot manager,"
            " and guest kernel",
            NULL);
    object_property_add_bool(obj, "s390-squash-mcss",
                             machine_get_squash_mcss,
                             machine_set_squash_mcss, NULL);
    object_property_set_description(obj, "s390-squash-mcss",
            "enable/disable squashing subchannels into the default css",
            NULL);
    object_property_set_bool(obj, false, "s390-squash-mcss", NULL);
}

static const TypeInfo ccw_machine_info = {
    .name          = TYPE_S390_CCW_MACHINE,
    .parent        = TYPE_MACHINE,
    .abstract      = true,
    .instance_size = sizeof(S390CcwMachineState),
    .instance_init = s390_machine_initfn,
    .class_size = sizeof(S390CcwMachineClass),
    .class_init    = ccw_machine_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_NMI },
        { TYPE_HOTPLUG_HANDLER},
        { }
    },
};

bool css_migration_enabled(void)
{
    return get_machine_class()->css_migration_enabled;
}

#define DEFINE_CCW_MACHINE(suffix, verstr, latest)                            \
    static void ccw_machine_##suffix##_class_init(ObjectClass *oc,            \
                                                  void *data)                 \
    {                                                                         \
        MachineClass *mc = MACHINE_CLASS(oc);                                 \
        ccw_machine_##suffix##_class_options(mc);                             \
        mc->desc = "VirtIO-ccw based S390 machine v" verstr;                  \
        if (latest) {                                                         \
            mc->alias = "s390-ccw-virtio";                                    \
            mc->is_default = 1;                                               \
        }                                                                     \
    }                                                                         \
    static void ccw_machine_##suffix##_instance_init(Object *obj)             \
    {                                                                         \
        MachineState *machine = MACHINE(obj);                                 \
        current_mc = S390_MACHINE_CLASS(MACHINE_GET_CLASS(machine));          \
        ccw_machine_##suffix##_instance_options(machine);                     \
    }                                                                         \
    static const TypeInfo ccw_machine_##suffix##_info = {                     \
        .name = MACHINE_TYPE_NAME("s390-ccw-virtio-" verstr),                 \
        .parent = TYPE_S390_CCW_MACHINE,                                      \
        .class_init = ccw_machine_##suffix##_class_init,                      \
        .instance_init = ccw_machine_##suffix##_instance_init,                \
    };                                                                        \
    static void ccw_machine_register_##suffix(void)                           \
    {                                                                         \
        type_register_static(&ccw_machine_##suffix##_info);                   \
    }                                                                         \
    type_init(ccw_machine_register_##suffix)

#define CCW_COMPAT_2_10 \
        HW_COMPAT_2_10

#define CCW_COMPAT_2_9 \
        HW_COMPAT_2_9 \
        {\
            .driver   = TYPE_S390_STATTRIB,\
            .property = "migration-enabled",\
            .value    = "off",\
        },

#define CCW_COMPAT_2_8 \
        HW_COMPAT_2_8 \
        {\
            .driver   = TYPE_S390_FLIC_COMMON,\
            .property = "adapter_routes_max_batch",\
            .value    = "64",\
        },

#define CCW_COMPAT_2_7 \
        HW_COMPAT_2_7

#define CCW_COMPAT_2_6 \
        HW_COMPAT_2_6 \
        {\
            .driver   = TYPE_S390_IPL,\
            .property = "iplbext_migration",\
            .value    = "off",\
        }, {\
            .driver   = TYPE_VIRTUAL_CSS_BRIDGE,\
            .property = "css_dev_path",\
            .value    = "off",\
        },

#define CCW_COMPAT_2_5 \
        HW_COMPAT_2_5

#define CCW_COMPAT_2_4 \
        HW_COMPAT_2_4 \
        {\
            .driver   = TYPE_S390_SKEYS,\
            .property = "migration-enabled",\
            .value    = "off",\
        },{\
            .driver   = "virtio-blk-ccw",\
            .property = "max_revision",\
            .value    = "0",\
        },{\
            .driver   = "virtio-balloon-ccw",\
            .property = "max_revision",\
            .value    = "0",\
        },{\
            .driver   = "virtio-serial-ccw",\
            .property = "max_revision",\
            .value    = "0",\
        },{\
            .driver   = "virtio-9p-ccw",\
            .property = "max_revision",\
            .value    = "0",\
        },{\
            .driver   = "virtio-rng-ccw",\
            .property = "max_revision",\
            .value    = "0",\
        },{\
            .driver   = "virtio-net-ccw",\
            .property = "max_revision",\
            .value    = "0",\
        },{\
            .driver   = "virtio-scsi-ccw",\
            .property = "max_revision",\
            .value    = "0",\
        },{\
            .driver   = "vhost-scsi-ccw",\
            .property = "max_revision",\
            .value    = "0",\
        },

static void ccw_machine_2_11_instance_options(MachineState *machine)
{
}

static void ccw_machine_2_11_class_options(MachineClass *mc)
{
}
DEFINE_CCW_MACHINE(2_11, "2.11", true);

static void ccw_machine_2_10_instance_options(MachineState *machine)
{
    ccw_machine_2_11_instance_options(machine);
    if (css_migration_enabled()) {
        css_register_vmstate();
    }
}

static void ccw_machine_2_10_class_options(MachineClass *mc)
{
    ccw_machine_2_11_class_options(mc);
    SET_MACHINE_COMPAT(mc, CCW_COMPAT_2_10);
}
DEFINE_CCW_MACHINE(2_10, "2.10", false);

static void ccw_machine_2_9_instance_options(MachineState *machine)
{
    ccw_machine_2_10_instance_options(machine);
    s390_cpudef_featoff_greater(12, 1, S390_FEAT_ESOP);
    s390_cpudef_featoff_greater(12, 1, S390_FEAT_SIDE_EFFECT_ACCESS_ESOP2);
    s390_cpudef_featoff_greater(12, 1, S390_FEAT_ZPCI);
    s390_cpudef_featoff_greater(12, 1, S390_FEAT_ADAPTER_INT_SUPPRESSION);
    s390_cpudef_featoff_greater(12, 1, S390_FEAT_ADAPTER_EVENT_NOTIFICATION);
}

static void ccw_machine_2_9_class_options(MachineClass *mc)
{
    S390CcwMachineClass *s390mc = S390_MACHINE_CLASS(mc);

    s390mc->gs_allowed = false;
    ccw_machine_2_10_class_options(mc);
    SET_MACHINE_COMPAT(mc, CCW_COMPAT_2_9);
    s390mc->css_migration_enabled = false;
}
DEFINE_CCW_MACHINE(2_9, "2.9", false);

static void ccw_machine_2_8_instance_options(MachineState *machine)
{
    ccw_machine_2_9_instance_options(machine);
}

static void ccw_machine_2_8_class_options(MachineClass *mc)
{
    ccw_machine_2_9_class_options(mc);
    SET_MACHINE_COMPAT(mc, CCW_COMPAT_2_8);
}
DEFINE_CCW_MACHINE(2_8, "2.8", false);

static void ccw_machine_2_7_instance_options(MachineState *machine)
{
    ccw_machine_2_8_instance_options(machine);
}

static void ccw_machine_2_7_class_options(MachineClass *mc)
{
    S390CcwMachineClass *s390mc = S390_MACHINE_CLASS(mc);

    s390mc->cpu_model_allowed = false;
    ccw_machine_2_8_class_options(mc);
    SET_MACHINE_COMPAT(mc, CCW_COMPAT_2_7);
}
DEFINE_CCW_MACHINE(2_7, "2.7", false);

static void ccw_machine_2_6_instance_options(MachineState *machine)
{
    ccw_machine_2_7_instance_options(machine);
}

static void ccw_machine_2_6_class_options(MachineClass *mc)
{
    S390CcwMachineClass *s390mc = S390_MACHINE_CLASS(mc);

    s390mc->ri_allowed = false;
    ccw_machine_2_7_class_options(mc);
    SET_MACHINE_COMPAT(mc, CCW_COMPAT_2_6);
}
DEFINE_CCW_MACHINE(2_6, "2.6", false);

static void ccw_machine_2_5_instance_options(MachineState *machine)
{
    ccw_machine_2_6_instance_options(machine);
}

static void ccw_machine_2_5_class_options(MachineClass *mc)
{
    ccw_machine_2_6_class_options(mc);
    SET_MACHINE_COMPAT(mc, CCW_COMPAT_2_5);
}
DEFINE_CCW_MACHINE(2_5, "2.5", false);

static void ccw_machine_2_4_instance_options(MachineState *machine)
{
    ccw_machine_2_5_instance_options(machine);
}

static void ccw_machine_2_4_class_options(MachineClass *mc)
{
    ccw_machine_2_5_class_options(mc);
    SET_MACHINE_COMPAT(mc, CCW_COMPAT_2_4);
}
DEFINE_CCW_MACHINE(2_4, "2.4", false);

static void ccw_machine_register_types(void)
{
    type_register_static(&ccw_machine_info);
}

type_init(ccw_machine_register_types)
