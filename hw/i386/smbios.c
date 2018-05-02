/*
 * SMBIOS Support
 *
 * Copyright (C) 2009 Hewlett-Packard Development Company, L.P.
 * Copyright (C) 2013 Red Hat, Inc.
 *
 * Authors:
 *  Alex Williamson <alex.williamson@hp.com>
 *  Markus Armbruster <armbru@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "hw/i386/pc.h"
#include "hw/i386/smbios.h"
#include "hw/loader.h"


/* legacy structures and constants for <= 2.0 machines */
struct smbios_header {
    uint16_t length;
    uint8_t type;
} QEMU_PACKED;

struct smbios_field {
    struct smbios_header header;
    uint8_t type;
    uint16_t offset;
    uint8_t data[];
} QEMU_PACKED;

struct smbios_table {
    struct smbios_header header;
    uint8_t data[];
} QEMU_PACKED;

#define SMBIOS_FIELD_ENTRY 0
#define SMBIOS_TABLE_ENTRY 1

static uint8_t *smbios_entries;
static size_t smbios_entries_len;
static bool smbios_legacy = true;
/* end: legacy structures & constants for <= 2.0 machines */


static uint8_t *smbios_tables;
static size_t smbios_tables_len;
static unsigned smbios_table_max;
static unsigned smbios_table_cnt;
static struct smbios_entry_point ep;

static int smbios_type4_count = 0;
static bool smbios_immutable;
static bool smbios_have_defaults;
static uint32_t smbios_cpuid_version, smbios_cpuid_features, smbios_smp_sockets;

static DECLARE_BITMAP(have_binfile_bitmap, SMBIOS_MAX_TYPE+1);
static DECLARE_BITMAP(have_fields_bitmap, SMBIOS_MAX_TYPE+1);

static struct {
    const char *vendor, *version, *date;
    bool have_major_minor;
    uint8_t major, minor;
} type0;

static struct {
    const char *manufacturer, *product, *version, *serial, *sku, *family;
    /* uuid is in qemu_uuid[] */
} type1;

static struct {
    const char *manufacturer, *product, *version, *serial, *asset, *location;
} type2;

static struct {
    const char *manufacturer, *version, *serial, *asset, *sku;
} type3;

static struct {
    const char *sock_pfx, *manufacturer, *version, *serial, *asset, *part;
} type4;

static struct {
    const char *loc_pfx, *bank, *manufacturer, *serial, *asset, *part;
} type17;

static QemuOptsList qemu_smbios_opts = {
    .name = "smbios",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_smbios_opts.head),
    .desc = {
        /*
         * no elements => accept any params
         * validation will happen later
         */
        { /* end of list */ }
    }
};

static const QemuOptDesc qemu_smbios_file_opts[] = {
    {
        .name = "file",
        .type = QEMU_OPT_STRING,
        .help = "binary file containing an SMBIOS element",
    },
    { /* end of list */ }
};

static const QemuOptDesc qemu_smbios_type0_opts[] = {
    {
        .name = "type",
        .type = QEMU_OPT_NUMBER,
        .help = "SMBIOS element type",
    },{
        .name = "vendor",
        .type = QEMU_OPT_STRING,
        .help = "vendor name",
    },{
        .name = "version",
        .type = QEMU_OPT_STRING,
        .help = "version number",
    },{
        .name = "date",
        .type = QEMU_OPT_STRING,
        .help = "release date",
    },{
        .name = "release",
        .type = QEMU_OPT_STRING,
        .help = "revision number",
    },
    { /* end of list */ }
};

static const QemuOptDesc qemu_smbios_type1_opts[] = {
    {
        .name = "type",
        .type = QEMU_OPT_NUMBER,
        .help = "SMBIOS element type",
    },{
        .name = "manufacturer",
        .type = QEMU_OPT_STRING,
        .help = "manufacturer name",
    },{
        .name = "product",
        .type = QEMU_OPT_STRING,
        .help = "product name",
    },{
        .name = "version",
        .type = QEMU_OPT_STRING,
        .help = "version number",
    },{
        .name = "serial",
        .type = QEMU_OPT_STRING,
        .help = "serial number",
    },{
        .name = "uuid",
        .type = QEMU_OPT_STRING,
        .help = "UUID",
    },{
        .name = "sku",
        .type = QEMU_OPT_STRING,
        .help = "SKU number",
    },{
        .name = "family",
        .type = QEMU_OPT_STRING,
        .help = "family name",
    },
    { /* end of list */ }
};

static const QemuOptDesc qemu_smbios_type2_opts[] = {
    {
        .name = "type",
        .type = QEMU_OPT_NUMBER,
        .help = "SMBIOS element type",
    },{
        .name = "manufacturer",
        .type = QEMU_OPT_STRING,
        .help = "manufacturer name",
    },{
        .name = "product",
        .type = QEMU_OPT_STRING,
        .help = "product name",
    },{
        .name = "version",
        .type = QEMU_OPT_STRING,
        .help = "version number",
    },{
        .name = "serial",
        .type = QEMU_OPT_STRING,
        .help = "serial number",
    },{
        .name = "asset",
        .type = QEMU_OPT_STRING,
        .help = "asset tag number",
    },{
        .name = "location",
        .type = QEMU_OPT_STRING,
        .help = "location in chassis",
    },
    { /* end of list */ }
};

static const QemuOptDesc qemu_smbios_type3_opts[] = {
    {
        .name = "type",
        .type = QEMU_OPT_NUMBER,
        .help = "SMBIOS element type",
    },{
        .name = "manufacturer",
        .type = QEMU_OPT_STRING,
        .help = "manufacturer name",
    },{
        .name = "version",
        .type = QEMU_OPT_STRING,
        .help = "version number",
    },{
        .name = "serial",
        .type = QEMU_OPT_STRING,
        .help = "serial number",
    },{
        .name = "asset",
        .type = QEMU_OPT_STRING,
        .help = "asset tag number",
    },{
        .name = "sku",
        .type = QEMU_OPT_STRING,
        .help = "SKU number",
    },
    { /* end of list */ }
};

static const QemuOptDesc qemu_smbios_type4_opts[] = {
    {
        .name = "type",
        .type = QEMU_OPT_NUMBER,
        .help = "SMBIOS element type",
    },{
        .name = "sock_pfx",
        .type = QEMU_OPT_STRING,
        .help = "socket designation string prefix",
    },{
        .name = "manufacturer",
        .type = QEMU_OPT_STRING,
        .help = "manufacturer name",
    },{
        .name = "version",
        .type = QEMU_OPT_STRING,
        .help = "version number",
    },{
        .name = "serial",
        .type = QEMU_OPT_STRING,
        .help = "serial number",
    },{
        .name = "asset",
        .type = QEMU_OPT_STRING,
        .help = "asset tag number",
    },{
        .name = "part",
        .type = QEMU_OPT_STRING,
        .help = "part number",
    },
    { /* end of list */ }
};

static const QemuOptDesc qemu_smbios_type17_opts[] = {
    {
        .name = "type",
        .type = QEMU_OPT_NUMBER,
        .help = "SMBIOS element type",
    },{
        .name = "loc_pfx",
        .type = QEMU_OPT_STRING,
        .help = "device locator string prefix",
    },{
        .name = "bank",
        .type = QEMU_OPT_STRING,
        .help = "bank locator string",
    },{
        .name = "manufacturer",
        .type = QEMU_OPT_STRING,
        .help = "manufacturer name",
    },{
        .name = "serial",
        .type = QEMU_OPT_STRING,
        .help = "serial number",
    },{
        .name = "asset",
        .type = QEMU_OPT_STRING,
        .help = "asset tag number",
    },{
        .name = "part",
        .type = QEMU_OPT_STRING,
        .help = "part number",
    },
    { /* end of list */ }
};

static void smbios_register_config(void)
{
    qemu_add_opts(&qemu_smbios_opts);
}

machine_init(smbios_register_config);

static void smbios_validate_table(void)
{
    uint32_t expect_t4_count = smbios_legacy ? smp_cpus : smbios_smp_sockets;

    if (smbios_type4_count && smbios_type4_count != expect_t4_count) {
        error_report("Expected %d SMBIOS Type 4 tables, got %d instead",
                     expect_t4_count, smbios_type4_count);
        exit(1);
    }
}


/* legacy setup functions for <= 2.0 machines */
static void smbios_add_field(int type, int offset, const void *data, size_t len)
{
    struct smbios_field *field;

    if (!smbios_entries) {
        smbios_entries_len = sizeof(uint16_t);
        smbios_entries = g_malloc0(smbios_entries_len);
    }
    smbios_entries = g_realloc(smbios_entries, smbios_entries_len +
                                                  sizeof(*field) + len);
    field = (struct smbios_field *)(smbios_entries + smbios_entries_len);
    field->header.type = SMBIOS_FIELD_ENTRY;
    field->header.length = cpu_to_le16(sizeof(*field) + len);

    field->type = type;
    field->offset = cpu_to_le16(offset);
    memcpy(field->data, data, len);

    smbios_entries_len += sizeof(*field) + len;
    (*(uint16_t *)smbios_entries) =
            cpu_to_le16(le16_to_cpu(*(uint16_t *)smbios_entries) + 1);
}

static void smbios_maybe_add_str(int type, int offset, const char *data)
{
    if (data) {
        smbios_add_field(type, offset, data, strlen(data) + 1);
    }
}

static void smbios_build_type_0_fields(void)
{
    smbios_maybe_add_str(0, offsetof(struct smbios_type_0, vendor_str),
                         type0.vendor);
    smbios_maybe_add_str(0, offsetof(struct smbios_type_0, bios_version_str),
                         type0.version);
    smbios_maybe_add_str(0, offsetof(struct smbios_type_0,
                                     bios_release_date_str),
                         type0.date);
    if (type0.have_major_minor) {
        smbios_add_field(0, offsetof(struct smbios_type_0,
                                     system_bios_major_release),
                         &type0.major, 1);
        smbios_add_field(0, offsetof(struct smbios_type_0,
                                     system_bios_minor_release),
                         &type0.minor, 1);
    }
}

static void smbios_build_type_1_fields(void)
{
    smbios_maybe_add_str(1, offsetof(struct smbios_type_1, manufacturer_str),
                         type1.manufacturer);
    smbios_maybe_add_str(1, offsetof(struct smbios_type_1, product_name_str),
                         type1.product);
    smbios_maybe_add_str(1, offsetof(struct smbios_type_1, version_str),
                         type1.version);
    smbios_maybe_add_str(1, offsetof(struct smbios_type_1, serial_number_str),
                         type1.serial);
    smbios_maybe_add_str(1, offsetof(struct smbios_type_1, sku_number_str),
                         type1.sku);
    smbios_maybe_add_str(1, offsetof(struct smbios_type_1, family_str),
                         type1.family);
    if (qemu_uuid_set) {
        smbios_add_field(1, offsetof(struct smbios_type_1, uuid),
                         qemu_uuid, 16);
    }
}

uint8_t *smbios_get_table_legacy(size_t *length)
{
    if (!smbios_legacy) {
        *length = 0;
        return NULL;
    }

    if (!smbios_immutable) {
        smbios_build_type_0_fields();
        smbios_build_type_1_fields();
        smbios_validate_table();
        smbios_immutable = true;
    }
    *length = smbios_entries_len;
    return smbios_entries;
}
/* end: legacy setup functions for <= 2.0 machines */


static bool smbios_skip_table(uint8_t type, bool required_table)
{
    if (test_bit(type, have_binfile_bitmap)) {
        return true; /* user provided their own binary blob(s) */
    }
    if (test_bit(type, have_fields_bitmap)) {
        return false; /* user provided fields via command line */
    }
    if (smbios_have_defaults && required_table) {
        return false; /* we're building tables, and this one's required */
    }
    return true;
}

#define SMBIOS_BUILD_TABLE_PRE(tbl_type, tbl_handle, tbl_required)        \
    struct smbios_type_##tbl_type *t;                                     \
    size_t t_off; /* table offset into smbios_tables */                   \
    int str_index = 0;                                                    \
    do {                                                                  \
        /* should we skip building this table ? */                        \
        if (smbios_skip_table(tbl_type, tbl_required)) {                  \
            return;                                                       \
        }                                                                 \
                                                                          \
        /* use offset of table t within smbios_tables */                  \
        /* (pointer must be updated after each realloc) */                \
        t_off = smbios_tables_len;                                        \
        smbios_tables_len += sizeof(*t);                                  \
        smbios_tables = g_realloc(smbios_tables, smbios_tables_len);      \
        t = (struct smbios_type_##tbl_type *)(smbios_tables + t_off);     \
                                                                          \
        t->header.type = tbl_type;                                        \
        t->header.length = sizeof(*t);                                    \
        t->header.handle = tbl_handle;                                    \
    } while (0)

#define SMBIOS_TABLE_SET_STR(tbl_type, field, value)                      \
    do {                                                                  \
        int len = (value != NULL) ? strlen(value) + 1 : 0;                \
        if (len > 1) {                                                    \
            smbios_tables = g_realloc(smbios_tables,                      \
                                      smbios_tables_len + len);           \
            memcpy(smbios_tables + smbios_tables_len, value, len);        \
            smbios_tables_len += len;                                     \
            /* update pointer post-realloc */                             \
            t = (struct smbios_type_##tbl_type *)(smbios_tables + t_off); \
            t->field = ++str_index;                                       \
        } else {                                                          \
            t->field = 0;                                                 \
        }                                                                 \
    } while (0)

#define SMBIOS_BUILD_TABLE_POST                                           \
    do {                                                                  \
        size_t term_cnt, t_size;                                          \
                                                                          \
        /* add '\0' terminator (add two if no strings defined) */         \
        term_cnt = (str_index == 0) ? 2 : 1;                              \
        smbios_tables = g_realloc(smbios_tables,                          \
                                  smbios_tables_len + term_cnt);          \
        memset(smbios_tables + smbios_tables_len, 0, term_cnt);           \
        smbios_tables_len += term_cnt;                                    \
                                                                          \
        /* update smbios max. element size */                             \
        t_size = smbios_tables_len - t_off;                               \
        if (t_size > smbios_table_max) {                                  \
            smbios_table_max = t_size;                                    \
        }                                                                 \
                                                                          \
        /* update smbios element count */                                 \
        smbios_table_cnt++;                                               \
    } while (0)

static void smbios_build_type_0_table(void)
{
    SMBIOS_BUILD_TABLE_PRE(0, 0x000, false); /* optional, leave up to BIOS */

    SMBIOS_TABLE_SET_STR(0, vendor_str, type0.vendor);
    SMBIOS_TABLE_SET_STR(0, bios_version_str, type0.version);

    t->bios_starting_address_segment = 0xE800; /* hardcoded in SeaBIOS */

    SMBIOS_TABLE_SET_STR(0, bios_release_date_str, type0.date);

    t->bios_rom_size = 0; /* hardcoded in SeaBIOS with FIXME comment */

    /* BIOS characteristics not supported */
    memset(t->bios_characteristics, 0, 8);
    t->bios_characteristics[0] = 0x08;

    /* Enable targeted content distribution (needed for SVVP, per SeaBIOS) */
    t->bios_characteristics_extension_bytes[0] = 0;
    t->bios_characteristics_extension_bytes[1] = 4;

    if (type0.have_major_minor) {
        t->system_bios_major_release = type0.major;
        t->system_bios_minor_release = type0.minor;
    } else {
        t->system_bios_major_release = 0;
        t->system_bios_minor_release = 0;
    }

    /* hardcoded in SeaBIOS */
    t->embedded_controller_major_release = 0xFF;
    t->embedded_controller_minor_release = 0xFF;

    SMBIOS_BUILD_TABLE_POST;
}

static void smbios_build_type_1_table(void)
{
    SMBIOS_BUILD_TABLE_PRE(1, 0x100, true); /* required */

    SMBIOS_TABLE_SET_STR(1, manufacturer_str, type1.manufacturer);
    SMBIOS_TABLE_SET_STR(1, product_name_str, type1.product);
    SMBIOS_TABLE_SET_STR(1, version_str, type1.version);
    SMBIOS_TABLE_SET_STR(1, serial_number_str, type1.serial);
    if (qemu_uuid_set) {
        memcpy(t->uuid, qemu_uuid, 16);
    } else {
        memset(t->uuid, 0, 16);
    }
    t->wake_up_type = 0x06; /* power switch */
    SMBIOS_TABLE_SET_STR(1, sku_number_str, type1.sku);
    SMBIOS_TABLE_SET_STR(1, family_str, type1.family);

    SMBIOS_BUILD_TABLE_POST;
}

static void smbios_build_type_2_table(void)
{
    SMBIOS_BUILD_TABLE_PRE(2, 0x200, false); /* optional */

    SMBIOS_TABLE_SET_STR(2, manufacturer_str, type2.manufacturer);
    SMBIOS_TABLE_SET_STR(2, product_str, type2.product);
    SMBIOS_TABLE_SET_STR(2, version_str, type2.version);
    SMBIOS_TABLE_SET_STR(2, serial_number_str, type2.serial);
    SMBIOS_TABLE_SET_STR(2, asset_tag_number_str, type2.asset);
    t->feature_flags = 0x01; /* Motherboard */
    SMBIOS_TABLE_SET_STR(2, location_str, type2.location);
    t->chassis_handle = 0x300; /* Type 3 (System enclosure) */
    t->board_type = 0x0A; /* Motherboard */
    t->contained_element_count = 0;

    SMBIOS_BUILD_TABLE_POST;
}

static void smbios_build_type_3_table(void)
{
    SMBIOS_BUILD_TABLE_PRE(3, 0x300, true); /* required */

    SMBIOS_TABLE_SET_STR(3, manufacturer_str, type3.manufacturer);
    t->type = 0x01; /* Other */
    SMBIOS_TABLE_SET_STR(3, version_str, type3.version);
    SMBIOS_TABLE_SET_STR(3, serial_number_str, type3.serial);
    SMBIOS_TABLE_SET_STR(3, asset_tag_number_str, type3.asset);
    t->boot_up_state = 0x03; /* Safe */
    t->power_supply_state = 0x03; /* Safe */
    t->thermal_state = 0x03; /* Safe */
    t->security_status = 0x02; /* Unknown */
    t->oem_defined = 0;
    t->height = 0;
    t->number_of_power_cords = 0;
    t->contained_element_count = 0;
    SMBIOS_TABLE_SET_STR(3, sku_number_str, type3.sku);

    SMBIOS_BUILD_TABLE_POST;
}

static void smbios_build_type_4_table(unsigned instance)
{
    char sock_str[128];

    SMBIOS_BUILD_TABLE_PRE(4, 0x400 + instance, true); /* required */

    snprintf(sock_str, sizeof(sock_str), "%s%2x", type4.sock_pfx, instance);
    SMBIOS_TABLE_SET_STR(4, socket_designation_str, sock_str);
    t->processor_type = 0x03; /* CPU */
    SMBIOS_TABLE_SET_STR(4, processor_manufacturer_str, type4.manufacturer);
    t->processor_id[0] = smbios_cpuid_version;
    t->processor_id[1] = smbios_cpuid_features;
    SMBIOS_TABLE_SET_STR(4, processor_version_str, type4.version);
    t->voltage = 0;
    t->external_clock = 0; /* Unknown */
    t->max_speed = 0; /* Unknown */
    t->current_speed = 0; /* Unknown */
    t->status = 0x41; /* Socket populated, CPU enabled */
    t->processor_upgrade = 0x01; /* Other */
    t->l1_cache_handle = 0xFFFF; /* N/A */
    t->l2_cache_handle = 0xFFFF; /* N/A */
    t->l3_cache_handle = 0xFFFF; /* N/A */
    SMBIOS_TABLE_SET_STR(4, serial_number_str, type4.serial);
    SMBIOS_TABLE_SET_STR(4, asset_tag_number_str, type4.asset);
    SMBIOS_TABLE_SET_STR(4, part_number_str, type4.part);
    t->core_count = t->core_enabled = smp_cores;
    t->thread_count = smp_threads;
    t->processor_characteristics = 0x02; /* Unknown */
    t->processor_family = t->processor_family2 = 0x01; /* Other */

    SMBIOS_BUILD_TABLE_POST;
    smbios_type4_count++;
}

#define ONE_KB ((ram_addr_t)1 << 10)
#define ONE_MB ((ram_addr_t)1 << 20)
#define ONE_GB ((ram_addr_t)1 << 30)

#define MAX_T16_STD_SZ 0x80000000 /* 2T in Kilobytes */

static void smbios_build_type_16_table(unsigned dimm_cnt)
{
    ram_addr_t size_kb;

    SMBIOS_BUILD_TABLE_PRE(16, 0x1000, true); /* required */

    t->location = 0x01; /* Other */
    t->use = 0x03; /* System memory */
    t->error_correction = 0x06; /* Multi-bit ECC (for Microsoft, per SeaBIOS) */
    size_kb = QEMU_ALIGN_UP(ram_size, ONE_KB) / ONE_KB;
    if (size_kb < MAX_T16_STD_SZ) {
        t->maximum_capacity = size_kb;
        t->extended_maximum_capacity = 0;
    } else {
        t->maximum_capacity = MAX_T16_STD_SZ;
        t->extended_maximum_capacity = ram_size;
    }
    t->memory_error_information_handle = 0xFFFE; /* Not provided */
    t->number_of_memory_devices = dimm_cnt;

    SMBIOS_BUILD_TABLE_POST;
}

#define MAX_T17_STD_SZ 0x7FFF /* (32G - 1M), in Megabytes */
#define MAX_T17_EXT_SZ 0x80000000 /* 2P, in Megabytes */

static void smbios_build_type_17_table(unsigned instance, ram_addr_t size)
{
    char loc_str[128];
    ram_addr_t size_mb;

    SMBIOS_BUILD_TABLE_PRE(17, 0x1100 + instance, true); /* required */

    t->physical_memory_array_handle = 0x1000; /* Type 16 (Phys. Mem. Array) */
    t->memory_error_information_handle = 0xFFFE; /* Not provided */
    t->total_width = 0xFFFF; /* Unknown */
    t->data_width = 0xFFFF; /* Unknown */
    size_mb = QEMU_ALIGN_UP(size, ONE_MB) / ONE_MB;
    if (size_mb < MAX_T17_STD_SZ) {
        t->size = size_mb;
        t->extended_size = 0;
    } else {
        assert(size_mb < MAX_T17_EXT_SZ);
        t->size = MAX_T17_STD_SZ;
        t->extended_size = size_mb;
    }
    t->form_factor = 0x09; /* DIMM */
    t->device_set = 0; /* Not in a set */
    snprintf(loc_str, sizeof(loc_str), "%s %d", type17.loc_pfx, instance);
    SMBIOS_TABLE_SET_STR(17, device_locator_str, loc_str);
    SMBIOS_TABLE_SET_STR(17, bank_locator_str, type17.bank);
    t->memory_type = 0x07; /* RAM */
    t->type_detail = 0x02; /* Other */
    t->speed = 0; /* Unknown */
    SMBIOS_TABLE_SET_STR(17, manufacturer_str, type17.manufacturer);
    SMBIOS_TABLE_SET_STR(17, serial_number_str, type17.serial);
    SMBIOS_TABLE_SET_STR(17, asset_tag_number_str, type17.asset);
    SMBIOS_TABLE_SET_STR(17, part_number_str, type17.part);
    t->attributes = 0; /* Unknown */
    t->configured_clock_speed = 0; /* Unknown */
    t->minimum_voltage = 0; /* Unknown */
    t->maximum_voltage = 0; /* Unknown */
    t->configured_voltage = 0; /* Unknown */

    SMBIOS_BUILD_TABLE_POST;
}

static void smbios_build_type_19_table(unsigned instance,
                                       ram_addr_t start, ram_addr_t size)
{
    ram_addr_t end, start_kb, end_kb;

    SMBIOS_BUILD_TABLE_PRE(19, 0x1300 + instance, true); /* required */

    end = start + size - 1;
    assert(end > start);
    start_kb = start / ONE_KB;
    end_kb = end / ONE_KB;
    if (start_kb < UINT32_MAX && end_kb < UINT32_MAX) {
        t->starting_address = start_kb;
        t->ending_address = end_kb;
        t->extended_starting_address = t->extended_ending_address = 0;
    } else {
        t->starting_address = t->ending_address = UINT32_MAX;
        t->extended_starting_address = start;
        t->extended_ending_address = end;
    }
    t->memory_array_handle = 0x1000; /* Type 16 (Phys. Mem. Array) */
    t->partition_width = 1; /* One device per row */

    SMBIOS_BUILD_TABLE_POST;
}

static void smbios_build_type_32_table(void)
{
    SMBIOS_BUILD_TABLE_PRE(32, 0x2000, true); /* required */

    memset(t->reserved, 0, 6);
    t->boot_status = 0; /* No errors detected */

    SMBIOS_BUILD_TABLE_POST;
}

static void smbios_build_type_127_table(void)
{
    SMBIOS_BUILD_TABLE_PRE(127, 0x7F00, true); /* required */
    SMBIOS_BUILD_TABLE_POST;
}

void smbios_set_cpuid(uint32_t version, uint32_t features)
{
    smbios_cpuid_version = version;
    smbios_cpuid_features = features;
}

#define SMBIOS_SET_DEFAULT(field, value)                                  \
    if (!field) {                                                         \
        field = value;                                                    \
    }

#define G_FREE_UNLESS_NULL(ptr)                                           \
    if (ptr != NULL) {                                                    \
        g_free(ptr);                                                      \
    }

void smbios_set_defaults(const char *manufacturer, const char *product,
                         const char *version, bool legacy_mode)
{
    smbios_have_defaults = true;
    smbios_legacy = legacy_mode;

    /* drop unwanted version of command-line file blob(s) */
    if (smbios_legacy) {
        G_FREE_UNLESS_NULL(smbios_tables);
        /* in legacy mode, also complain if fields were given for types > 1 */
        if (find_next_bit(have_fields_bitmap,
                          SMBIOS_MAX_TYPE+1, 2) < SMBIOS_MAX_TYPE+1) {
            error_report("can't process fields for smbios "
                         "types > 1 on machine versions < 2.1!");
            exit(1);
        }
    } else {
        G_FREE_UNLESS_NULL(smbios_entries);
    }

    SMBIOS_SET_DEFAULT(type1.manufacturer, manufacturer);
    SMBIOS_SET_DEFAULT(type1.product, product);
    SMBIOS_SET_DEFAULT(type1.version, version);
    SMBIOS_SET_DEFAULT(type2.manufacturer, manufacturer);
    SMBIOS_SET_DEFAULT(type2.product, product);
    SMBIOS_SET_DEFAULT(type2.version, version);
    SMBIOS_SET_DEFAULT(type3.manufacturer, manufacturer);
    SMBIOS_SET_DEFAULT(type3.version, version);
    SMBIOS_SET_DEFAULT(type4.sock_pfx, "CPU");
    SMBIOS_SET_DEFAULT(type4.manufacturer, manufacturer);
    SMBIOS_SET_DEFAULT(type4.version, version);
    SMBIOS_SET_DEFAULT(type17.loc_pfx, "DIMM");
    SMBIOS_SET_DEFAULT(type17.manufacturer, manufacturer);
}

static void smbios_entry_point_setup(void)
{
    memcpy(ep.anchor_string, "_SM_", 4);
    memcpy(ep.intermediate_anchor_string, "_DMI_", 5);
    ep.length = sizeof(struct smbios_entry_point);
    ep.entry_point_revision = 0; /* formatted_area reserved, per spec v2.1+ */
    memset(ep.formatted_area, 0, 5);

    /* compliant with smbios spec v2.8 */
    ep.smbios_major_version = 2;
    ep.smbios_minor_version = 8;
    ep.smbios_bcd_revision = 0x28;

    /* set during table construction, but BIOS may override: */
    ep.structure_table_length = smbios_tables_len;
    ep.max_structure_size = smbios_table_max;
    ep.number_of_structures = smbios_table_cnt;

    /* BIOS must recalculate: */
    ep.checksum = 0;
    ep.intermediate_checksum = 0;
    ep.structure_table_address = 0; /* where BIOS has copied smbios_tables */
}

void smbios_get_tables(uint8_t **tables, size_t *tables_len,
                       uint8_t **anchor, size_t *anchor_len)
{
    unsigned i, dimm_cnt, instance;

    if (smbios_legacy) {
        *tables = *anchor = NULL;
        *tables_len = *anchor_len = 0;
        return;
    }

    if (!smbios_immutable) {
        smbios_build_type_0_table();
        smbios_build_type_1_table();
        smbios_build_type_2_table();
        smbios_build_type_3_table();

        smbios_smp_sockets = smp_cpus / (smp_cores * smp_threads);
        assert(smbios_smp_sockets >= 1);

        for (i = 0; i < smbios_smp_sockets; i++) {
            smbios_build_type_4_table(i);
        }

#define MAX_DIMM_SZ (16ll * ONE_GB)
#define GET_DIMM_SZ ((i < dimm_cnt - 1) ? MAX_DIMM_SZ : ram_size % MAX_DIMM_SZ)

        dimm_cnt = QEMU_ALIGN_UP(ram_size, MAX_DIMM_SZ) / MAX_DIMM_SZ;

        smbios_build_type_16_table(dimm_cnt);

        for (i = 0; i < dimm_cnt; i++) {
            smbios_build_type_17_table(i, GET_DIMM_SZ);
        }

        for (i = 0, instance = 0; i < e820_get_num_entries(); i++) {
            uint64_t address, length;
            if (e820_get_entry(i, E820_RAM, &address, &length)) {
                smbios_build_type_19_table(instance++, address, length);
            }
        }

        smbios_build_type_32_table();
        smbios_build_type_127_table();

        smbios_validate_table();
        smbios_entry_point_setup();
        smbios_immutable = true;
    }

    /* return tables blob and entry point (anchor), and their sizes */
    *tables = smbios_tables;
    *tables_len = smbios_tables_len;
    *anchor = (uint8_t *)&ep;
    *anchor_len = sizeof(struct smbios_entry_point);
}

static void save_opt(const char **dest, QemuOpts *opts, const char *name)
{
    const char *val = qemu_opt_get(opts, name);

    if (val) {
        *dest = val;
    }
}

void smbios_entry_add(QemuOpts *opts)
{
    Error *local_err = NULL;
    const char *val;

    assert(!smbios_immutable);

    val = qemu_opt_get(opts, "file");
    if (val) {
        struct smbios_structure_header *header;
        int size;
        struct smbios_table *table; /* legacy mode only */

        qemu_opts_validate(opts, qemu_smbios_file_opts, &local_err);
        if (local_err) {
            error_report("%s", error_get_pretty(local_err));
            exit(1);
        }

        size = get_image_size(val);
        if (size == -1 || size < sizeof(struct smbios_structure_header)) {
            error_report("Cannot read SMBIOS file %s", val);
            exit(1);
        }

        /*
         * NOTE: standard double '\0' terminator expected, per smbios spec.
         * (except in legacy mode, where the second '\0' is implicit and
         *  will be inserted by the BIOS).
         */
        smbios_tables = g_realloc(smbios_tables, smbios_tables_len + size);
        header = (struct smbios_structure_header *)(smbios_tables +
                                                    smbios_tables_len);

        if (load_image(val, (uint8_t *)header) != size) {
            error_report("Failed to load SMBIOS file %s", val);
            exit(1);
        }

        if (test_bit(header->type, have_fields_bitmap)) {
            error_report("can't load type %d struct, fields already specified!",
                         header->type);
            exit(1);
        }
        set_bit(header->type, have_binfile_bitmap);

        if (header->type == 4) {
            smbios_type4_count++;
        }

        smbios_tables_len += size;
        if (size > smbios_table_max) {
            smbios_table_max = size;
        }
        smbios_table_cnt++;

        /* add a copy of the newly loaded blob to legacy smbios_entries */
        /* NOTE: This code runs before smbios_set_defaults(), so we don't
         *       yet know which mode (legacy vs. aggregate-table) will be
         *       required. We therefore add the binary blob to both legacy
         *       (smbios_entries) and aggregate (smbios_tables) tables, and
         *       delete the one we don't need from smbios_set_defaults(),
         *       once we know which machine version has been requested.
         */
        if (!smbios_entries) {
            smbios_entries_len = sizeof(uint16_t);
            smbios_entries = g_malloc0(smbios_entries_len);
        }
        smbios_entries = g_realloc(smbios_entries, smbios_entries_len +
                                                   size + sizeof(*table));
        table = (struct smbios_table *)(smbios_entries + smbios_entries_len);
        table->header.type = SMBIOS_TABLE_ENTRY;
        table->header.length = cpu_to_le16(sizeof(*table) + size);
        memcpy(table->data, header, size);
        smbios_entries_len += sizeof(*table) + size;
        (*(uint16_t *)smbios_entries) =
                cpu_to_le16(le16_to_cpu(*(uint16_t *)smbios_entries) + 1);
        /* end: add a copy of the newly loaded blob to legacy smbios_entries */

        return;
    }

    val = qemu_opt_get(opts, "type");
    if (val) {
        unsigned long type = strtoul(val, NULL, 0);

        if (type > SMBIOS_MAX_TYPE) {
            error_report("out of range!");
            exit(1);
        }

        if (test_bit(type, have_binfile_bitmap)) {
            error_report("can't add fields, binary file already loaded!");
            exit(1);
        }
        set_bit(type, have_fields_bitmap);

        switch (type) {
        case 0:
            qemu_opts_validate(opts, qemu_smbios_type0_opts, &local_err);
            if (local_err) {
                error_report("%s", error_get_pretty(local_err));
                exit(1);
            }
            save_opt(&type0.vendor, opts, "vendor");
            save_opt(&type0.version, opts, "version");
            save_opt(&type0.date, opts, "date");

            val = qemu_opt_get(opts, "release");
            if (val) {
                if (sscanf(val, "%hhu.%hhu", &type0.major, &type0.minor) != 2) {
                    error_report("Invalid release");
                    exit(1);
                }
                type0.have_major_minor = true;
            }
            return;
        case 1:
            qemu_opts_validate(opts, qemu_smbios_type1_opts, &local_err);
            if (local_err) {
                error_report("%s", error_get_pretty(local_err));
                exit(1);
            }
            save_opt(&type1.manufacturer, opts, "manufacturer");
            save_opt(&type1.product, opts, "product");
            save_opt(&type1.version, opts, "version");
            save_opt(&type1.serial, opts, "serial");
            save_opt(&type1.sku, opts, "sku");
            save_opt(&type1.family, opts, "family");

            val = qemu_opt_get(opts, "uuid");
            if (val) {
                if (qemu_uuid_parse(val, qemu_uuid) != 0) {
                    error_report("Invalid UUID");
                    exit(1);
                }
                qemu_uuid_set = true;
            }
            return;
        case 2:
            qemu_opts_validate(opts, qemu_smbios_type2_opts, &local_err);
            if (local_err) {
                error_report("%s", error_get_pretty(local_err));
                exit(1);
            }
            save_opt(&type2.manufacturer, opts, "manufacturer");
            save_opt(&type2.product, opts, "product");
            save_opt(&type2.version, opts, "version");
            save_opt(&type2.serial, opts, "serial");
            save_opt(&type2.asset, opts, "asset");
            save_opt(&type2.location, opts, "location");
            return;
        case 3:
            qemu_opts_validate(opts, qemu_smbios_type3_opts, &local_err);
            if (local_err) {
                error_report("%s", error_get_pretty(local_err));
                exit(1);
            }
            save_opt(&type3.manufacturer, opts, "manufacturer");
            save_opt(&type3.version, opts, "version");
            save_opt(&type3.serial, opts, "serial");
            save_opt(&type3.asset, opts, "asset");
            save_opt(&type3.sku, opts, "sku");
            return;
        case 4:
            qemu_opts_validate(opts, qemu_smbios_type4_opts, &local_err);
            if (local_err) {
                error_report("%s", error_get_pretty(local_err));
                exit(1);
            }
            save_opt(&type4.sock_pfx, opts, "sock_pfx");
            save_opt(&type4.manufacturer, opts, "manufacturer");
            save_opt(&type4.version, opts, "version");
            save_opt(&type4.serial, opts, "serial");
            save_opt(&type4.asset, opts, "asset");
            save_opt(&type4.part, opts, "part");
            return;
        case 17:
            qemu_opts_validate(opts, qemu_smbios_type17_opts, &local_err);
            if (local_err) {
                error_report("%s", error_get_pretty(local_err));
                exit(1);
            }
            save_opt(&type17.loc_pfx, opts, "loc_pfx");
            save_opt(&type17.bank, opts, "bank");
            save_opt(&type17.manufacturer, opts, "manufacturer");
            save_opt(&type17.serial, opts, "serial");
            save_opt(&type17.asset, opts, "asset");
            save_opt(&type17.part, opts, "part");
            return;
        default:
            error_report("Don't know how to build fields for SMBIOS type %ld",
                         type);
            exit(1);
        }
    }

    error_report("Must specify type= or file=");
    exit(1);
}
