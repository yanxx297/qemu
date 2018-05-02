#ifndef QEMU_SMBIOS_H
#define QEMU_SMBIOS_H
/*
 * SMBIOS Support
 *
 * Copyright (C) 2009 Hewlett-Packard Development Company, L.P.
 *
 * Authors:
 *  Alex Williamson <alex.williamson@hp.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "qemu/option.h"

#define SMBIOS_MAX_TYPE 127

void smbios_entry_add(QemuOpts *opts);
void smbios_set_defaults(const char *manufacturer, const char *product,
                         const char *version);
uint8_t *smbios_get_table_legacy(size_t *length);

/*
 * SMBIOS spec defined tables
 */

/* SMBIOS entry point (anchor).
 * BIOS must place this at a 16-bit-aligned address between 0xf0000 and 0xfffff.
 */
struct smbios_entry_point {
    uint8_t anchor_string[4];
    uint8_t checksum;
    uint8_t length;
    uint8_t smbios_major_version;
    uint8_t smbios_minor_version;
    uint16_t max_structure_size;
    uint8_t entry_point_revision;
    uint8_t formatted_area[5];
    uint8_t intermediate_anchor_string[5];
    uint8_t intermediate_checksum;
    uint16_t structure_table_length;
    uint32_t structure_table_address;
    uint16_t number_of_structures;
    uint8_t smbios_bcd_revision;
} QEMU_PACKED;

/* This goes at the beginning of every SMBIOS structure. */
struct smbios_structure_header {
    uint8_t type;
    uint8_t length;
    uint16_t handle;
} QEMU_PACKED;

/* SMBIOS type 0 - BIOS Information */
struct smbios_type_0 {
    struct smbios_structure_header header;
    uint8_t vendor_str;
    uint8_t bios_version_str;
    uint16_t bios_starting_address_segment;
    uint8_t bios_release_date_str;
    uint8_t bios_rom_size;
    uint8_t bios_characteristics[8];
    uint8_t bios_characteristics_extension_bytes[2];
    uint8_t system_bios_major_release;
    uint8_t system_bios_minor_release;
    uint8_t embedded_controller_major_release;
    uint8_t embedded_controller_minor_release;
} QEMU_PACKED;

/* SMBIOS type 1 - System Information */
struct smbios_type_1 {
    struct smbios_structure_header header;
    uint8_t manufacturer_str;
    uint8_t product_name_str;
    uint8_t version_str;
    uint8_t serial_number_str;
    uint8_t uuid[16];
    uint8_t wake_up_type;
    uint8_t sku_number_str;
    uint8_t family_str;
} QEMU_PACKED;

/* SMBIOS type 2 - Base Board */
struct smbios_type_2 {
    struct smbios_structure_header header;
    uint8_t manufacturer_str;
    uint8_t product_str;
    uint8_t version_str;
    uint8_t serial_number_str;
    uint8_t asset_tag_number_str;
    uint8_t feature_flags;
    uint8_t location_str;
    uint16_t chassis_handle;
    uint8_t board_type;
    uint8_t contained_element_count;
    /* contained elements follow */
} QEMU_PACKED;

/* SMBIOS type 3 - System Enclosure (v2.7) */
struct smbios_type_3 {
    struct smbios_structure_header header;
    uint8_t manufacturer_str;
    uint8_t type;
    uint8_t version_str;
    uint8_t serial_number_str;
    uint8_t asset_tag_number_str;
    uint8_t boot_up_state;
    uint8_t power_supply_state;
    uint8_t thermal_state;
    uint8_t security_status;
    uint32_t oem_defined;
    uint8_t height;
    uint8_t number_of_power_cords;
    uint8_t contained_element_count;
    uint8_t sku_number_str;
    /* contained elements follow */
} QEMU_PACKED;

/* SMBIOS type 4 - Processor Information (v2.6) */
struct smbios_type_4 {
    struct smbios_structure_header header;
    uint8_t socket_designation_str;
    uint8_t processor_type;
    uint8_t processor_family;
    uint8_t processor_manufacturer_str;
    uint32_t processor_id[2];
    uint8_t processor_version_str;
    uint8_t voltage;
    uint16_t external_clock;
    uint16_t max_speed;
    uint16_t current_speed;
    uint8_t status;
    uint8_t processor_upgrade;
    uint16_t l1_cache_handle;
    uint16_t l2_cache_handle;
    uint16_t l3_cache_handle;
    uint8_t serial_number_str;
    uint8_t asset_tag_number_str;
    uint8_t part_number_str;
    uint8_t core_count;
    uint8_t core_enabled;
    uint8_t thread_count;
    uint16_t processor_characteristics;
    uint16_t processor_family2;
} QEMU_PACKED;

/* SMBIOS type 16 - Physical Memory Array (v2.7) */
struct smbios_type_16 {
    struct smbios_structure_header header;
    uint8_t location;
    uint8_t use;
    uint8_t error_correction;
    uint32_t maximum_capacity;
    uint16_t memory_error_information_handle;
    uint16_t number_of_memory_devices;
    uint64_t extended_maximum_capacity;
} QEMU_PACKED;

/* SMBIOS type 17 - Memory Device (v2.8) */
struct smbios_type_17 {
    struct smbios_structure_header header;
    uint16_t physical_memory_array_handle;
    uint16_t memory_error_information_handle;
    uint16_t total_width;
    uint16_t data_width;
    uint16_t size;
    uint8_t form_factor;
    uint8_t device_set;
    uint8_t device_locator_str;
    uint8_t bank_locator_str;
    uint8_t memory_type;
    uint16_t type_detail;
    uint16_t speed;
    uint8_t manufacturer_str;
    uint8_t serial_number_str;
    uint8_t asset_tag_number_str;
    uint8_t part_number_str;
    uint8_t attributes;
    uint32_t extended_size;
    uint32_t configured_clock_speed;
    uint32_t minimum_voltage;
    uint32_t maximum_voltage;
    uint32_t configured_voltage;
} QEMU_PACKED;

/* SMBIOS type 19 - Memory Array Mapped Address (v2.7) */
struct smbios_type_19 {
    struct smbios_structure_header header;
    uint32_t starting_address;
    uint32_t ending_address;
    uint16_t memory_array_handle;
    uint8_t partition_width;
    uint64_t extended_starting_address;
    uint64_t extended_ending_address;
} QEMU_PACKED;

/* SMBIOS type 32 - System Boot Information */
struct smbios_type_32 {
    struct smbios_structure_header header;
    uint8_t reserved[6];
    uint8_t boot_status;
} QEMU_PACKED;

/* SMBIOS type 127 -- End-of-table */
struct smbios_type_127 {
    struct smbios_structure_header header;
} QEMU_PACKED;

#endif /*QEMU_SMBIOS_H */
