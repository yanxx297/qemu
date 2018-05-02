/*
 * Block driver for Hyper-V VHDX Images
 *
 * Copyright (c) 2013 Red Hat, Inc.,
 *
 * Authors:
 *  Jeff Cody <jcody@redhat.com>
 *
 *  This is based on the "VHDX Format Specification v1.00", published 8/25/2012
 *  by Microsoft:
 *      https://www.microsoft.com/en-us/download/details.aspx?id=34750
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qemu-common.h"
#include "block/block_int.h"
#include "qemu/module.h"
#include "qemu/crc32c.h"
#include "block/vhdx.h"
#include "migration/migration.h"

#include <uuid/uuid.h>
#include <glib.h>

/* Options for VHDX creation */

#define VHDX_BLOCK_OPT_LOG_SIZE   "log_size"
#define VHDX_BLOCK_OPT_BLOCK_SIZE "block_size"
#define VHDX_BLOCK_OPT_ZERO "block_state_zero"

typedef enum VHDXImageType {
    VHDX_TYPE_DYNAMIC = 0,
    VHDX_TYPE_FIXED,
    VHDX_TYPE_DIFFERENCING,   /* Currently unsupported */
} VHDXImageType;

/* Several metadata and region table data entries are identified by
 * guids in  a MS-specific GUID format. */


/* ------- Known Region Table GUIDs ---------------------- */
static const MSGUID bat_guid =      { .data1 = 0x2dc27766,
                                      .data2 = 0xf623,
                                      .data3 = 0x4200,
                                      .data4 = { 0x9d, 0x64, 0x11, 0x5e,
                                                 0x9b, 0xfd, 0x4a, 0x08} };

static const MSGUID metadata_guid = { .data1 = 0x8b7ca206,
                                      .data2 = 0x4790,
                                      .data3 = 0x4b9a,
                                      .data4 = { 0xb8, 0xfe, 0x57, 0x5f,
                                                 0x05, 0x0f, 0x88, 0x6e} };



/* ------- Known Metadata Entry GUIDs ---------------------- */
static const MSGUID file_param_guid =   { .data1 = 0xcaa16737,
                                          .data2 = 0xfa36,
                                          .data3 = 0x4d43,
                                          .data4 = { 0xb3, 0xb6, 0x33, 0xf0,
                                                     0xaa, 0x44, 0xe7, 0x6b} };

static const MSGUID virtual_size_guid = { .data1 = 0x2FA54224,
                                          .data2 = 0xcd1b,
                                          .data3 = 0x4876,
                                          .data4 = { 0xb2, 0x11, 0x5d, 0xbe,
                                                     0xd8, 0x3b, 0xf4, 0xb8} };

static const MSGUID page83_guid =       { .data1 = 0xbeca12ab,
                                          .data2 = 0xb2e6,
                                          .data3 = 0x4523,
                                          .data4 = { 0x93, 0xef, 0xc3, 0x09,
                                                     0xe0, 0x00, 0xc7, 0x46} };


static const MSGUID phys_sector_guid =  { .data1 = 0xcda348c7,
                                          .data2 = 0x445d,
                                          .data3 = 0x4471,
                                          .data4 = { 0x9c, 0xc9, 0xe9, 0x88,
                                                     0x52, 0x51, 0xc5, 0x56} };

static const MSGUID parent_locator_guid = { .data1 = 0xa8d35f2d,
                                            .data2 = 0xb30b,
                                            .data3 = 0x454d,
                                            .data4 = { 0xab, 0xf7, 0xd3,
                                                       0xd8, 0x48, 0x34,
                                                       0xab, 0x0c} };

static const MSGUID logical_sector_guid = { .data1 = 0x8141bf1d,
                                            .data2 = 0xa96f,
                                            .data3 = 0x4709,
                                            .data4 = { 0xba, 0x47, 0xf2,
                                                       0x33, 0xa8, 0xfa,
                                                       0xab, 0x5f} };

/* Each parent type must have a valid GUID; this is for parent images
 * of type 'VHDX'.  If we were to allow e.g. a QCOW2 parent, we would
 * need to make up our own QCOW2 GUID type */
static const MSGUID parent_vhdx_guid = { .data1 = 0xb04aefb7,
                                         .data2 = 0xd19e,
                                         .data3 = 0x4a81,
                                         .data4 = { 0xb7, 0x89, 0x25, 0xb8,
                                                    0xe9, 0x44, 0x59, 0x13} };


#define META_FILE_PARAMETER_PRESENT      0x01
#define META_VIRTUAL_DISK_SIZE_PRESENT   0x02
#define META_PAGE_83_PRESENT             0x04
#define META_LOGICAL_SECTOR_SIZE_PRESENT 0x08
#define META_PHYS_SECTOR_SIZE_PRESENT    0x10
#define META_PARENT_LOCATOR_PRESENT      0x20

#define META_ALL_PRESENT    \
    (META_FILE_PARAMETER_PRESENT | META_VIRTUAL_DISK_SIZE_PRESENT | \
     META_PAGE_83_PRESENT | META_LOGICAL_SECTOR_SIZE_PRESENT | \
     META_PHYS_SECTOR_SIZE_PRESENT)


typedef struct VHDXSectorInfo {
    uint32_t bat_idx;       /* BAT entry index */
    uint32_t sectors_avail; /* sectors available in payload block */
    uint32_t bytes_left;    /* bytes left in the block after data to r/w */
    uint32_t bytes_avail;   /* bytes available in payload block */
    uint64_t file_offset;   /* absolute offset in bytes, in file */
    uint64_t block_offset;  /* block offset, in bytes */
} VHDXSectorInfo;

/* Calculates new checksum.
 *
 * Zero is substituted during crc calculation for the original crc field
 * crc_offset: byte offset in buf of the buffer crc
 * buf: buffer pointer
 * size: size of buffer (must be > crc_offset+4)
 *
 * Note: The resulting checksum is in the CPU endianness, not necessarily
 *       in the file format endianness (LE).  Any header export to disk should
 *       make sure that vhdx_header_le_export() is used to convert to the
 *       correct endianness
 */
uint32_t vhdx_update_checksum(uint8_t *buf, size_t size, int crc_offset)
{
    uint32_t crc;

    assert(buf != NULL);
    assert(size > (crc_offset + sizeof(crc)));

    memset(buf + crc_offset, 0, sizeof(crc));
    crc =  crc32c(0xffffffff, buf, size);
    memcpy(buf + crc_offset, &crc, sizeof(crc));

    return crc;
}

uint32_t vhdx_checksum_calc(uint32_t crc, uint8_t *buf, size_t size,
                            int crc_offset)
{
    uint32_t crc_new;
    uint32_t crc_orig;
    assert(buf != NULL);

    if (crc_offset > 0) {
        memcpy(&crc_orig, buf + crc_offset, sizeof(crc_orig));
        memset(buf + crc_offset, 0, sizeof(crc_orig));
    }

    crc_new = crc32c(crc, buf, size);
    if (crc_offset > 0) {
        memcpy(buf + crc_offset, &crc_orig, sizeof(crc_orig));
    }

    return crc_new;
}

/* Validates the checksum of the buffer, with an in-place CRC.
 *
 * Zero is substituted during crc calculation for the original crc field,
 * and the crc field is restored afterwards.  But the buffer will be modifed
 * during the calculation, so this may not be not suitable for multi-threaded
 * use.
 *
 * crc_offset: byte offset in buf of the buffer crc
 * buf: buffer pointer
 * size: size of buffer (must be > crc_offset+4)
 *
 * returns true if checksum is valid, false otherwise
 */
bool vhdx_checksum_is_valid(uint8_t *buf, size_t size, int crc_offset)
{
    uint32_t crc_orig;
    uint32_t crc;

    assert(buf != NULL);
    assert(size > (crc_offset + 4));

    memcpy(&crc_orig, buf + crc_offset, sizeof(crc_orig));
    crc_orig = le32_to_cpu(crc_orig);

    crc = vhdx_checksum_calc(0xffffffff, buf, size, crc_offset);

    return crc == crc_orig;
}


/*
 * This generates a UUID that is compliant with the MS GUIDs used
 * in the VHDX spec (and elsewhere).
 */
void vhdx_guid_generate(MSGUID *guid)
{
    uuid_t uuid;
    assert(guid != NULL);

    uuid_generate(uuid);
    memcpy(guid, uuid, sizeof(MSGUID));
}

/* Check for region overlaps inside the VHDX image */
static int vhdx_region_check(BDRVVHDXState *s, uint64_t start, uint64_t length)
{
    int ret = 0;
    uint64_t end;
    VHDXRegionEntry *r;

    end = start + length;
    QLIST_FOREACH(r, &s->regions, entries) {
        if (!((start >= r->end) || (end <= r->start))) {
            ret = -EINVAL;
            goto exit;
        }
    }

exit:
    return ret;
}

/* Register a region for future checks */
static void vhdx_region_register(BDRVVHDXState *s,
                                 uint64_t start, uint64_t length)
{
    VHDXRegionEntry *r;

    r = g_malloc0(sizeof(*r));

    r->start = start;
    r->end = start + length;

    QLIST_INSERT_HEAD(&s->regions, r, entries);
}

/* Free all registered regions */
static void vhdx_region_unregister_all(BDRVVHDXState *s)
{
    VHDXRegionEntry *r, *r_next;

    QLIST_FOREACH_SAFE(r, &s->regions, entries, r_next) {
        QLIST_REMOVE(r, entries);
        g_free(r);
    }
}

static void vhdx_set_shift_bits(BDRVVHDXState *s)
{
    s->logical_sector_size_bits = 31 - clz32(s->logical_sector_size);
    s->sectors_per_block_bits =   31 - clz32(s->sectors_per_block);
    s->chunk_ratio_bits =         63 - clz64(s->chunk_ratio);
    s->block_size_bits =          31 - clz32(s->block_size);
}

/*
 * Per the MS VHDX Specification, for every VHDX file:
 *      - The header section is fixed size - 1 MB
 *      - The header section is always the first "object"
 *      - The first 64KB of the header is the File Identifier
 *      - The first uint64 (8 bytes) is the VHDX Signature ("vhdxfile")
 *      - The following 512 bytes constitute a UTF-16 string identifiying the
 *        software that created the file, and is optional and diagnostic only.
 *
 *  Therefore, we probe by looking for the vhdxfile signature "vhdxfile"
 */
static int vhdx_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    if (buf_size >= 8 && !memcmp(buf, "vhdxfile", 8)) {
        return 100;
    }
    return 0;
}

/*
 * Writes the header to the specified offset.
 *
 * This will optionally read in buffer data from disk (otherwise zero-fill),
 * and then update the header checksum.  Header is converted to proper
 * endianness before being written to the specified file offset
 */
static int vhdx_write_header(BlockDriverState *bs_file, VHDXHeader *hdr,
                             uint64_t offset, bool read)
{
    uint8_t *buffer = NULL;
    int ret;
    VHDXHeader header_le;

    assert(bs_file != NULL);
    assert(hdr != NULL);

    /* the header checksum is not over just the packed size of VHDXHeader,
     * but rather over the entire 'reserved' range for the header, which is
     * 4KB (VHDX_HEADER_SIZE). */

    buffer = qemu_blockalign(bs_file, VHDX_HEADER_SIZE);
    if (read) {
        /* if true, we can't assume the extra reserved bytes are 0 */
        ret = bdrv_pread(bs_file, offset, buffer, VHDX_HEADER_SIZE);
        if (ret < 0) {
            goto exit;
        }
    } else {
        memset(buffer, 0, VHDX_HEADER_SIZE);
    }

    /* overwrite the actual VHDXHeader portion */
    memcpy(buffer, hdr, sizeof(VHDXHeader));
    hdr->checksum = vhdx_update_checksum(buffer, VHDX_HEADER_SIZE,
                                         offsetof(VHDXHeader, checksum));
    vhdx_header_le_export(hdr, &header_le);
    ret = bdrv_pwrite_sync(bs_file, offset, &header_le, sizeof(VHDXHeader));

exit:
    qemu_vfree(buffer);
    return ret;
}

/* Update the VHDX headers
 *
 * This follows the VHDX spec procedures for header updates.
 *
 *  - non-current header is updated with largest sequence number
 */
static int vhdx_update_header(BlockDriverState *bs, BDRVVHDXState *s,
                              bool generate_data_write_guid, MSGUID *log_guid)
{
    int ret = 0;
    int hdr_idx = 0;
    uint64_t header_offset = VHDX_HEADER1_OFFSET;

    VHDXHeader *active_header;
    VHDXHeader *inactive_header;

    /* operate on the non-current header */
    if (s->curr_header == 0) {
        hdr_idx = 1;
        header_offset = VHDX_HEADER2_OFFSET;
    }

    active_header   = s->headers[s->curr_header];
    inactive_header = s->headers[hdr_idx];

    inactive_header->sequence_number = active_header->sequence_number + 1;

    /* a new file guid must be generated before any file write, including
     * headers */
    inactive_header->file_write_guid = s->session_guid;

    /* a new data guid only needs to be generated before any guest-visible
     * writes (i.e. something observable via virtual disk read) */
    if (generate_data_write_guid) {
        vhdx_guid_generate(&inactive_header->data_write_guid);
    }

    /* update the log guid if present */
    if (log_guid) {
        inactive_header->log_guid = *log_guid;
    }

    ret = vhdx_write_header(bs->file, inactive_header, header_offset, true);
    if (ret < 0) {
        goto exit;
    }
    s->curr_header = hdr_idx;

exit:
    return ret;
}

/*
 * The VHDX spec calls for header updates to be performed twice, so that both
 * the current and non-current header have valid info
 */
int vhdx_update_headers(BlockDriverState *bs, BDRVVHDXState *s,
                        bool generate_data_write_guid, MSGUID *log_guid)
{
    int ret;

    ret = vhdx_update_header(bs, s, generate_data_write_guid, log_guid);
    if (ret < 0) {
        return ret;
    }
    ret = vhdx_update_header(bs, s, generate_data_write_guid, log_guid);
    return ret;
}

/* opens the specified header block from the VHDX file header section */
static void vhdx_parse_header(BlockDriverState *bs, BDRVVHDXState *s,
                              Error **errp)
{
    int ret;
    VHDXHeader *header1;
    VHDXHeader *header2;
    bool h1_valid = false;
    bool h2_valid = false;
    uint64_t h1_seq = 0;
    uint64_t h2_seq = 0;
    uint8_t *buffer;

    /* header1 & header2 are freed in vhdx_close() */
    header1 = qemu_blockalign(bs, sizeof(VHDXHeader));
    header2 = qemu_blockalign(bs, sizeof(VHDXHeader));

    buffer = qemu_blockalign(bs, VHDX_HEADER_SIZE);

    s->headers[0] = header1;
    s->headers[1] = header2;

    /* We have to read the whole VHDX_HEADER_SIZE instead of
     * sizeof(VHDXHeader), because the checksum is over the whole
     * region */
    ret = bdrv_pread(bs->file, VHDX_HEADER1_OFFSET, buffer, VHDX_HEADER_SIZE);
    if (ret < 0) {
        goto fail;
    }
    /* copy over just the relevant portion that we need */
    memcpy(header1, buffer, sizeof(VHDXHeader));
    vhdx_header_le_import(header1);

    if (vhdx_checksum_is_valid(buffer, VHDX_HEADER_SIZE, 4) &&
        !memcmp(&header1->signature, "head", 4)             &&
        header1->version == 1) {
        h1_seq = header1->sequence_number;
        h1_valid = true;
    }

    ret = bdrv_pread(bs->file, VHDX_HEADER2_OFFSET, buffer, VHDX_HEADER_SIZE);
    if (ret < 0) {
        goto fail;
    }
    /* copy over just the relevant portion that we need */
    memcpy(header2, buffer, sizeof(VHDXHeader));
    vhdx_header_le_import(header2);

    if (vhdx_checksum_is_valid(buffer, VHDX_HEADER_SIZE, 4) &&
        !memcmp(&header2->signature, "head", 4)             &&
        header2->version == 1) {
        h2_seq = header2->sequence_number;
        h2_valid = true;
    }

    /* If there is only 1 valid header (or no valid headers), we
     * don't care what the sequence numbers are */
    if (h1_valid && !h2_valid) {
        s->curr_header = 0;
    } else if (!h1_valid && h2_valid) {
        s->curr_header = 1;
    } else if (!h1_valid && !h2_valid) {
        goto fail;
    } else {
        /* If both headers are valid, then we choose the active one by the
         * highest sequence number.  If the sequence numbers are equal, that is
         * invalid */
        if (h1_seq > h2_seq) {
            s->curr_header = 0;
        } else if (h2_seq > h1_seq) {
            s->curr_header = 1;
        } else {
            /* The Microsoft Disk2VHD tool will create 2 identical
             * headers, with identical sequence numbers.  If the headers are
             * identical, don't consider the file corrupt */
            if (!memcmp(header1, header2, sizeof(VHDXHeader))) {
                s->curr_header = 0;
            } else {
                goto fail;
            }
        }
    }

    vhdx_region_register(s, s->headers[s->curr_header]->log_offset,
                            s->headers[s->curr_header]->log_length);
    goto exit;

fail:
    error_setg_errno(errp, -ret, "No valid VHDX header found");
    qemu_vfree(header1);
    qemu_vfree(header2);
    s->headers[0] = NULL;
    s->headers[1] = NULL;
exit:
    qemu_vfree(buffer);
}


static int vhdx_open_region_tables(BlockDriverState *bs, BDRVVHDXState *s)
{
    int ret = 0;
    uint8_t *buffer;
    int offset = 0;
    VHDXRegionTableEntry rt_entry;
    uint32_t i;
    bool bat_rt_found = false;
    bool metadata_rt_found = false;

    /* We have to read the whole 64KB block, because the crc32 is over the
     * whole block */
    buffer = qemu_blockalign(bs, VHDX_HEADER_BLOCK_SIZE);

    ret = bdrv_pread(bs->file, VHDX_REGION_TABLE_OFFSET, buffer,
                     VHDX_HEADER_BLOCK_SIZE);
    if (ret < 0) {
        goto fail;
    }
    memcpy(&s->rt, buffer, sizeof(s->rt));
    vhdx_region_header_le_import(&s->rt);
    offset += sizeof(s->rt);

    if (!vhdx_checksum_is_valid(buffer, VHDX_HEADER_BLOCK_SIZE, 4) ||
        memcmp(&s->rt.signature, "regi", 4)) {
        ret = -EINVAL;
        goto fail;
    }

    /* Per spec, maximum region table entry count is 2047 */
    if (s->rt.entry_count > 2047) {
        ret = -EINVAL;
        goto fail;
    }

    for (i = 0; i < s->rt.entry_count; i++) {
        memcpy(&rt_entry, buffer + offset, sizeof(rt_entry));
        offset += sizeof(rt_entry);

        vhdx_region_entry_le_import(&rt_entry);

        /* check for region overlap between these entries, and any
         * other memory regions in the file */
        ret = vhdx_region_check(s, rt_entry.file_offset, rt_entry.length);
        if (ret < 0) {
            goto fail;
        }

        vhdx_region_register(s, rt_entry.file_offset, rt_entry.length);

        /* see if we recognize the entry */
        if (guid_eq(rt_entry.guid, bat_guid)) {
            /* must be unique; if we have already found it this is invalid */
            if (bat_rt_found) {
                ret = -EINVAL;
                goto fail;
            }
            bat_rt_found = true;
            s->bat_rt = rt_entry;
            continue;
        }

        if (guid_eq(rt_entry.guid, metadata_guid)) {
            /* must be unique; if we have already found it this is invalid */
            if (metadata_rt_found) {
                ret = -EINVAL;
                goto fail;
            }
            metadata_rt_found = true;
            s->metadata_rt = rt_entry;
            continue;
        }

        if (rt_entry.data_bits & VHDX_REGION_ENTRY_REQUIRED) {
            /* cannot read vhdx file - required region table entry that
             * we do not understand.  per spec, we must fail to open */
            ret = -ENOTSUP;
            goto fail;
        }
    }

    if (!bat_rt_found || !metadata_rt_found) {
        ret = -EINVAL;
        goto fail;
    }

    ret = 0;

fail:
    qemu_vfree(buffer);
    return ret;
}



/* Metadata initial parser
 *
 * This loads all the metadata entry fields.  This may cause additional
 * fields to be processed (e.g. parent locator, etc..).
 *
 * There are 5 Metadata items that are always required:
 *      - File Parameters (block size, has a parent)
 *      - Virtual Disk Size (size, in bytes, of the virtual drive)
 *      - Page 83 Data (scsi page 83 guid)
 *      - Logical Sector Size (logical sector size in bytes, either 512 or
 *                             4096.  We only support 512 currently)
 *      - Physical Sector Size (512 or 4096)
 *
 * Also, if the File Parameters indicate this is a differencing file,
 * we must also look for the Parent Locator metadata item.
 */
static int vhdx_parse_metadata(BlockDriverState *bs, BDRVVHDXState *s)
{
    int ret = 0;
    uint8_t *buffer;
    int offset = 0;
    uint32_t i = 0;
    VHDXMetadataTableEntry md_entry;

    buffer = qemu_blockalign(bs, VHDX_METADATA_TABLE_MAX_SIZE);

    ret = bdrv_pread(bs->file, s->metadata_rt.file_offset, buffer,
                     VHDX_METADATA_TABLE_MAX_SIZE);
    if (ret < 0) {
        goto exit;
    }
    memcpy(&s->metadata_hdr, buffer, sizeof(s->metadata_hdr));
    offset += sizeof(s->metadata_hdr);

    vhdx_metadata_header_le_import(&s->metadata_hdr);

    if (memcmp(&s->metadata_hdr.signature, "metadata", 8)) {
        ret = -EINVAL;
        goto exit;
    }

    s->metadata_entries.present = 0;

    if ((s->metadata_hdr.entry_count * sizeof(md_entry)) >
        (VHDX_METADATA_TABLE_MAX_SIZE - offset)) {
        ret = -EINVAL;
        goto exit;
    }

    for (i = 0; i < s->metadata_hdr.entry_count; i++) {
        memcpy(&md_entry, buffer + offset, sizeof(md_entry));
        offset += sizeof(md_entry);

        vhdx_metadata_entry_le_import(&md_entry);

        if (guid_eq(md_entry.item_id, file_param_guid)) {
            if (s->metadata_entries.present & META_FILE_PARAMETER_PRESENT) {
                ret = -EINVAL;
                goto exit;
            }
            s->metadata_entries.file_parameters_entry = md_entry;
            s->metadata_entries.present |= META_FILE_PARAMETER_PRESENT;
            continue;
        }

        if (guid_eq(md_entry.item_id, virtual_size_guid)) {
            if (s->metadata_entries.present & META_VIRTUAL_DISK_SIZE_PRESENT) {
                ret = -EINVAL;
                goto exit;
            }
            s->metadata_entries.virtual_disk_size_entry = md_entry;
            s->metadata_entries.present |= META_VIRTUAL_DISK_SIZE_PRESENT;
            continue;
        }

        if (guid_eq(md_entry.item_id, page83_guid)) {
            if (s->metadata_entries.present & META_PAGE_83_PRESENT) {
                ret = -EINVAL;
                goto exit;
            }
            s->metadata_entries.page83_data_entry = md_entry;
            s->metadata_entries.present |= META_PAGE_83_PRESENT;
            continue;
        }

        if (guid_eq(md_entry.item_id, logical_sector_guid)) {
            if (s->metadata_entries.present &
                META_LOGICAL_SECTOR_SIZE_PRESENT) {
                ret = -EINVAL;
                goto exit;
            }
            s->metadata_entries.logical_sector_size_entry = md_entry;
            s->metadata_entries.present |= META_LOGICAL_SECTOR_SIZE_PRESENT;
            continue;
        }

        if (guid_eq(md_entry.item_id, phys_sector_guid)) {
            if (s->metadata_entries.present & META_PHYS_SECTOR_SIZE_PRESENT) {
                ret = -EINVAL;
                goto exit;
            }
            s->metadata_entries.phys_sector_size_entry = md_entry;
            s->metadata_entries.present |= META_PHYS_SECTOR_SIZE_PRESENT;
            continue;
        }

        if (guid_eq(md_entry.item_id, parent_locator_guid)) {
            if (s->metadata_entries.present & META_PARENT_LOCATOR_PRESENT) {
                ret = -EINVAL;
                goto exit;
            }
            s->metadata_entries.parent_locator_entry = md_entry;
            s->metadata_entries.present |= META_PARENT_LOCATOR_PRESENT;
            continue;
        }

        if (md_entry.data_bits & VHDX_META_FLAGS_IS_REQUIRED) {
            /* cannot read vhdx file - required region table entry that
             * we do not understand.  per spec, we must fail to open */
            ret = -ENOTSUP;
            goto exit;
        }
    }

    if (s->metadata_entries.present != META_ALL_PRESENT) {
        ret = -ENOTSUP;
        goto exit;
    }

    ret = bdrv_pread(bs->file,
                     s->metadata_entries.file_parameters_entry.offset
                                         + s->metadata_rt.file_offset,
                     &s->params,
                     sizeof(s->params));

    if (ret < 0) {
        goto exit;
    }

    le32_to_cpus(&s->params.block_size);
    le32_to_cpus(&s->params.data_bits);


    /* We now have the file parameters, so we can tell if this is a
     * differencing file (i.e.. has_parent), is dynamic or fixed
     * sized (leave_blocks_allocated), and the block size */

    /* The parent locator required iff the file parameters has_parent set */
    if (s->params.data_bits & VHDX_PARAMS_HAS_PARENT) {
        if (s->metadata_entries.present & META_PARENT_LOCATOR_PRESENT) {
            /* TODO: parse  parent locator fields */
            ret = -ENOTSUP; /* temp, until differencing files are supported */
            goto exit;
        } else {
            /* if has_parent is set, but there is not parent locator present,
             * then that is an invalid combination */
            ret = -EINVAL;
            goto exit;
        }
    }

    /* determine virtual disk size, logical sector size,
     * and phys sector size */

    ret = bdrv_pread(bs->file,
                     s->metadata_entries.virtual_disk_size_entry.offset
                                           + s->metadata_rt.file_offset,
                     &s->virtual_disk_size,
                     sizeof(uint64_t));
    if (ret < 0) {
        goto exit;
    }
    ret = bdrv_pread(bs->file,
                     s->metadata_entries.logical_sector_size_entry.offset
                                             + s->metadata_rt.file_offset,
                     &s->logical_sector_size,
                     sizeof(uint32_t));
    if (ret < 0) {
        goto exit;
    }
    ret = bdrv_pread(bs->file,
                     s->metadata_entries.phys_sector_size_entry.offset
                                          + s->metadata_rt.file_offset,
                     &s->physical_sector_size,
                     sizeof(uint32_t));
    if (ret < 0) {
        goto exit;
    }

    le64_to_cpus(&s->virtual_disk_size);
    le32_to_cpus(&s->logical_sector_size);
    le32_to_cpus(&s->physical_sector_size);

    if (s->params.block_size < VHDX_BLOCK_SIZE_MIN ||
        s->params.block_size > VHDX_BLOCK_SIZE_MAX) {
        ret = -EINVAL;
        goto exit;
    }

    /* only 2 supported sector sizes */
    if (s->logical_sector_size != 512 && s->logical_sector_size != 4096) {
        ret = -EINVAL;
        goto exit;
    }

    /* Both block_size and sector_size are guaranteed powers of 2, below.
       Due to range checks above, s->sectors_per_block can never be < 256 */
    s->sectors_per_block = s->params.block_size / s->logical_sector_size;
    s->chunk_ratio = (VHDX_MAX_SECTORS_PER_BLOCK) *
                     (uint64_t)s->logical_sector_size /
                     (uint64_t)s->params.block_size;

    /* These values are ones we will want to use for division / multiplication
     * later on, and they are all guaranteed (per the spec) to be powers of 2,
     * so we can take advantage of that for shift operations during
     * reads/writes */
    if (s->logical_sector_size & (s->logical_sector_size - 1)) {
        ret = -EINVAL;
        goto exit;
    }
    if (s->sectors_per_block & (s->sectors_per_block - 1)) {
        ret = -EINVAL;
        goto exit;
    }
    if (s->chunk_ratio & (s->chunk_ratio - 1)) {
        ret = -EINVAL;
        goto exit;
    }
    s->block_size = s->params.block_size;
    if (s->block_size & (s->block_size - 1)) {
        ret = -EINVAL;
        goto exit;
    }

    vhdx_set_shift_bits(s);

    ret = 0;

exit:
    qemu_vfree(buffer);
    return ret;
}

/*
 * Calculate the number of BAT entries, including sector
 * bitmap entries.
 */
static void vhdx_calc_bat_entries(BDRVVHDXState *s)
{
    uint32_t data_blocks_cnt, bitmap_blocks_cnt;

    data_blocks_cnt = s->virtual_disk_size >> s->block_size_bits;
    if (s->virtual_disk_size - (data_blocks_cnt << s->block_size_bits)) {
        data_blocks_cnt++;
    }
    bitmap_blocks_cnt = data_blocks_cnt >> s->chunk_ratio_bits;
    if (data_blocks_cnt - (bitmap_blocks_cnt << s->chunk_ratio_bits)) {
        bitmap_blocks_cnt++;
    }

    if (s->parent_entries) {
        s->bat_entries = bitmap_blocks_cnt * (s->chunk_ratio + 1);
    } else {
        s->bat_entries = data_blocks_cnt +
                         ((data_blocks_cnt - 1) >> s->chunk_ratio_bits);
    }

}

static void vhdx_close(BlockDriverState *bs)
{
    BDRVVHDXState *s = bs->opaque;
    qemu_vfree(s->headers[0]);
    s->headers[0] = NULL;
    qemu_vfree(s->headers[1]);
    s->headers[1] = NULL;
    qemu_vfree(s->bat);
    s->bat = NULL;
    qemu_vfree(s->parent_entries);
    s->parent_entries = NULL;
    migrate_del_blocker(s->migration_blocker);
    error_free(s->migration_blocker);
    qemu_vfree(s->log.hdr);
    s->log.hdr = NULL;
    vhdx_region_unregister_all(s);
}

static int vhdx_open(BlockDriverState *bs, QDict *options, int flags,
                     Error **errp)
{
    BDRVVHDXState *s = bs->opaque;
    int ret = 0;
    uint32_t i;
    uint64_t signature;
    Error *local_err = NULL;

    s->bat = NULL;
    s->first_visible_write = true;

    qemu_co_mutex_init(&s->lock);
    QLIST_INIT(&s->regions);

    /* validate the file signature */
    ret = bdrv_pread(bs->file, 0, &signature, sizeof(uint64_t));
    if (ret < 0) {
        goto fail;
    }
    if (memcmp(&signature, "vhdxfile", 8)) {
        ret = -EINVAL;
        goto fail;
    }

    /* This is used for any header updates, for the file_write_guid.
     * The spec dictates that a new value should be used for the first
     * header update */
    vhdx_guid_generate(&s->session_guid);

    vhdx_parse_header(bs, s, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto fail;
    }

    ret = vhdx_parse_log(bs, s, &s->log_replayed_on_open, errp);
    if (ret < 0) {
        goto fail;
    }

    ret = vhdx_open_region_tables(bs, s);
    if (ret < 0) {
        goto fail;
    }

    ret = vhdx_parse_metadata(bs, s);
    if (ret < 0) {
        goto fail;
    }

    s->block_size = s->params.block_size;

    /* the VHDX spec dictates that virtual_disk_size is always a multiple of
     * logical_sector_size */
    bs->total_sectors = s->virtual_disk_size >> s->logical_sector_size_bits;

    vhdx_calc_bat_entries(s);

    s->bat_offset = s->bat_rt.file_offset;

    if (s->bat_entries > s->bat_rt.length / sizeof(VHDXBatEntry)) {
        /* BAT allocation is not large enough for all entries */
        ret = -EINVAL;
        goto fail;
    }

    /* s->bat is freed in vhdx_close() */
    s->bat = qemu_blockalign(bs, s->bat_rt.length);

    ret = bdrv_pread(bs->file, s->bat_offset, s->bat, s->bat_rt.length);
    if (ret < 0) {
        goto fail;
    }

    uint64_t payblocks = s->chunk_ratio;
    /* endian convert, and verify populated BAT field file offsets against
     * region table and log entries */
    for (i = 0; i < s->bat_entries; i++) {
        le64_to_cpus(&s->bat[i]);
        if (payblocks--) {
            /* payload bat entries */
            if ((s->bat[i] & VHDX_BAT_STATE_BIT_MASK) ==
                    PAYLOAD_BLOCK_FULLY_PRESENT) {
                ret = vhdx_region_check(s, s->bat[i] & VHDX_BAT_FILE_OFF_MASK,
                                        s->block_size);
                if (ret < 0) {
                    goto fail;
                }
            }
        } else {
            payblocks = s->chunk_ratio;
            /* Once differencing files are supported, verify sector bitmap
             * blocks here */
        }
    }

    if (flags & BDRV_O_RDWR) {
        ret = vhdx_update_headers(bs, s, false, NULL);
        if (ret < 0) {
            goto fail;
        }
    }

    /* TODO: differencing files */

    /* Disable migration when VHDX images are used */
    error_set(&s->migration_blocker,
            QERR_BLOCK_FORMAT_FEATURE_NOT_SUPPORTED,
            "vhdx", bs->device_name, "live migration");
    migrate_add_blocker(s->migration_blocker);

    return 0;
fail:
    vhdx_close(bs);
    return ret;
}

static int vhdx_reopen_prepare(BDRVReopenState *state,
                               BlockReopenQueue *queue, Error **errp)
{
    return 0;
}


/*
 * Perform sector to block offset translations, to get various
 * sector and file offsets into the image.  See VHDXSectorInfo
 */
static void vhdx_block_translate(BDRVVHDXState *s, int64_t sector_num,
                                 int nb_sectors, VHDXSectorInfo *sinfo)
{
    uint32_t block_offset;

    sinfo->bat_idx = sector_num >> s->sectors_per_block_bits;
    /* effectively a modulo - this gives us the offset into the block
     * (in sector sizes) for our sector number */
    block_offset = sector_num - (sinfo->bat_idx << s->sectors_per_block_bits);
    /* the chunk ratio gives us the interleaving of the sector
     * bitmaps, so we need to advance our page block index by the
     * sector bitmaps entry number */
    sinfo->bat_idx += sinfo->bat_idx >> s->chunk_ratio_bits;

    /* the number of sectors we can read/write in this cycle */
    sinfo->sectors_avail = s->sectors_per_block - block_offset;

    sinfo->bytes_left = sinfo->sectors_avail << s->logical_sector_size_bits;

    if (sinfo->sectors_avail > nb_sectors) {
        sinfo->sectors_avail = nb_sectors;
    }

    sinfo->bytes_avail = sinfo->sectors_avail << s->logical_sector_size_bits;

    sinfo->file_offset = s->bat[sinfo->bat_idx] & VHDX_BAT_FILE_OFF_MASK;

    sinfo->block_offset = block_offset << s->logical_sector_size_bits;

    /* The file offset must be past the header section, so must be > 0 */
    if (sinfo->file_offset == 0) {
        return;
    }

    /* block offset is the offset in vhdx logical sectors, in
     * the payload data block. Convert that to a byte offset
     * in the block, and add in the payload data block offset
     * in the file, in bytes, to get the final read address */

    sinfo->file_offset += sinfo->block_offset;
}


static int vhdx_get_info(BlockDriverState *bs, BlockDriverInfo *bdi)
{
    BDRVVHDXState *s = bs->opaque;

    bdi->cluster_size = s->block_size;

    bdi->unallocated_blocks_are_zero =
        (s->params.data_bits & VHDX_PARAMS_HAS_PARENT) == 0;

    return 0;
}


static coroutine_fn int vhdx_co_readv(BlockDriverState *bs, int64_t sector_num,
                                      int nb_sectors, QEMUIOVector *qiov)
{
    BDRVVHDXState *s = bs->opaque;
    int ret = 0;
    VHDXSectorInfo sinfo;
    uint64_t bytes_done = 0;
    QEMUIOVector hd_qiov;

    qemu_iovec_init(&hd_qiov, qiov->niov);

    qemu_co_mutex_lock(&s->lock);

    while (nb_sectors > 0) {
        /* We are a differencing file, so we need to inspect the sector bitmap
         * to see if we have the data or not */
        if (s->params.data_bits & VHDX_PARAMS_HAS_PARENT) {
            /* not supported yet */
            ret = -ENOTSUP;
            goto exit;
        } else {
            vhdx_block_translate(s, sector_num, nb_sectors, &sinfo);

            qemu_iovec_reset(&hd_qiov);
            qemu_iovec_concat(&hd_qiov, qiov,  bytes_done, sinfo.bytes_avail);

            /* check the payload block state */
            switch (s->bat[sinfo.bat_idx] & VHDX_BAT_STATE_BIT_MASK) {
            case PAYLOAD_BLOCK_NOT_PRESENT: /* fall through */
            case PAYLOAD_BLOCK_UNDEFINED:   /* fall through */
            case PAYLOAD_BLOCK_UNMAPPED:    /* fall through */
            case PAYLOAD_BLOCK_ZERO:
                /* return zero */
                qemu_iovec_memset(&hd_qiov, 0, 0, sinfo.bytes_avail);
                break;
            case PAYLOAD_BLOCK_FULLY_PRESENT:
                qemu_co_mutex_unlock(&s->lock);
                ret = bdrv_co_readv(bs->file,
                                    sinfo.file_offset >> BDRV_SECTOR_BITS,
                                    sinfo.sectors_avail, &hd_qiov);
                qemu_co_mutex_lock(&s->lock);
                if (ret < 0) {
                    goto exit;
                }
                break;
            case PAYLOAD_BLOCK_PARTIALLY_PRESENT:
                /* we don't yet support difference files, fall through
                 * to error */
            default:
                ret = -EIO;
                goto exit;
                break;
            }
            nb_sectors -= sinfo.sectors_avail;
            sector_num += sinfo.sectors_avail;
            bytes_done += sinfo.bytes_avail;
        }
    }
    ret = 0;
exit:
    qemu_co_mutex_unlock(&s->lock);
    qemu_iovec_destroy(&hd_qiov);
    return ret;
}

/*
 * Allocate a new payload block at the end of the file.
 *
 * Allocation will happen at 1MB alignment inside the file
 *
 * Returns the file offset start of the new payload block
 */
static int vhdx_allocate_block(BlockDriverState *bs, BDRVVHDXState *s,
                                    uint64_t *new_offset)
{
    *new_offset = bdrv_getlength(bs->file);

    /* per the spec, the address for a block is in units of 1MB */
    *new_offset = ROUND_UP(*new_offset, 1024 * 1024);

    return bdrv_truncate(bs->file, *new_offset + s->block_size);
}

/*
 * Update the BAT table entry with the new file offset, and the new entry
 * state */
static void vhdx_update_bat_table_entry(BlockDriverState *bs, BDRVVHDXState *s,
                                       VHDXSectorInfo *sinfo,
                                       uint64_t *bat_entry_le,
                                       uint64_t *bat_offset, int state)
{
    /* The BAT entry is a uint64, with 44 bits for the file offset in units of
     * 1MB, and 3 bits for the block state. */
    s->bat[sinfo->bat_idx]  = sinfo->file_offset;

    s->bat[sinfo->bat_idx] |= state & VHDX_BAT_STATE_BIT_MASK;

    *bat_entry_le = cpu_to_le64(s->bat[sinfo->bat_idx]);
    *bat_offset = s->bat_offset + sinfo->bat_idx * sizeof(VHDXBatEntry);

}

/* Per the spec, on the first write of guest-visible data to the file the
 * data write guid must be updated in the header */
int vhdx_user_visible_write(BlockDriverState *bs, BDRVVHDXState *s)
{
    int ret = 0;
    if (s->first_visible_write) {
        s->first_visible_write = false;
        ret = vhdx_update_headers(bs, s, true, NULL);
    }
    return ret;
}

static coroutine_fn int vhdx_co_writev(BlockDriverState *bs, int64_t sector_num,
                                      int nb_sectors, QEMUIOVector *qiov)
{
    int ret = -ENOTSUP;
    BDRVVHDXState *s = bs->opaque;
    VHDXSectorInfo sinfo;
    uint64_t bytes_done = 0;
    uint64_t bat_entry = 0;
    uint64_t bat_entry_offset = 0;
    QEMUIOVector hd_qiov;
    struct iovec iov1 = { 0 };
    struct iovec iov2 = { 0 };
    int sectors_to_write;
    int bat_state;
    uint64_t bat_prior_offset = 0;
    bool bat_update = false;

    qemu_iovec_init(&hd_qiov, qiov->niov);

    qemu_co_mutex_lock(&s->lock);

    ret = vhdx_user_visible_write(bs, s);
    if (ret < 0) {
        goto exit;
    }

    while (nb_sectors > 0) {
        bool use_zero_buffers = false;
        bat_update = false;
        if (s->params.data_bits & VHDX_PARAMS_HAS_PARENT) {
            /* not supported yet */
            ret = -ENOTSUP;
            goto exit;
        } else {
            vhdx_block_translate(s, sector_num, nb_sectors, &sinfo);
            sectors_to_write = sinfo.sectors_avail;

            qemu_iovec_reset(&hd_qiov);
            /* check the payload block state */
            bat_state = s->bat[sinfo.bat_idx] & VHDX_BAT_STATE_BIT_MASK;
            switch (bat_state) {
            case PAYLOAD_BLOCK_ZERO:
                /* in this case, we need to preserve zero writes for
                 * data that is not part of this write, so we must pad
                 * the rest of the buffer to zeroes */

                /* if we are on a posix system with ftruncate() that extends
                 * a file, then it is zero-filled for us.  On Win32, the raw
                 * layer uses SetFilePointer and SetFileEnd, which does not
                 * zero fill AFAIK */

                /* Queue another write of zero buffers if the underlying file
                 * does not zero-fill on file extension */

                if (bdrv_has_zero_init(bs->file) == 0) {
                    use_zero_buffers = true;

                    /* zero fill the front, if any */
                    if (sinfo.block_offset) {
                        iov1.iov_len = sinfo.block_offset;
                        iov1.iov_base = qemu_blockalign(bs, iov1.iov_len);
                        memset(iov1.iov_base, 0, iov1.iov_len);
                        qemu_iovec_concat_iov(&hd_qiov, &iov1, 1, 0,
                                              sinfo.block_offset);
                        sectors_to_write += iov1.iov_len >> BDRV_SECTOR_BITS;
                    }

                    /* our actual data */
                    qemu_iovec_concat(&hd_qiov, qiov,  bytes_done,
                                      sinfo.bytes_avail);

                    /* zero fill the back, if any */
                    if ((sinfo.bytes_avail - sinfo.block_offset) <
                         s->block_size) {
                        iov2.iov_len = s->block_size -
                                      (sinfo.bytes_avail + sinfo.block_offset);
                        iov2.iov_base = qemu_blockalign(bs, iov2.iov_len);
                        memset(iov2.iov_base, 0, iov2.iov_len);
                        qemu_iovec_concat_iov(&hd_qiov, &iov2, 1, 0,
                                              sinfo.block_offset);
                        sectors_to_write += iov2.iov_len >> BDRV_SECTOR_BITS;
                    }
                }

                /* fall through */
            case PAYLOAD_BLOCK_NOT_PRESENT: /* fall through */
            case PAYLOAD_BLOCK_UNMAPPED:    /* fall through */
            case PAYLOAD_BLOCK_UNDEFINED:   /* fall through */
                bat_prior_offset = sinfo.file_offset;
                ret = vhdx_allocate_block(bs, s, &sinfo.file_offset);
                if (ret < 0) {
                    goto exit;
                }
                /* once we support differencing files, this may also be
                 * partially present */
                /* update block state to the newly specified state */
                vhdx_update_bat_table_entry(bs, s, &sinfo, &bat_entry,
                                            &bat_entry_offset,
                                            PAYLOAD_BLOCK_FULLY_PRESENT);
                bat_update = true;
                /* since we just allocated a block, file_offset is the
                 * beginning of the payload block. It needs to be the
                 * write address, which includes the offset into the block */
                if (!use_zero_buffers) {
                    sinfo.file_offset += sinfo.block_offset;
                }
                /* fall through */
            case PAYLOAD_BLOCK_FULLY_PRESENT:
                /* if the file offset address is in the header zone,
                 * there is a problem */
                if (sinfo.file_offset < (1024 * 1024)) {
                    ret = -EFAULT;
                    goto error_bat_restore;
                }

                if (!use_zero_buffers) {
                    qemu_iovec_concat(&hd_qiov, qiov,  bytes_done,
                                      sinfo.bytes_avail);
                }
                /* block exists, so we can just overwrite it */
                qemu_co_mutex_unlock(&s->lock);
                ret = bdrv_co_writev(bs->file,
                                    sinfo.file_offset >> BDRV_SECTOR_BITS,
                                    sectors_to_write, &hd_qiov);
                qemu_co_mutex_lock(&s->lock);
                if (ret < 0) {
                    goto error_bat_restore;
                }
                break;
            case PAYLOAD_BLOCK_PARTIALLY_PRESENT:
                /* we don't yet support difference files, fall through
                 * to error */
            default:
                ret = -EIO;
                goto exit;
                break;
            }

            if (bat_update) {
                /* this will update the BAT entry into the log journal, and
                 * then flush the log journal out to disk */
                ret =  vhdx_log_write_and_flush(bs, s, &bat_entry,
                                                sizeof(VHDXBatEntry),
                                                bat_entry_offset);
                if (ret < 0) {
                    goto exit;
                }
            }

            nb_sectors -= sinfo.sectors_avail;
            sector_num += sinfo.sectors_avail;
            bytes_done += sinfo.bytes_avail;

        }
    }

    goto exit;

error_bat_restore:
    if (bat_update) {
        /* keep metadata in sync, and restore the bat entry state
         * if error. */
        sinfo.file_offset = bat_prior_offset;
        vhdx_update_bat_table_entry(bs, s, &sinfo, &bat_entry,
                                    &bat_entry_offset, bat_state);
    }
exit:
    qemu_vfree(iov1.iov_base);
    qemu_vfree(iov2.iov_base);
    qemu_co_mutex_unlock(&s->lock);
    qemu_iovec_destroy(&hd_qiov);
    return ret;
}



/*
 * Create VHDX Headers
 *
 * There are 2 headers, and the highest sequence number will represent
 * the active header
 */
static int vhdx_create_new_headers(BlockDriverState *bs, uint64_t image_size,
                                   uint32_t log_size)
{
    int ret = 0;
    VHDXHeader *hdr = NULL;

    hdr = g_malloc0(sizeof(VHDXHeader));

    hdr->signature       = VHDX_HEADER_SIGNATURE;
    hdr->sequence_number = g_random_int();
    hdr->log_version     = 0;
    hdr->version         = 1;
    hdr->log_length      = log_size;
    hdr->log_offset      = VHDX_HEADER_SECTION_END;
    vhdx_guid_generate(&hdr->file_write_guid);
    vhdx_guid_generate(&hdr->data_write_guid);

    ret = vhdx_write_header(bs, hdr, VHDX_HEADER1_OFFSET, false);
    if (ret < 0) {
        goto exit;
    }
    hdr->sequence_number++;
    ret = vhdx_write_header(bs, hdr, VHDX_HEADER2_OFFSET, false);
    if (ret < 0) {
        goto exit;
    }

exit:
    g_free(hdr);
    return ret;
}


/*
 * Create the Metadata entries.
 *
 * For more details on the entries, see section 3.5 (pg 29) in the
 * VHDX 1.00 specification.
 *
 * We support 5 metadata entries (all required by spec):
 *          File Parameters,
 *          Virtual Disk Size,
 *          Page 83 Data,
 *          Logical Sector Size,
 *          Physical Sector Size
 *
 * The first 64KB of the Metadata section is reserved for the metadata
 * header and entries; beyond that, the metadata items themselves reside.
 */
static int vhdx_create_new_metadata(BlockDriverState *bs,
                                    uint64_t image_size,
                                    uint32_t block_size,
                                    uint32_t sector_size,
                                    uint64_t metadata_offset,
                                    VHDXImageType type)
{
    int ret = 0;
    uint32_t offset = 0;
    void *buffer = NULL;
    void *entry_buffer;
    VHDXMetadataTableHeader *md_table;;
    VHDXMetadataTableEntry  *md_table_entry;

    /* Metadata entries */
    VHDXFileParameters     *mt_file_params;
    VHDXVirtualDiskSize    *mt_virtual_size;
    VHDXPage83Data         *mt_page83;
    VHDXVirtualDiskLogicalSectorSize  *mt_log_sector_size;
    VHDXVirtualDiskPhysicalSectorSize *mt_phys_sector_size;

    entry_buffer = g_malloc0(sizeof(VHDXFileParameters)               +
                             sizeof(VHDXVirtualDiskSize)              +
                             sizeof(VHDXPage83Data)                   +
                             sizeof(VHDXVirtualDiskLogicalSectorSize) +
                             sizeof(VHDXVirtualDiskPhysicalSectorSize));

    mt_file_params = entry_buffer;
    offset += sizeof(VHDXFileParameters);
    mt_virtual_size = entry_buffer + offset;
    offset += sizeof(VHDXVirtualDiskSize);
    mt_page83 = entry_buffer + offset;
    offset += sizeof(VHDXPage83Data);
    mt_log_sector_size = entry_buffer + offset;
    offset += sizeof(VHDXVirtualDiskLogicalSectorSize);
    mt_phys_sector_size = entry_buffer + offset;

    mt_file_params->block_size = cpu_to_le32(block_size);
    if (type == VHDX_TYPE_FIXED) {
        mt_file_params->data_bits |= VHDX_PARAMS_LEAVE_BLOCKS_ALLOCED;
        cpu_to_le32s(&mt_file_params->data_bits);
    }

    vhdx_guid_generate(&mt_page83->page_83_data);
    cpu_to_leguids(&mt_page83->page_83_data);
    mt_virtual_size->virtual_disk_size        = cpu_to_le64(image_size);
    mt_log_sector_size->logical_sector_size   = cpu_to_le32(sector_size);
    mt_phys_sector_size->physical_sector_size = cpu_to_le32(sector_size);

    buffer = g_malloc0(VHDX_HEADER_BLOCK_SIZE);
    md_table = buffer;

    md_table->signature   = VHDX_METADATA_SIGNATURE;
    md_table->entry_count = 5;
    vhdx_metadata_header_le_export(md_table);


    /* This will reference beyond the reserved table portion */
    offset = 64 * KiB;

    md_table_entry = buffer + sizeof(VHDXMetadataTableHeader);

    md_table_entry[0].item_id = file_param_guid;
    md_table_entry[0].offset  = offset;
    md_table_entry[0].length  = sizeof(VHDXFileParameters);
    md_table_entry[0].data_bits |= VHDX_META_FLAGS_IS_REQUIRED;
    offset += md_table_entry[0].length;
    vhdx_metadata_entry_le_export(&md_table_entry[0]);

    md_table_entry[1].item_id = virtual_size_guid;
    md_table_entry[1].offset  = offset;
    md_table_entry[1].length  = sizeof(VHDXVirtualDiskSize);
    md_table_entry[1].data_bits |= VHDX_META_FLAGS_IS_REQUIRED |
                                   VHDX_META_FLAGS_IS_VIRTUAL_DISK;
    offset += md_table_entry[1].length;
    vhdx_metadata_entry_le_export(&md_table_entry[1]);

    md_table_entry[2].item_id = page83_guid;
    md_table_entry[2].offset  = offset;
    md_table_entry[2].length  = sizeof(VHDXPage83Data);
    md_table_entry[2].data_bits |= VHDX_META_FLAGS_IS_REQUIRED |
                                   VHDX_META_FLAGS_IS_VIRTUAL_DISK;
    offset += md_table_entry[2].length;
    vhdx_metadata_entry_le_export(&md_table_entry[2]);

    md_table_entry[3].item_id = logical_sector_guid;
    md_table_entry[3].offset  = offset;
    md_table_entry[3].length  = sizeof(VHDXVirtualDiskLogicalSectorSize);
    md_table_entry[3].data_bits |= VHDX_META_FLAGS_IS_REQUIRED |
                                   VHDX_META_FLAGS_IS_VIRTUAL_DISK;
    offset += md_table_entry[3].length;
    vhdx_metadata_entry_le_export(&md_table_entry[3]);

    md_table_entry[4].item_id = phys_sector_guid;
    md_table_entry[4].offset  = offset;
    md_table_entry[4].length  = sizeof(VHDXVirtualDiskPhysicalSectorSize);
    md_table_entry[4].data_bits |= VHDX_META_FLAGS_IS_REQUIRED |
                                   VHDX_META_FLAGS_IS_VIRTUAL_DISK;
    vhdx_metadata_entry_le_export(&md_table_entry[4]);

    ret = bdrv_pwrite(bs, metadata_offset, buffer, VHDX_HEADER_BLOCK_SIZE);
    if (ret < 0) {
        goto exit;
    }

    ret = bdrv_pwrite(bs, metadata_offset + (64 * KiB), entry_buffer,
                      VHDX_HEADER_BLOCK_SIZE);
    if (ret < 0) {
        goto exit;
    }


exit:
    g_free(buffer);
    g_free(entry_buffer);
    return ret;
}

/* This create the actual BAT itself.  We currently only support
 * 'Dynamic' and 'Fixed' image types.
 *
 *  Dynamic images: default state of the BAT is all zeroes.
 *
 *  Fixed images: default state of the BAT is fully populated, with
 *                file offsets and state PAYLOAD_BLOCK_FULLY_PRESENT.
 */
static int vhdx_create_bat(BlockDriverState *bs, BDRVVHDXState *s,
                           uint64_t image_size, VHDXImageType type,
                           bool use_zero_blocks, VHDXRegionTableEntry *rt_bat)
{
    int ret = 0;
    uint64_t data_file_offset;
    uint64_t total_sectors = 0;
    uint64_t sector_num = 0;
    uint64_t unused;
    int block_state;
    VHDXSectorInfo sinfo;

    assert(s->bat == NULL);

    /* this gives a data start after BAT/bitmap entries, and well
     * past any metadata entries (with a 4 MB buffer for future
     * expansion */
    data_file_offset = rt_bat->file_offset + rt_bat->length + 5 * MiB;
    total_sectors = image_size >> s->logical_sector_size_bits;

    if (type == VHDX_TYPE_DYNAMIC) {
        /* All zeroes, so we can just extend the file - the end of the BAT
         * is the furthest thing we have written yet */
        ret = bdrv_truncate(bs, data_file_offset);
        if (ret < 0) {
            goto exit;
        }
    } else if (type == VHDX_TYPE_FIXED) {
        ret = bdrv_truncate(bs, data_file_offset + image_size);
        if (ret < 0) {
            goto exit;
        }
    } else {
        ret = -ENOTSUP;
        goto exit;
    }

    if (type == VHDX_TYPE_FIXED ||
                use_zero_blocks ||
                bdrv_has_zero_init(bs) == 0) {
        /* for a fixed file, the default BAT entry is not zero */
        s->bat = g_malloc0(rt_bat->length);
        block_state = type == VHDX_TYPE_FIXED ? PAYLOAD_BLOCK_FULLY_PRESENT :
                                                PAYLOAD_BLOCK_NOT_PRESENT;
        block_state = use_zero_blocks ? PAYLOAD_BLOCK_ZERO : block_state;
        /* fill the BAT by emulating sector writes of sectors_per_block size */
        while (sector_num < total_sectors) {
            vhdx_block_translate(s, sector_num, s->sectors_per_block, &sinfo);
            sinfo.file_offset = data_file_offset +
                                (sector_num << s->logical_sector_size_bits);
            sinfo.file_offset = ROUND_UP(sinfo.file_offset, MiB);
            vhdx_update_bat_table_entry(bs, s, &sinfo, &unused, &unused,
                                        block_state);
            cpu_to_le64s(&s->bat[sinfo.bat_idx]);
            sector_num += s->sectors_per_block;
        }
        ret = bdrv_pwrite(bs, rt_bat->file_offset, s->bat, rt_bat->length);
        if (ret < 0) {
            goto exit;
        }
    }



exit:
    g_free(s->bat);
    return ret;
}

/* Creates the region table header, and region table entries.
 * There are 2 supported region table entries: BAT, and Metadata/
 *
 * As the calculations for the BAT region table are also needed
 * to create the BAT itself, we will also cause the BAT to be
 * created.
 */
static int vhdx_create_new_region_table(BlockDriverState *bs,
                                        uint64_t image_size,
                                        uint32_t block_size,
                                        uint32_t sector_size,
                                        uint32_t log_size,
                                        bool use_zero_blocks,
                                        VHDXImageType type,
                                        uint64_t *metadata_offset)
{
    int ret = 0;
    uint32_t offset = 0;
    void *buffer = NULL;
    BDRVVHDXState *s = NULL;
    VHDXRegionTableHeader *region_table;
    VHDXRegionTableEntry *rt_bat;
    VHDXRegionTableEntry *rt_metadata;

    assert(metadata_offset != NULL);

    /* Populate enough of the BDRVVHDXState to be able to use the
     * pre-existing BAT calculation, translation, and update functions */
    s = g_malloc0(sizeof(BDRVVHDXState));

    s->chunk_ratio = (VHDX_MAX_SECTORS_PER_BLOCK) *
                     (uint64_t) sector_size / (uint64_t) block_size;

    s->sectors_per_block = block_size / sector_size;
    s->virtual_disk_size = image_size;
    s->block_size = block_size;
    s->logical_sector_size = sector_size;

    vhdx_set_shift_bits(s);

    vhdx_calc_bat_entries(s);

    /* At this point the VHDX state is populated enough for creation */

    /* a single buffer is used so we can calculate the checksum over the
     * entire 64KB block */
    buffer = g_malloc0(VHDX_HEADER_BLOCK_SIZE);
    region_table = buffer;
    offset += sizeof(VHDXRegionTableHeader);
    rt_bat = buffer + offset;
    offset += sizeof(VHDXRegionTableEntry);
    rt_metadata  = buffer + offset;

    region_table->signature = VHDX_REGION_SIGNATURE;
    region_table->entry_count = 2;   /* BAT and Metadata */

    rt_bat->guid        = bat_guid;
    rt_bat->length      = ROUND_UP(s->bat_entries * sizeof(VHDXBatEntry), MiB);
    rt_bat->file_offset = ROUND_UP(VHDX_HEADER_SECTION_END + log_size, MiB);
    s->bat_offset = rt_bat->file_offset;

    rt_metadata->guid        = metadata_guid;
    rt_metadata->file_offset = ROUND_UP(rt_bat->file_offset + rt_bat->length,
                                        MiB);
    rt_metadata->length      = 1 * MiB; /* min size, and more than enough */
    *metadata_offset = rt_metadata->file_offset;

    vhdx_update_checksum(buffer, VHDX_HEADER_BLOCK_SIZE,
                         offsetof(VHDXRegionTableHeader, checksum));


    /* The region table gives us the data we need to create the BAT,
     * so do that now */
    ret = vhdx_create_bat(bs, s, image_size, type, use_zero_blocks, rt_bat);

    /* Now write out the region headers to disk */
    vhdx_region_header_le_export(region_table);
    vhdx_region_entry_le_export(rt_bat);
    vhdx_region_entry_le_export(rt_metadata);

    ret = bdrv_pwrite(bs, VHDX_REGION_TABLE_OFFSET, buffer,
                      VHDX_HEADER_BLOCK_SIZE);
    if (ret < 0) {
        goto exit;
    }

    ret = bdrv_pwrite(bs, VHDX_REGION_TABLE2_OFFSET, buffer,
                      VHDX_HEADER_BLOCK_SIZE);
    if (ret < 0) {
        goto exit;
    }


exit:
    g_free(s);
    g_free(buffer);
    return ret;
}

/* We need to create the following elements:
 *
 *    .-----------------------------------------------------------------.
 *    |   (A)    |   (B)    |    (C)    |     (D)       |     (E)       |
 *    |  File ID |  Header1 |  Header 2 |  Region Tbl 1 |  Region Tbl 2 |
 *    |          |          |           |               |               |
 *    .-----------------------------------------------------------------.
 *    0         64KB      128KB       192KB           256KB           320KB
 *
 *
 *    .---- ~ ----------- ~ ------------ ~ ---------------- ~ -----------.
 *    |     (F)     |     (G)       |    (H)    |                        |
 *    | Journal Log |  BAT / Bitmap |  Metadata |  .... data ......      |
 *    |             |               |           |                        |
 *    .---- ~ ----------- ~ ------------ ~ ---------------- ~ -----------.
 *   1MB
 */
static int vhdx_create(const char *filename, QemuOpts *opts, Error **errp)
{
    int ret = 0;
    uint64_t image_size = (uint64_t) 2 * GiB;
    uint32_t log_size   = 1 * MiB;
    uint32_t block_size = 0;
    uint64_t signature;
    uint64_t metadata_offset;
    bool use_zero_blocks = false;

    gunichar2 *creator = NULL;
    glong creator_items;
    BlockDriverState *bs;
    char *type = NULL;
    VHDXImageType image_type;
    Error *local_err = NULL;

    image_size = qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0);
    log_size = qemu_opt_get_size_del(opts, VHDX_BLOCK_OPT_LOG_SIZE, 0);
    block_size = qemu_opt_get_size_del(opts, VHDX_BLOCK_OPT_BLOCK_SIZE, 0);
    type = qemu_opt_get_del(opts, BLOCK_OPT_SUBFMT);
    use_zero_blocks = qemu_opt_get_bool_del(opts, VHDX_BLOCK_OPT_ZERO, false);

    if (image_size > VHDX_MAX_IMAGE_SIZE) {
        error_setg_errno(errp, EINVAL, "Image size too large; max of 64TB");
        ret = -EINVAL;
        goto exit;
    }

    if (type == NULL) {
        type = g_strdup("dynamic");
    }

    if (!strcmp(type, "dynamic")) {
        image_type = VHDX_TYPE_DYNAMIC;
    } else if (!strcmp(type, "fixed")) {
        image_type = VHDX_TYPE_FIXED;
    } else if (!strcmp(type, "differencing")) {
        error_setg_errno(errp, ENOTSUP,
                         "Differencing files not yet supported");
        ret = -ENOTSUP;
        goto exit;
    } else {
        ret = -EINVAL;
        goto exit;
    }

    /* These are pretty arbitrary, and mainly designed to keep the BAT
     * size reasonable to load into RAM */
    if (block_size == 0) {
        if (image_size > 32 * TiB) {
            block_size = 64 * MiB;
        } else if (image_size > (uint64_t) 100 * GiB) {
            block_size = 32 * MiB;
        } else if (image_size > 1 * GiB) {
            block_size = 16 * MiB;
        } else {
            block_size = 8 * MiB;
        }
    }


    /* make the log size close to what was specified, but must be
     * min 1MB, and multiple of 1MB */
    log_size = ROUND_UP(log_size, MiB);

    block_size = ROUND_UP(block_size, MiB);
    block_size = block_size > VHDX_BLOCK_SIZE_MAX ? VHDX_BLOCK_SIZE_MAX :
                                                    block_size;

    ret = bdrv_create_file(filename, opts, &local_err);
    if (ret < 0) {
        error_propagate(errp, local_err);
        goto exit;
    }

    bs = NULL;
    ret = bdrv_open(&bs, filename, NULL, NULL, BDRV_O_RDWR | BDRV_O_PROTOCOL,
                    NULL, &local_err);
    if (ret < 0) {
        error_propagate(errp, local_err);
        goto exit;
    }

    /* Create (A) */

    /* The creator field is optional, but may be useful for
     * debugging / diagnostics */
    creator = g_utf8_to_utf16("QEMU v" QEMU_VERSION, -1, NULL,
                              &creator_items, NULL);
    signature = cpu_to_le64(VHDX_FILE_SIGNATURE);
    ret = bdrv_pwrite(bs, VHDX_FILE_ID_OFFSET, &signature, sizeof(signature));
    if (ret < 0) {
        goto delete_and_exit;
    }
    if (creator) {
        ret = bdrv_pwrite(bs, VHDX_FILE_ID_OFFSET + sizeof(signature),
                          creator, creator_items * sizeof(gunichar2));
        if (ret < 0) {
            goto delete_and_exit;
        }
    }


    /* Creates (B),(C) */
    ret = vhdx_create_new_headers(bs, image_size, log_size);
    if (ret < 0) {
        goto delete_and_exit;
    }

    /* Creates (D),(E),(G) explicitly. (F) created as by-product */
    ret = vhdx_create_new_region_table(bs, image_size, block_size, 512,
                                       log_size, use_zero_blocks, image_type,
                                       &metadata_offset);
    if (ret < 0) {
        goto delete_and_exit;
    }

    /* Creates (H) */
    ret = vhdx_create_new_metadata(bs, image_size, block_size, 512,
                                   metadata_offset, image_type);
    if (ret < 0) {
        goto delete_and_exit;
    }



delete_and_exit:
    bdrv_unref(bs);
exit:
    g_free(type);
    g_free(creator);
    return ret;
}

/* If opened r/w, the VHDX driver will automatically replay the log,
 * if one is present, inside the vhdx_open() call.
 *
 * If qemu-img check -r all is called, the image is automatically opened
 * r/w and any log has already been replayed, so there is nothing (currently)
 * for us to do here
 */
static int vhdx_check(BlockDriverState *bs, BdrvCheckResult *result,
                       BdrvCheckMode fix)
{
    BDRVVHDXState *s = bs->opaque;

    if (s->log_replayed_on_open) {
        result->corruptions_fixed++;
    }
    return 0;
}

static QemuOptsList vhdx_create_opts = {
    .name = "vhdx-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(vhdx_create_opts.head),
    .desc = {
        {
           .name = BLOCK_OPT_SIZE,
           .type = QEMU_OPT_SIZE,
           .help = "Virtual disk size; max of 64TB."
       },
       {
           .name = VHDX_BLOCK_OPT_LOG_SIZE,
           .type = QEMU_OPT_SIZE,
           .def_value_str = stringify(DEFAULT_LOG_SIZE),
           .help = "Log size; min 1MB."
       },
       {
           .name = VHDX_BLOCK_OPT_BLOCK_SIZE,
           .type = QEMU_OPT_SIZE,
           .def_value_str = stringify(0),
           .help = "Block Size; min 1MB, max 256MB. " \
                   "0 means auto-calculate based on image size."
       },
       {
           .name = BLOCK_OPT_SUBFMT,
           .type = QEMU_OPT_STRING,
           .help = "VHDX format type, can be either 'dynamic' or 'fixed'. "\
                   "Default is 'dynamic'."
       },
       {
           .name = VHDX_BLOCK_OPT_ZERO,
           .type = QEMU_OPT_BOOL,
           .help = "Force use of payload blocks of type 'ZERO'.  Non-standard."
       },
       { NULL }
    }
};

static BlockDriver bdrv_vhdx = {
    .format_name            = "vhdx",
    .instance_size          = sizeof(BDRVVHDXState),
    .bdrv_probe             = vhdx_probe,
    .bdrv_open              = vhdx_open,
    .bdrv_close             = vhdx_close,
    .bdrv_reopen_prepare    = vhdx_reopen_prepare,
    .bdrv_co_readv          = vhdx_co_readv,
    .bdrv_co_writev         = vhdx_co_writev,
    .bdrv_create            = vhdx_create,
    .bdrv_get_info          = vhdx_get_info,
    .bdrv_check             = vhdx_check,

    .create_opts            = &vhdx_create_opts,
};

static void bdrv_vhdx_init(void)
{
    bdrv_register(&bdrv_vhdx);
}

block_init(bdrv_vhdx_init);
