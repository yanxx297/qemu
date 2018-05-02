/*
 * libqos AHCI functions
 *
 * Copyright (c) 2014 John Snow <jsnow@redhat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <glib.h>

#include "libqtest.h"
#include "libqos/ahci.h"
#include "libqos/pci-pc.h"

#include "qemu-common.h"
#include "qemu/host-utils.h"

#include "hw/pci/pci_ids.h"
#include "hw/pci/pci_regs.h"

/**
 * Allocate space in the guest using information in the AHCIQState object.
 */
uint64_t ahci_alloc(AHCIQState *ahci, size_t bytes)
{
    g_assert(ahci);
    g_assert(ahci->parent);
    return qmalloc(ahci->parent, bytes);
}

void ahci_free(AHCIQState *ahci, uint64_t addr)
{
    g_assert(ahci);
    g_assert(ahci->parent);
    qfree(ahci->parent, addr);
}

/**
 * Locate, verify, and return a handle to the AHCI device.
 */
QPCIDevice *get_ahci_device(uint32_t *fingerprint)
{
    QPCIDevice *ahci;
    uint32_t ahci_fingerprint;
    QPCIBus *pcibus;

    pcibus = qpci_init_pc();

    /* Find the AHCI PCI device and verify it's the right one. */
    ahci = qpci_device_find(pcibus, QPCI_DEVFN(0x1F, 0x02));
    g_assert(ahci != NULL);

    ahci_fingerprint = qpci_config_readl(ahci, PCI_VENDOR_ID);

    switch (ahci_fingerprint) {
    case AHCI_INTEL_ICH9:
        break;
    default:
        /* Unknown device. */
        g_assert_not_reached();
    }

    if (fingerprint) {
        *fingerprint = ahci_fingerprint;
    }
    return ahci;
}

void free_ahci_device(QPCIDevice *dev)
{
    QPCIBus *pcibus = dev ? dev->bus : NULL;

    /* libqos doesn't have a function for this, so free it manually */
    g_free(dev);
    qpci_free_pc(pcibus);
}

/*** Logical Device Initialization ***/

/**
 * Start the PCI device and sanity-check default operation.
 */
void ahci_pci_enable(AHCIQState *ahci)
{
    uint8_t reg;

    start_ahci_device(ahci);

    switch (ahci->fingerprint) {
    case AHCI_INTEL_ICH9:
        /* ICH9 has a register at PCI 0x92 that
         * acts as a master port enabler mask. */
        reg = qpci_config_readb(ahci->dev, 0x92);
        reg |= 0x3F;
        qpci_config_writeb(ahci->dev, 0x92, reg);
        /* 0...0111111b -- bit significant, ports 0-5 enabled. */
        ASSERT_BIT_SET(qpci_config_readb(ahci->dev, 0x92), 0x3F);
        break;
    }

}

/**
 * Map BAR5/ABAR, and engage the PCI device.
 */
void start_ahci_device(AHCIQState *ahci)
{
    /* Map AHCI's ABAR (BAR5) */
    ahci->hba_base = qpci_iomap(ahci->dev, 5, &ahci->barsize);
    g_assert(ahci->hba_base);

    /* turns on pci.cmd.iose, pci.cmd.mse and pci.cmd.bme */
    qpci_device_enable(ahci->dev);
}

/**
 * Test and initialize the AHCI's HBA memory areas.
 * Initialize and start any ports with devices attached.
 * Bring the HBA into the idle state.
 */
void ahci_hba_enable(AHCIQState *ahci)
{
    /* Bits of interest in this section:
     * GHC.AE     Global Host Control / AHCI Enable
     * PxCMD.ST   Port Command: Start
     * PxCMD.SUD  "Spin Up Device"
     * PxCMD.POD  "Power On Device"
     * PxCMD.FRE  "FIS Receive Enable"
     * PxCMD.FR   "FIS Receive Running"
     * PxCMD.CR   "Command List Running"
     */
    uint32_t reg, ports_impl;
    uint16_t i;
    uint8_t num_cmd_slots;

    g_assert(ahci != NULL);

    /* Set GHC.AE to 1 */
    ahci_set(ahci, AHCI_GHC, AHCI_GHC_AE);
    reg = ahci_rreg(ahci, AHCI_GHC);
    ASSERT_BIT_SET(reg, AHCI_GHC_AE);

    /* Cache CAP and CAP2. */
    ahci->cap = ahci_rreg(ahci, AHCI_CAP);
    ahci->cap2 = ahci_rreg(ahci, AHCI_CAP2);

    /* Read CAP.NCS, how many command slots do we have? */
    num_cmd_slots = ((ahci->cap & AHCI_CAP_NCS) >> ctzl(AHCI_CAP_NCS)) + 1;
    g_test_message("Number of Command Slots: %u", num_cmd_slots);

    /* Determine which ports are implemented. */
    ports_impl = ahci_rreg(ahci, AHCI_PI);

    for (i = 0; ports_impl; ports_impl >>= 1, ++i) {
        if (!(ports_impl & 0x01)) {
            continue;
        }

        g_test_message("Initializing port %u", i);

        reg = ahci_px_rreg(ahci, i, AHCI_PX_CMD);
        if (BITCLR(reg, AHCI_PX_CMD_ST | AHCI_PX_CMD_CR |
                   AHCI_PX_CMD_FRE | AHCI_PX_CMD_FR)) {
            g_test_message("port is idle");
        } else {
            g_test_message("port needs to be idled");
            ahci_px_clr(ahci, i, AHCI_PX_CMD,
                        (AHCI_PX_CMD_ST | AHCI_PX_CMD_FRE));
            /* The port has 500ms to disengage. */
            usleep(500000);
            reg = ahci_px_rreg(ahci, i, AHCI_PX_CMD);
            ASSERT_BIT_CLEAR(reg, AHCI_PX_CMD_CR);
            ASSERT_BIT_CLEAR(reg, AHCI_PX_CMD_FR);
            g_test_message("port is now idle");
            /* The spec does allow for possibly needing a PORT RESET
             * or HBA reset if we fail to idle the port. */
        }

        /* Allocate Memory for the Command List Buffer & FIS Buffer */
        /* PxCLB space ... 0x20 per command, as in 4.2.2 p 36 */
        ahci->port[i].clb = ahci_alloc(ahci, num_cmd_slots * 0x20);
        qmemset(ahci->port[i].clb, 0x00, 0x100);
        g_test_message("CLB: 0x%08" PRIx64, ahci->port[i].clb);
        ahci_px_wreg(ahci, i, AHCI_PX_CLB, ahci->port[i].clb);
        g_assert_cmphex(ahci->port[i].clb, ==,
                        ahci_px_rreg(ahci, i, AHCI_PX_CLB));

        /* PxFB space ... 0x100, as in 4.2.1 p 35 */
        ahci->port[i].fb = ahci_alloc(ahci, 0x100);
        qmemset(ahci->port[i].fb, 0x00, 0x100);
        g_test_message("FB: 0x%08" PRIx64, ahci->port[i].fb);
        ahci_px_wreg(ahci, i, AHCI_PX_FB, ahci->port[i].fb);
        g_assert_cmphex(ahci->port[i].fb, ==,
                        ahci_px_rreg(ahci, i, AHCI_PX_FB));

        /* Clear PxSERR, PxIS, then IS.IPS[x] by writing '1's. */
        ahci_px_wreg(ahci, i, AHCI_PX_SERR, 0xFFFFFFFF);
        ahci_px_wreg(ahci, i, AHCI_PX_IS, 0xFFFFFFFF);
        ahci_wreg(ahci, AHCI_IS, (1 << i));

        /* Verify Interrupts Cleared */
        reg = ahci_px_rreg(ahci, i, AHCI_PX_SERR);
        g_assert_cmphex(reg, ==, 0);

        reg = ahci_px_rreg(ahci, i, AHCI_PX_IS);
        g_assert_cmphex(reg, ==, 0);

        reg = ahci_rreg(ahci, AHCI_IS);
        ASSERT_BIT_CLEAR(reg, (1 << i));

        /* Enable All Interrupts: */
        ahci_px_wreg(ahci, i, AHCI_PX_IE, 0xFFFFFFFF);
        reg = ahci_px_rreg(ahci, i, AHCI_PX_IE);
        g_assert_cmphex(reg, ==, ~((uint32_t)AHCI_PX_IE_RESERVED));

        /* Enable the FIS Receive Engine. */
        ahci_px_set(ahci, i, AHCI_PX_CMD, AHCI_PX_CMD_FRE);
        reg = ahci_px_rreg(ahci, i, AHCI_PX_CMD);
        ASSERT_BIT_SET(reg, AHCI_PX_CMD_FR);

        /* AHCI 1.3 spec: if !STS.BSY, !STS.DRQ and PxSSTS.DET indicates
         * physical presence, a device is present and may be started. However,
         * PxSERR.DIAG.X /may/ need to be cleared a priori. */
        reg = ahci_px_rreg(ahci, i, AHCI_PX_SERR);
        if (BITSET(reg, AHCI_PX_SERR_DIAG_X)) {
            ahci_px_set(ahci, i, AHCI_PX_SERR, AHCI_PX_SERR_DIAG_X);
        }

        reg = ahci_px_rreg(ahci, i, AHCI_PX_TFD);
        if (BITCLR(reg, AHCI_PX_TFD_STS_BSY | AHCI_PX_TFD_STS_DRQ)) {
            reg = ahci_px_rreg(ahci, i, AHCI_PX_SSTS);
            if ((reg & AHCI_PX_SSTS_DET) == SSTS_DET_ESTABLISHED) {
                /* Device Found: set PxCMD.ST := 1 */
                ahci_px_set(ahci, i, AHCI_PX_CMD, AHCI_PX_CMD_ST);
                ASSERT_BIT_SET(ahci_px_rreg(ahci, i, AHCI_PX_CMD),
                               AHCI_PX_CMD_CR);
                g_test_message("Started Device %u", i);
            } else if ((reg & AHCI_PX_SSTS_DET)) {
                /* Device present, but in some unknown state. */
                g_assert_not_reached();
            }
        }
    }

    /* Enable GHC.IE */
    ahci_set(ahci, AHCI_GHC, AHCI_GHC_IE);
    reg = ahci_rreg(ahci, AHCI_GHC);
    ASSERT_BIT_SET(reg, AHCI_GHC_IE);

    /* TODO: The device should now be idling and waiting for commands.
     * In the future, a small test-case to inspect the Register D2H FIS
     * and clear the initial interrupts might be good. */
}

/**
 * Pick the first implemented and running port
 */
unsigned ahci_port_select(AHCIQState *ahci)
{
    uint32_t ports, reg;
    unsigned i;

    ports = ahci_rreg(ahci, AHCI_PI);
    for (i = 0; i < 32; ports >>= 1, ++i) {
        if (ports == 0) {
            i = 32;
        }

        if (!(ports & 0x01)) {
            continue;
        }

        reg = ahci_px_rreg(ahci, i, AHCI_PX_CMD);
        if (BITSET(reg, AHCI_PX_CMD_ST)) {
            break;
        }
    }
    g_assert(i < 32);
    return i;
}

/**
 * Clear a port's interrupts and status information prior to a test.
 */
void ahci_port_clear(AHCIQState *ahci, uint8_t port)
{
    uint32_t reg;

    /* Clear out this port's interrupts (ignore the init register d2h fis) */
    reg = ahci_px_rreg(ahci, port, AHCI_PX_IS);
    ahci_px_wreg(ahci, port, AHCI_PX_IS, reg);
    g_assert_cmphex(ahci_px_rreg(ahci, port, AHCI_PX_IS), ==, 0);

    /* Wipe the FIS-Recieve Buffer */
    qmemset(ahci->port[port].fb, 0x00, 0x100);
}

/**
 * Check a port for errors.
 */
void ahci_port_check_error(AHCIQState *ahci, uint8_t port)
{
    uint32_t reg;

    /* The upper 9 bits of the IS register all indicate errors. */
    reg = ahci_px_rreg(ahci, port, AHCI_PX_IS);
    reg >>= 23;
    g_assert_cmphex(reg, ==, 0);

    /* The Sata Error Register should be empty. */
    reg = ahci_px_rreg(ahci, port, AHCI_PX_SERR);
    g_assert_cmphex(reg, ==, 0);

    /* The TFD also has two error sections. */
    reg = ahci_px_rreg(ahci, port, AHCI_PX_TFD);
    ASSERT_BIT_CLEAR(reg, AHCI_PX_TFD_STS_ERR);
    ASSERT_BIT_CLEAR(reg, AHCI_PX_TFD_ERR);
}

void ahci_port_check_interrupts(AHCIQState *ahci, uint8_t port,
                                uint32_t intr_mask)
{
    uint32_t reg;

    /* Check for expected interrupts */
    reg = ahci_px_rreg(ahci, port, AHCI_PX_IS);
    ASSERT_BIT_SET(reg, intr_mask);

    /* Clear expected interrupts and assert all interrupts now cleared. */
    ahci_px_wreg(ahci, port, AHCI_PX_IS, intr_mask);
    g_assert_cmphex(ahci_px_rreg(ahci, port, AHCI_PX_IS), ==, 0);
}

/* Get the command in #slot of port #port. */
void ahci_get_command_header(AHCIQState *ahci, uint8_t port,
                             uint8_t slot, AHCICommandHeader *cmd)
{
    uint64_t ba = ahci->port[port].clb;
    ba += slot * sizeof(AHCICommandHeader);
    memread(ba, cmd, sizeof(AHCICommandHeader));

    cmd->flags = le16_to_cpu(cmd->flags);
    cmd->prdtl = le16_to_cpu(cmd->prdtl);
    cmd->prdbc = le32_to_cpu(cmd->prdbc);
    cmd->ctba = le64_to_cpu(cmd->ctba);
}

/* Set the command in #slot of port #port. */
void ahci_set_command_header(AHCIQState *ahci, uint8_t port,
                             uint8_t slot, AHCICommandHeader *cmd)
{
    AHCICommandHeader tmp;
    uint64_t ba = ahci->port[port].clb;
    ba += slot * sizeof(AHCICommandHeader);

    tmp.flags = cpu_to_le16(cmd->flags);
    tmp.prdtl = cpu_to_le16(cmd->prdtl);
    tmp.prdbc = cpu_to_le32(cmd->prdbc);
    tmp.ctba = cpu_to_le64(cmd->ctba);

    memwrite(ba, &tmp, sizeof(AHCICommandHeader));
}

void ahci_destroy_command(AHCIQState *ahci, uint8_t port, uint8_t slot)
{
    AHCICommandHeader cmd;

    /* Obtain the Nth Command Header */
    ahci_get_command_header(ahci, port, slot, &cmd);
    if (cmd.ctba == 0) {
        /* No address in it, so just return -- it's empty. */
        goto tidy;
    }

    /* Free the Table */
    ahci_free(ahci, cmd.ctba);

 tidy:
    /* NULL the header. */
    memset(&cmd, 0x00, sizeof(cmd));
    ahci_set_command_header(ahci, port, slot, &cmd);
    ahci->port[port].ctba[slot] = 0;
    ahci->port[port].prdtl[slot] = 0;
}

unsigned ahci_pick_cmd(AHCIQState *ahci, uint8_t port)
{
    unsigned i;
    unsigned j;
    uint32_t reg;

    reg = ahci_px_rreg(ahci, port, AHCI_PX_CI);

    /* Pick the least recently used command slot that's available */
    for (i = 0; i < 32; ++i) {
        j = ((ahci->port[port].next + i) % 32);
        if (reg & (1 << j)) {
            continue;
        }
        ahci_destroy_command(ahci, port, i);
        ahci->port[port].next = (j + 1) % 32;
        return j;
    }

    g_test_message("All command slots were busy.");
    g_assert_not_reached();
}
