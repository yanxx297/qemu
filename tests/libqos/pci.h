/*
 * libqos PCI bindings
 *
 * Copyright IBM, Corp. 2012-2013
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef LIBQOS_PCI_H
#define LIBQOS_PCI_H

#include "libqtest.h"

#define QPCI_PIO_LIMIT    0x10000

#define QPCI_DEVFN(dev, fn) (((dev) << 3) | (fn))

typedef struct QPCIDevice QPCIDevice;
typedef struct QPCIBus QPCIBus;

struct QPCIBus {
    uint8_t (*pio_readb)(QPCIBus *bus, uint32_t addr);
    uint16_t (*pio_readw)(QPCIBus *bus, uint32_t addr);
    uint32_t (*pio_readl)(QPCIBus *bus, uint32_t addr);

    uint8_t (*mmio_readb)(QPCIBus *bus, uint32_t addr);
    uint16_t (*mmio_readw)(QPCIBus *bus, uint32_t addr);
    uint32_t (*mmio_readl)(QPCIBus *bus, uint32_t addr);

    void (*pio_writeb)(QPCIBus *bus, uint32_t addr, uint8_t value);
    void (*pio_writew)(QPCIBus *bus, uint32_t addr, uint16_t value);
    void (*pio_writel)(QPCIBus *bus, uint32_t addr, uint32_t value);

    void (*mmio_writeb)(QPCIBus *bus, uint32_t addr, uint8_t value);
    void (*mmio_writew)(QPCIBus *bus, uint32_t addr, uint16_t value);
    void (*mmio_writel)(QPCIBus *bus, uint32_t addr, uint32_t value);

    uint8_t (*config_readb)(QPCIBus *bus, int devfn, uint8_t offset);
    uint16_t (*config_readw)(QPCIBus *bus, int devfn, uint8_t offset);
    uint32_t (*config_readl)(QPCIBus *bus, int devfn, uint8_t offset);

    void (*config_writeb)(QPCIBus *bus, int devfn,
                          uint8_t offset, uint8_t value);
    void (*config_writew)(QPCIBus *bus, int devfn,
                          uint8_t offset, uint16_t value);
    void (*config_writel)(QPCIBus *bus, int devfn,
                          uint8_t offset, uint32_t value);

    uint16_t pio_alloc_ptr;
    uint64_t mmio_alloc_ptr, mmio_limit;
};

struct QPCIDevice
{
    QPCIBus *bus;
    int devfn;
    bool msix_enabled;
    void *msix_table;
    void *msix_pba;
};

void qpci_device_foreach(QPCIBus *bus, int vendor_id, int device_id,
                         void (*func)(QPCIDevice *dev, int devfn, void *data),
                         void *data);
QPCIDevice *qpci_device_find(QPCIBus *bus, int devfn);

void qpci_device_enable(QPCIDevice *dev);
uint8_t qpci_find_capability(QPCIDevice *dev, uint8_t id);
void qpci_msix_enable(QPCIDevice *dev);
void qpci_msix_disable(QPCIDevice *dev);
bool qpci_msix_pending(QPCIDevice *dev, uint16_t entry);
bool qpci_msix_masked(QPCIDevice *dev, uint16_t entry);
uint16_t qpci_msix_table_size(QPCIDevice *dev);

uint8_t qpci_config_readb(QPCIDevice *dev, uint8_t offset);
uint16_t qpci_config_readw(QPCIDevice *dev, uint8_t offset);
uint32_t qpci_config_readl(QPCIDevice *dev, uint8_t offset);

void qpci_config_writeb(QPCIDevice *dev, uint8_t offset, uint8_t value);
void qpci_config_writew(QPCIDevice *dev, uint8_t offset, uint16_t value);
void qpci_config_writel(QPCIDevice *dev, uint8_t offset, uint32_t value);

uint8_t qpci_io_readb(QPCIDevice *dev, void *data);
uint16_t qpci_io_readw(QPCIDevice *dev, void *data);
uint32_t qpci_io_readl(QPCIDevice *dev, void *data);

void qpci_io_writeb(QPCIDevice *dev, void *data, uint8_t value);
void qpci_io_writew(QPCIDevice *dev, void *data, uint16_t value);
void qpci_io_writel(QPCIDevice *dev, void *data, uint32_t value);

void *qpci_iomap(QPCIDevice *dev, int barno, uint64_t *sizeptr);
void qpci_iounmap(QPCIDevice *dev, void *data);
void *qpci_legacy_iomap(QPCIDevice *dev, uint16_t addr);

void qpci_plug_device_test(const char *driver, const char *id,
                           uint8_t slot, const char *opts);
void qpci_unplug_acpi_device_test(const char *id, uint8_t slot);
#endif
