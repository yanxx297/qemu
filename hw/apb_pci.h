#ifndef APB_PCI_H
#define APB_PCI_H

#include "qemu-common.h"

PCIBus *pci_apb_init(hwaddr special_base,
                     hwaddr mem_base,
                     qemu_irq *ivec_irqs, PCIBus **bus2, PCIBus **bus3,
                     qemu_irq **pbm_irqs);
#endif
