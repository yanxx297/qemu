/*
 * QEMU sPAPR IOMMU (TCE) code
 *
 * Copyright (c) 2010 David Gibson, IBM Corporation <dwg@au1.ibm.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "hw.h"
#include "kvm.h"
#include "qdev.h"
#include "kvm_ppc.h"
#include "dma.h"

#include "hw/spapr.h"

#include <libfdt.h>

/* #define DEBUG_TCE */

enum sPAPRTCEAccess {
    SPAPR_TCE_FAULT = 0,
    SPAPR_TCE_RO = 1,
    SPAPR_TCE_WO = 2,
    SPAPR_TCE_RW = 3,
};

typedef struct sPAPRTCETable sPAPRTCETable;

struct sPAPRTCETable {
    DMAContext dma;
    uint32_t liobn;
    uint32_t window_size;
    sPAPRTCE *table;
    int fd;
    QLIST_ENTRY(sPAPRTCETable) list;
};


QLIST_HEAD(spapr_tce_tables, sPAPRTCETable) spapr_tce_tables;

static sPAPRTCETable *spapr_tce_find_by_liobn(uint32_t liobn)
{
    sPAPRTCETable *tcet;

    QLIST_FOREACH(tcet, &spapr_tce_tables, list) {
        if (tcet->liobn == liobn) {
            return tcet;
        }
    }

    return NULL;
}

static int spapr_tce_translate(DMAContext *dma,
                               dma_addr_t addr,
                               target_phys_addr_t *paddr,
                               target_phys_addr_t *len,
                               DMADirection dir)
{
    sPAPRTCETable *tcet = DO_UPCAST(sPAPRTCETable, dma, dma);
    enum sPAPRTCEAccess access = (dir == DMA_DIRECTION_FROM_DEVICE)
        ? SPAPR_TCE_WO : SPAPR_TCE_RO;
    uint64_t tce;

#ifdef DEBUG_TCE
    fprintf(stderr, "spapr_tce_translate liobn=0x%" PRIx32 " addr=0x"
            DMA_ADDR_FMT "\n", tcet->liobn, addr);
#endif

    /* Check if we are in bound */
    if (addr >= tcet->window_size) {
#ifdef DEBUG_TCE
        fprintf(stderr, "spapr_tce_translate out of bounds\n");
#endif
        return -EFAULT;
    }

    tce = tcet->table[addr >> SPAPR_TCE_PAGE_SHIFT].tce;

    /* Check TCE */
    if (!(tce & access)) {
        return -EPERM;
    }

    /* How much til end of page ? */
    *len = ((~addr) & SPAPR_TCE_PAGE_MASK) + 1;

    /* Translate */
    *paddr = (tce & ~SPAPR_TCE_PAGE_MASK) |
        (addr & SPAPR_TCE_PAGE_MASK);

#ifdef DEBUG_TCE
    fprintf(stderr, " ->  *paddr=0x" TARGET_FMT_plx ", *len=0x"
            TARGET_FMT_plx "\n", *paddr, *len);
#endif

    return 0;
}

DMAContext *spapr_tce_new_dma_context(uint32_t liobn, size_t window_size)
{
    sPAPRTCETable *tcet;

    if (!window_size) {
        return NULL;
    }

    tcet = g_malloc0(sizeof(*tcet));
    dma_context_init(&tcet->dma, spapr_tce_translate, NULL, NULL);

    tcet->liobn = liobn;
    tcet->window_size = window_size;

    if (kvm_enabled()) {
        tcet->table = kvmppc_create_spapr_tce(liobn,
                                              window_size,
                                              &tcet->fd);
    }

    if (!tcet->table) {
        size_t table_size = (window_size >> SPAPR_TCE_PAGE_SHIFT)
            * sizeof(sPAPRTCE);
        tcet->table = g_malloc0(table_size);
    }

#ifdef DEBUG_TCE
    fprintf(stderr, "spapr_iommu: New TCE table, liobn=0x%x, context @ %p, "
            "table @ %p, fd=%d\n", liobn, &tcet->dma, tcet->table, tcet->fd);
#endif

    QLIST_INSERT_HEAD(&spapr_tce_tables, tcet, list);

    return &tcet->dma;
}

void spapr_tce_free(DMAContext *dma)
{

    if (dma) {
        sPAPRTCETable *tcet = DO_UPCAST(sPAPRTCETable, dma, dma);

        QLIST_REMOVE(tcet, list);

        if (!kvm_enabled() ||
            (kvmppc_remove_spapr_tce(tcet->table, tcet->fd,
                                     tcet->window_size) != 0)) {
            g_free(tcet->table);
        }

        g_free(tcet);
    }
}


static target_ulong h_put_tce(CPUPPCState *env, sPAPREnvironment *spapr,
                              target_ulong opcode, target_ulong *args)
{
    target_ulong liobn = args[0];
    target_ulong ioba = args[1];
    target_ulong tce = args[2];
    sPAPRTCETable *tcet = spapr_tce_find_by_liobn(liobn);
    sPAPRTCE *tcep;

    if (liobn & 0xFFFFFFFF00000000ULL) {
        hcall_dprintf("spapr_vio_put_tce on out-of-boundsw LIOBN "
                      TARGET_FMT_lx "\n", liobn);
        return H_PARAMETER;
    }
    if (!tcet) {
        hcall_dprintf("spapr_vio_put_tce on non-existent LIOBN "
                      TARGET_FMT_lx "\n", liobn);
        return H_PARAMETER;
    }

    ioba &= ~(SPAPR_TCE_PAGE_SIZE - 1);

#ifdef DEBUG_TCE
    fprintf(stderr, "spapr_vio_put_tce on liobn=" TARGET_FMT_lx /*%s*/
            "  ioba 0x" TARGET_FMT_lx "  TCE 0x" TARGET_FMT_lx "\n",
            liobn, /*dev->qdev.id, */ioba, tce);
#endif

    if (ioba >= tcet->window_size) {
        hcall_dprintf("spapr_vio_put_tce on out-of-boards IOBA 0x"
                      TARGET_FMT_lx "\n", ioba);
        return H_PARAMETER;
    }

    tcep = tcet->table + (ioba >> SPAPR_TCE_PAGE_SHIFT);
    tcep->tce = tce;

    return H_SUCCESS;
}

void spapr_iommu_init(void)
{
    QLIST_INIT(&spapr_tce_tables);

    /* hcall-tce */
    spapr_register_hypercall(H_PUT_TCE, h_put_tce);
}

int spapr_dma_dt(void *fdt, int node_off, const char *propname,
                 DMAContext *dma)
{
    if (dma) {
        sPAPRTCETable *tcet = DO_UPCAST(sPAPRTCETable, dma, dma);
        uint32_t dma_prop[] = {cpu_to_be32(tcet->liobn),
                               0, 0,
                               0, cpu_to_be32(tcet->window_size)};
        int ret;

        ret = fdt_setprop_cell(fdt, node_off, "ibm,#dma-address-cells", 2);
        if (ret < 0) {
            return ret;
        }

        ret = fdt_setprop_cell(fdt, node_off, "ibm,#dma-size-cells", 2);
        if (ret < 0) {
            return ret;
        }

        ret = fdt_setprop(fdt, node_off, propname, dma_prop,
                          sizeof(dma_prop));
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}
