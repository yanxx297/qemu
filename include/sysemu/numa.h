#ifndef SYSEMU_NUMA_H
#define SYSEMU_NUMA_H

#include <stdint.h>
#include "qemu/bitmap.h"
#include "qemu/option.h"
#include "sysemu/sysemu.h"
#include "sysemu/hostmem.h"

extern int nb_numa_nodes;   /* Number of NUMA nodes */

typedef struct node_info {
    uint64_t node_mem;
    DECLARE_BITMAP(node_cpu, MAX_CPUMASK_BITS);
    struct HostMemoryBackend *node_memdev;
    bool present;
} NodeInfo;
extern NodeInfo numa_info[MAX_NODES];
void set_numa_nodes(void);
void set_numa_modes(void);
void query_numa_node_mem(uint64_t node_mem[]);
extern QemuOptsList qemu_numa_opts;

#endif
