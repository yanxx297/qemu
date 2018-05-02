/*
 * Generic PKUnity SoC machine and board descriptor
 *
 * Copyright (C) 2010-2012 Guan Xuetao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation, or any later version.
 * See the COPYING file in the top-level directory.
 */
#include "console.h"
#include "elf.h"
#include "exec-memory.h"
#include "sysbus.h"
#include "boards.h"
#include "loader.h"
#include "pc.h"

#undef DEBUG_PUV3
#include "puv3.h"

#define KERNEL_LOAD_ADDR        0x03000000
#define KERNEL_MAX_SIZE         0x00800000 /* Just a guess */

static void puv3_soc_init(CPUUniCore32State *env)
{
    /* TODO */
}

static void puv3_board_init(CPUUniCore32State *env, ram_addr_t ram_size)
{
    MemoryRegion *ram_memory = g_new(MemoryRegion, 1);

    /* SDRAM at address zero.  */
    memory_region_init_ram(ram_memory, "puv3.ram", ram_size);
    vmstate_register_ram_global(ram_memory);
    memory_region_add_subregion(get_system_memory(), 0, ram_memory);
}

static void puv3_load_kernel(const char *kernel_filename)
{
    int size;

    assert(kernel_filename != NULL);

    /* only zImage format supported */
    size = load_image_targphys(kernel_filename, KERNEL_LOAD_ADDR,
            KERNEL_MAX_SIZE);
    if (size < 0) {
        hw_error("Load kernel error: '%s'\n", kernel_filename);
    }

    /* cheat curses that we have a graphic console, only under ocd console */
    graphic_console_init(NULL, NULL, NULL, NULL, NULL);
}

static void puv3_init(ram_addr_t ram_size, const char *boot_device,
                     const char *kernel_filename, const char *kernel_cmdline,
                     const char *initrd_filename, const char *cpu_model)
{
    CPUUniCore32State *env;

    if (initrd_filename) {
        hw_error("Please use kernel built-in initramdisk.\n");
    }

    if (!cpu_model) {
        cpu_model = "UniCore-II";
    }

    env = cpu_init(cpu_model);
    if (!env) {
        hw_error("Unable to find CPU definition\n");
    }

    puv3_soc_init(env);
    puv3_board_init(env, ram_size);
    puv3_load_kernel(kernel_filename);
}

static QEMUMachine puv3_machine = {
    .name = "puv3",
    .desc = "PKUnity Version-3 based on UniCore32",
    .init = puv3_init,
    .use_scsi = 0,
};

static void puv3_machine_init(void)
{
    qemu_register_machine(&puv3_machine);
}

machine_init(puv3_machine_init)
