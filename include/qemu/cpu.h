/*
 * QEMU CPU model
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 */
#ifndef QEMU_CPU_H
#define QEMU_CPU_H

#include "qemu/object.h"
#include "qemu-thread.h"

/**
 * SECTION:cpu
 * @section_id: QEMU-cpu
 * @title: CPU Class
 * @short_description: Base class for all CPUs
 */

#define TYPE_CPU "cpu"

#define CPU(obj) OBJECT_CHECK(CPUState, (obj), TYPE_CPU)
#define CPU_CLASS(class) OBJECT_CLASS_CHECK(CPUClass, (class), TYPE_CPU)
#define CPU_GET_CLASS(obj) OBJECT_GET_CLASS(CPUClass, (obj), TYPE_CPU)

typedef struct CPUState CPUState;

/**
 * CPUClass:
 * @reset: Callback to reset the #CPUState to its initial state.
 *
 * Represents a CPU family or model.
 */
typedef struct CPUClass {
    /*< private >*/
    ObjectClass parent_class;
    /*< public >*/

    void (*reset)(CPUState *cpu);
} CPUClass;

/**
 * CPUState:
 * @created: Indicates whether the CPU thread has been successfully created.
 * @stop: Indicates a pending stop request.
 * @stopped: Indicates the CPU has been artificially stopped.
 *
 * State of one CPU core or thread.
 */
struct CPUState {
    /*< private >*/
    Object parent_obj;
    /*< public >*/

    struct QemuThread *thread;
#ifdef _WIN32
    HANDLE hThread;
#endif
    bool thread_kicked;
    bool created;
    bool stop;
    bool stopped;

    /* TODO Move common fields from CPUArchState here. */
};


/**
 * cpu_reset:
 * @cpu: The CPU whose state is to be reset.
 */
void cpu_reset(CPUState *cpu);

/**
 * qemu_cpu_is_self:
 * @cpu: The vCPU to check against.
 *
 * Checks whether the caller is executing on the vCPU thread.
 *
 * Returns: %true if called from @cpu's thread, %false otherwise.
 */
bool qemu_cpu_is_self(CPUState *cpu);


#endif
