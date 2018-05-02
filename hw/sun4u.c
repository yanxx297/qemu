/*
 * QEMU Sun4u/Sun4v System Emulator
 *
 * Copyright (c) 2005 Fabrice Bellard
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
#include "hw.h"
#include "pci/pci.h"
#include "apb_pci.h"
#include "pc.h"
#include "serial.h"
#include "nvram.h"
#include "fdc.h"
#include "net/net.h"
#include "qemu/timer.h"
#include "sysemu/sysemu.h"
#include "boards.h"
#include "firmware_abi.h"
#include "fw_cfg.h"
#include "sysbus.h"
#include "ide.h"
#include "loader.h"
#include "elf.h"
#include "sysemu/blockdev.h"
#include "exec/address-spaces.h"

//#define DEBUG_IRQ
//#define DEBUG_EBUS
//#define DEBUG_TIMER

#ifdef DEBUG_IRQ
#define CPUIRQ_DPRINTF(fmt, ...)                                \
    do { printf("CPUIRQ: " fmt , ## __VA_ARGS__); } while (0)
#else
#define CPUIRQ_DPRINTF(fmt, ...)
#endif

#ifdef DEBUG_EBUS
#define EBUS_DPRINTF(fmt, ...)                                  \
    do { printf("EBUS: " fmt , ## __VA_ARGS__); } while (0)
#else
#define EBUS_DPRINTF(fmt, ...)
#endif

#ifdef DEBUG_TIMER
#define TIMER_DPRINTF(fmt, ...)                                  \
    do { printf("TIMER: " fmt , ## __VA_ARGS__); } while (0)
#else
#define TIMER_DPRINTF(fmt, ...)
#endif

#define KERNEL_LOAD_ADDR     0x00404000
#define CMDLINE_ADDR         0x003ff000
#define PROM_SIZE_MAX        (4 * 1024 * 1024)
#define PROM_VADDR           0x000ffd00000ULL
#define APB_SPECIAL_BASE     0x1fe00000000ULL
#define APB_MEM_BASE         0x1ff00000000ULL
#define APB_PCI_IO_BASE      (APB_SPECIAL_BASE + 0x02000000ULL)
#define PROM_FILENAME        "openbios-sparc64"
#define NVRAM_SIZE           0x2000
#define MAX_IDE_BUS          2
#define BIOS_CFG_IOPORT      0x510
#define FW_CFG_SPARC64_WIDTH (FW_CFG_ARCH_LOCAL + 0x00)
#define FW_CFG_SPARC64_HEIGHT (FW_CFG_ARCH_LOCAL + 0x01)
#define FW_CFG_SPARC64_DEPTH (FW_CFG_ARCH_LOCAL + 0x02)

#define IVEC_MAX             0x30

#define TICK_MAX             0x7fffffffffffffffULL

struct hwdef {
    const char * const default_cpu_model;
    uint16_t machine_id;
    uint64_t prom_addr;
    uint64_t console_serial_base;
};

typedef struct EbusState {
    PCIDevice pci_dev;
    MemoryRegion bar0;
    MemoryRegion bar1;
} EbusState;

int DMA_get_channel_mode (int nchan)
{
    return 0;
}
int DMA_read_memory (int nchan, void *buf, int pos, int size)
{
    return 0;
}
int DMA_write_memory (int nchan, void *buf, int pos, int size)
{
    return 0;
}
void DMA_hold_DREQ (int nchan) {}
void DMA_release_DREQ (int nchan) {}
void DMA_schedule(int nchan) {}

void DMA_init(int high_page_enable, qemu_irq *cpu_request_exit)
{
}

void DMA_register_channel (int nchan,
                           DMA_transfer_handler transfer_handler,
                           void *opaque)
{
}

static int fw_cfg_boot_set(void *opaque, const char *boot_device)
{
    fw_cfg_add_i16(opaque, FW_CFG_BOOT_DEVICE, boot_device[0]);
    return 0;
}

static int sun4u_NVRAM_set_params(M48t59State *nvram, uint16_t NVRAM_size,
                                  const char *arch, ram_addr_t RAM_size,
                                  const char *boot_devices,
                                  uint32_t kernel_image, uint32_t kernel_size,
                                  const char *cmdline,
                                  uint32_t initrd_image, uint32_t initrd_size,
                                  uint32_t NVRAM_image,
                                  int width, int height, int depth,
                                  const uint8_t *macaddr)
{
    unsigned int i;
    uint32_t start, end;
    uint8_t image[0x1ff0];
    struct OpenBIOS_nvpart_v1 *part_header;

    memset(image, '\0', sizeof(image));

    start = 0;

    // OpenBIOS nvram variables
    // Variable partition
    part_header = (struct OpenBIOS_nvpart_v1 *)&image[start];
    part_header->signature = OPENBIOS_PART_SYSTEM;
    pstrcpy(part_header->name, sizeof(part_header->name), "system");

    end = start + sizeof(struct OpenBIOS_nvpart_v1);
    for (i = 0; i < nb_prom_envs; i++)
        end = OpenBIOS_set_var(image, end, prom_envs[i]);

    // End marker
    image[end++] = '\0';

    end = start + ((end - start + 15) & ~15);
    OpenBIOS_finish_partition(part_header, end - start);

    // free partition
    start = end;
    part_header = (struct OpenBIOS_nvpart_v1 *)&image[start];
    part_header->signature = OPENBIOS_PART_FREE;
    pstrcpy(part_header->name, sizeof(part_header->name), "free");

    end = 0x1fd0;
    OpenBIOS_finish_partition(part_header, end - start);

    Sun_init_header((struct Sun_nvram *)&image[0x1fd8], macaddr, 0x80);

    for (i = 0; i < sizeof(image); i++)
        m48t59_write(nvram, i, image[i]);

    return 0;
}

static uint64_t sun4u_load_kernel(const char *kernel_filename,
                                  const char *initrd_filename,
                                  ram_addr_t RAM_size, uint64_t *initrd_size,
                                  uint64_t *initrd_addr, uint64_t *kernel_addr,
                                  uint64_t *kernel_entry)
{
    int linux_boot;
    unsigned int i;
    long kernel_size;
    uint8_t *ptr;
    uint64_t kernel_top;

    linux_boot = (kernel_filename != NULL);

    kernel_size = 0;
    if (linux_boot) {
        int bswap_needed;

#ifdef BSWAP_NEEDED
        bswap_needed = 1;
#else
        bswap_needed = 0;
#endif
        kernel_size = load_elf(kernel_filename, NULL, NULL, kernel_entry,
                               kernel_addr, &kernel_top, 1, ELF_MACHINE, 0);
        if (kernel_size < 0) {
            *kernel_addr = KERNEL_LOAD_ADDR;
            *kernel_entry = KERNEL_LOAD_ADDR;
            kernel_size = load_aout(kernel_filename, KERNEL_LOAD_ADDR,
                                    RAM_size - KERNEL_LOAD_ADDR, bswap_needed,
                                    TARGET_PAGE_SIZE);
        }
        if (kernel_size < 0) {
            kernel_size = load_image_targphys(kernel_filename,
                                              KERNEL_LOAD_ADDR,
                                              RAM_size - KERNEL_LOAD_ADDR);
        }
        if (kernel_size < 0) {
            fprintf(stderr, "qemu: could not load kernel '%s'\n",
                    kernel_filename);
            exit(1);
        }
        /* load initrd above kernel */
        *initrd_size = 0;
        if (initrd_filename) {
            *initrd_addr = TARGET_PAGE_ALIGN(kernel_top);

            *initrd_size = load_image_targphys(initrd_filename,
                                               *initrd_addr,
                                               RAM_size - *initrd_addr);
            if ((int)*initrd_size < 0) {
                fprintf(stderr, "qemu: could not load initial ram disk '%s'\n",
                        initrd_filename);
                exit(1);
            }
        }
        if (*initrd_size > 0) {
            for (i = 0; i < 64 * TARGET_PAGE_SIZE; i += TARGET_PAGE_SIZE) {
                ptr = rom_ptr(*kernel_addr + i);
                if (ldl_p(ptr + 8) == 0x48647253) { /* HdrS */
                    stl_p(ptr + 24, *initrd_addr + *kernel_addr);
                    stl_p(ptr + 28, *initrd_size);
                    break;
                }
            }
        }
    }
    return kernel_size;
}

void cpu_check_irqs(CPUSPARCState *env)
{
    uint32_t pil = env->pil_in |
                  (env->softint & ~(SOFTINT_TIMER | SOFTINT_STIMER));

    /* TT_IVEC has a higher priority (16) than TT_EXTINT (31..17) */
    if (env->ivec_status & 0x20) {
        return;
    }
    /* check if TM or SM in SOFTINT are set
       setting these also causes interrupt 14 */
    if (env->softint & (SOFTINT_TIMER | SOFTINT_STIMER)) {
        pil |= 1 << 14;
    }

    /* The bit corresponding to psrpil is (1<< psrpil), the next bit
       is (2 << psrpil). */
    if (pil < (2 << env->psrpil)){
        if (env->interrupt_request & CPU_INTERRUPT_HARD) {
            CPUIRQ_DPRINTF("Reset CPU IRQ (current interrupt %x)\n",
                           env->interrupt_index);
            env->interrupt_index = 0;
            cpu_reset_interrupt(env, CPU_INTERRUPT_HARD);
        }
        return;
    }

    if (cpu_interrupts_enabled(env)) {

        unsigned int i;

        for (i = 15; i > env->psrpil; i--) {
            if (pil & (1 << i)) {
                int old_interrupt = env->interrupt_index;
                int new_interrupt = TT_EXTINT | i;

                if (unlikely(env->tl > 0 && cpu_tsptr(env)->tt > new_interrupt
                  && ((cpu_tsptr(env)->tt & 0x1f0) == TT_EXTINT))) {
                    CPUIRQ_DPRINTF("Not setting CPU IRQ: TL=%d "
                                   "current %x >= pending %x\n",
                                   env->tl, cpu_tsptr(env)->tt, new_interrupt);
                } else if (old_interrupt != new_interrupt) {
                    env->interrupt_index = new_interrupt;
                    CPUIRQ_DPRINTF("Set CPU IRQ %d old=%x new=%x\n", i,
                                   old_interrupt, new_interrupt);
                    cpu_interrupt(env, CPU_INTERRUPT_HARD);
                }
                break;
            }
        }
    } else if (env->interrupt_request & CPU_INTERRUPT_HARD) {
        CPUIRQ_DPRINTF("Interrupts disabled, pil=%08x pil_in=%08x softint=%08x "
                       "current interrupt %x\n",
                       pil, env->pil_in, env->softint, env->interrupt_index);
        env->interrupt_index = 0;
        cpu_reset_interrupt(env, CPU_INTERRUPT_HARD);
    }
}

static void cpu_kick_irq(SPARCCPU *cpu)
{
    CPUSPARCState *env = &cpu->env;

    env->halted = 0;
    cpu_check_irqs(env);
    qemu_cpu_kick(CPU(cpu));
}

static void cpu_set_ivec_irq(void *opaque, int irq, int level)
{
    SPARCCPU *cpu = opaque;
    CPUSPARCState *env = &cpu->env;

    if (level) {
        if (!(env->ivec_status & 0x20)) {
            CPUIRQ_DPRINTF("Raise IVEC IRQ %d\n", irq);
            env->halted = 0;
            env->interrupt_index = TT_IVEC;
            env->ivec_status |= 0x20;
            env->ivec_data[0] = (0x1f << 6) | irq;
            env->ivec_data[1] = 0;
            env->ivec_data[2] = 0;
            cpu_interrupt(env, CPU_INTERRUPT_HARD);
        }
    } else {
        if (env->ivec_status & 0x20) {
            CPUIRQ_DPRINTF("Lower IVEC IRQ %d\n", irq);
            env->ivec_status &= ~0x20;
            cpu_reset_interrupt(env, CPU_INTERRUPT_HARD);
        }
    }
}

typedef struct ResetData {
    SPARCCPU *cpu;
    uint64_t prom_addr;
} ResetData;

void cpu_put_timer(QEMUFile *f, CPUTimer *s)
{
    qemu_put_be32s(f, &s->frequency);
    qemu_put_be32s(f, &s->disabled);
    qemu_put_be64s(f, &s->disabled_mask);
    qemu_put_sbe64s(f, &s->clock_offset);

    qemu_put_timer(f, s->qtimer);
}

void cpu_get_timer(QEMUFile *f, CPUTimer *s)
{
    qemu_get_be32s(f, &s->frequency);
    qemu_get_be32s(f, &s->disabled);
    qemu_get_be64s(f, &s->disabled_mask);
    qemu_get_sbe64s(f, &s->clock_offset);

    qemu_get_timer(f, s->qtimer);
}

static CPUTimer *cpu_timer_create(const char *name, SPARCCPU *cpu,
                                  QEMUBHFunc *cb, uint32_t frequency,
                                  uint64_t disabled_mask)
{
    CPUTimer *timer = g_malloc0(sizeof (CPUTimer));

    timer->name = name;
    timer->frequency = frequency;
    timer->disabled_mask = disabled_mask;

    timer->disabled = 1;
    timer->clock_offset = qemu_get_clock_ns(vm_clock);

    timer->qtimer = qemu_new_timer_ns(vm_clock, cb, cpu);

    return timer;
}

static void cpu_timer_reset(CPUTimer *timer)
{
    timer->disabled = 1;
    timer->clock_offset = qemu_get_clock_ns(vm_clock);

    qemu_del_timer(timer->qtimer);
}

static void main_cpu_reset(void *opaque)
{
    ResetData *s = (ResetData *)opaque;
    CPUSPARCState *env = &s->cpu->env;
    static unsigned int nr_resets;

    cpu_reset(CPU(s->cpu));

    cpu_timer_reset(env->tick);
    cpu_timer_reset(env->stick);
    cpu_timer_reset(env->hstick);

    env->gregs[1] = 0; // Memory start
    env->gregs[2] = ram_size; // Memory size
    env->gregs[3] = 0; // Machine description XXX
    if (nr_resets++ == 0) {
        /* Power on reset */
        env->pc = s->prom_addr + 0x20ULL;
    } else {
        env->pc = s->prom_addr + 0x40ULL;
    }
    env->npc = env->pc + 4;
}

static void tick_irq(void *opaque)
{
    SPARCCPU *cpu = opaque;
    CPUSPARCState *env = &cpu->env;

    CPUTimer* timer = env->tick;

    if (timer->disabled) {
        CPUIRQ_DPRINTF("tick_irq: softint disabled\n");
        return;
    } else {
        CPUIRQ_DPRINTF("tick: fire\n");
    }

    env->softint |= SOFTINT_TIMER;
    cpu_kick_irq(cpu);
}

static void stick_irq(void *opaque)
{
    SPARCCPU *cpu = opaque;
    CPUSPARCState *env = &cpu->env;

    CPUTimer* timer = env->stick;

    if (timer->disabled) {
        CPUIRQ_DPRINTF("stick_irq: softint disabled\n");
        return;
    } else {
        CPUIRQ_DPRINTF("stick: fire\n");
    }

    env->softint |= SOFTINT_STIMER;
    cpu_kick_irq(cpu);
}

static void hstick_irq(void *opaque)
{
    SPARCCPU *cpu = opaque;
    CPUSPARCState *env = &cpu->env;

    CPUTimer* timer = env->hstick;

    if (timer->disabled) {
        CPUIRQ_DPRINTF("hstick_irq: softint disabled\n");
        return;
    } else {
        CPUIRQ_DPRINTF("hstick: fire\n");
    }

    env->softint |= SOFTINT_STIMER;
    cpu_kick_irq(cpu);
}

static int64_t cpu_to_timer_ticks(int64_t cpu_ticks, uint32_t frequency)
{
    return muldiv64(cpu_ticks, get_ticks_per_sec(), frequency);
}

static uint64_t timer_to_cpu_ticks(int64_t timer_ticks, uint32_t frequency)
{
    return muldiv64(timer_ticks, frequency, get_ticks_per_sec());
}

void cpu_tick_set_count(CPUTimer *timer, uint64_t count)
{
    uint64_t real_count = count & ~timer->disabled_mask;
    uint64_t disabled_bit = count & timer->disabled_mask;

    int64_t vm_clock_offset = qemu_get_clock_ns(vm_clock) -
                    cpu_to_timer_ticks(real_count, timer->frequency);

    TIMER_DPRINTF("%s set_count count=0x%016lx (%s) p=%p\n",
                  timer->name, real_count,
                  timer->disabled?"disabled":"enabled", timer);

    timer->disabled = disabled_bit ? 1 : 0;
    timer->clock_offset = vm_clock_offset;
}

uint64_t cpu_tick_get_count(CPUTimer *timer)
{
    uint64_t real_count = timer_to_cpu_ticks(
                    qemu_get_clock_ns(vm_clock) - timer->clock_offset,
                    timer->frequency);

    TIMER_DPRINTF("%s get_count count=0x%016lx (%s) p=%p\n",
           timer->name, real_count,
           timer->disabled?"disabled":"enabled", timer);

    if (timer->disabled)
        real_count |= timer->disabled_mask;

    return real_count;
}

void cpu_tick_set_limit(CPUTimer *timer, uint64_t limit)
{
    int64_t now = qemu_get_clock_ns(vm_clock);

    uint64_t real_limit = limit & ~timer->disabled_mask;
    timer->disabled = (limit & timer->disabled_mask) ? 1 : 0;

    int64_t expires = cpu_to_timer_ticks(real_limit, timer->frequency) +
                    timer->clock_offset;

    if (expires < now) {
        expires = now + 1;
    }

    TIMER_DPRINTF("%s set_limit limit=0x%016lx (%s) p=%p "
                  "called with limit=0x%016lx at 0x%016lx (delta=0x%016lx)\n",
                  timer->name, real_limit,
                  timer->disabled?"disabled":"enabled",
                  timer, limit,
                  timer_to_cpu_ticks(now - timer->clock_offset,
                                     timer->frequency),
                  timer_to_cpu_ticks(expires - now, timer->frequency));

    if (!real_limit) {
        TIMER_DPRINTF("%s set_limit limit=ZERO - not starting timer\n",
                timer->name);
        qemu_del_timer(timer->qtimer);
    } else if (timer->disabled) {
        qemu_del_timer(timer->qtimer);
    } else {
        qemu_mod_timer(timer->qtimer, expires);
    }
}

static void isa_irq_handler(void *opaque, int n, int level)
{
    static const int isa_irq_to_ivec[16] = {
        [1] = 0x29, /* keyboard */
        [4] = 0x2b, /* serial */
        [6] = 0x27, /* floppy */
        [7] = 0x22, /* parallel */
        [12] = 0x2a, /* mouse */
    };
    qemu_irq *irqs = opaque;
    int ivec;

    assert(n < 16);
    ivec = isa_irq_to_ivec[n];
    EBUS_DPRINTF("Set ISA IRQ %d level %d -> ivec 0x%x\n", n, level, ivec);
    if (ivec) {
        qemu_set_irq(irqs[ivec], level);
    }
}

/* EBUS (Eight bit bus) bridge */
static ISABus *
pci_ebus_init(PCIBus *bus, int devfn, qemu_irq *irqs)
{
    qemu_irq *isa_irq;
    PCIDevice *pci_dev;
    ISABus *isa_bus;

    pci_dev = pci_create_simple(bus, devfn, "ebus");
    isa_bus = DO_UPCAST(ISABus, qbus,
                        qdev_get_child_bus(&pci_dev->qdev, "isa.0"));
    isa_irq = qemu_allocate_irqs(isa_irq_handler, irqs, 16);
    isa_bus_irqs(isa_bus, isa_irq);
    return isa_bus;
}

static int
pci_ebus_init1(PCIDevice *pci_dev)
{
    EbusState *s = DO_UPCAST(EbusState, pci_dev, pci_dev);

    isa_bus_new(&pci_dev->qdev, pci_address_space_io(pci_dev));

    pci_dev->config[0x04] = 0x06; // command = bus master, pci mem
    pci_dev->config[0x05] = 0x00;
    pci_dev->config[0x06] = 0xa0; // status = fast back-to-back, 66MHz, no error
    pci_dev->config[0x07] = 0x03; // status = medium devsel
    pci_dev->config[0x09] = 0x00; // programming i/f
    pci_dev->config[0x0D] = 0x0a; // latency_timer

    isa_mmio_setup(&s->bar0, 0x1000000);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar0);
    isa_mmio_setup(&s->bar1, 0x800000);
    pci_register_bar(pci_dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar1);
    return 0;
}

static void ebus_class_init(ObjectClass *klass, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = pci_ebus_init1;
    k->vendor_id = PCI_VENDOR_ID_SUN;
    k->device_id = PCI_DEVICE_ID_SUN_EBUS;
    k->revision = 0x01;
    k->class_id = PCI_CLASS_BRIDGE_OTHER;
}

static const TypeInfo ebus_info = {
    .name          = "ebus",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(EbusState),
    .class_init    = ebus_class_init,
};

typedef struct PROMState {
    SysBusDevice busdev;
    MemoryRegion prom;
} PROMState;

static uint64_t translate_prom_address(void *opaque, uint64_t addr)
{
    hwaddr *base_addr = (hwaddr *)opaque;
    return addr + *base_addr - PROM_VADDR;
}

/* Boot PROM (OpenBIOS) */
static void prom_init(hwaddr addr, const char *bios_name)
{
    DeviceState *dev;
    SysBusDevice *s;
    char *filename;
    int ret;

    dev = qdev_create(NULL, "openprom");
    qdev_init_nofail(dev);
    s = sysbus_from_qdev(dev);

    sysbus_mmio_map(s, 0, addr);

    /* load boot prom */
    if (bios_name == NULL) {
        bios_name = PROM_FILENAME;
    }
    filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, bios_name);
    if (filename) {
        ret = load_elf(filename, translate_prom_address, &addr,
                       NULL, NULL, NULL, 1, ELF_MACHINE, 0);
        if (ret < 0 || ret > PROM_SIZE_MAX) {
            ret = load_image_targphys(filename, addr, PROM_SIZE_MAX);
        }
        g_free(filename);
    } else {
        ret = -1;
    }
    if (ret < 0 || ret > PROM_SIZE_MAX) {
        fprintf(stderr, "qemu: could not load prom '%s'\n", bios_name);
        exit(1);
    }
}

static int prom_init1(SysBusDevice *dev)
{
    PROMState *s = FROM_SYSBUS(PROMState, dev);

    memory_region_init_ram(&s->prom, "sun4u.prom", PROM_SIZE_MAX);
    vmstate_register_ram_global(&s->prom);
    memory_region_set_readonly(&s->prom, true);
    sysbus_init_mmio(dev, &s->prom);
    return 0;
}

static Property prom_properties[] = {
    {/* end of property list */},
};

static void prom_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);

    k->init = prom_init1;
    dc->props = prom_properties;
}

static const TypeInfo prom_info = {
    .name          = "openprom",
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(PROMState),
    .class_init    = prom_class_init,
};


typedef struct RamDevice
{
    SysBusDevice busdev;
    MemoryRegion ram;
    uint64_t size;
} RamDevice;

/* System RAM */
static int ram_init1(SysBusDevice *dev)
{
    RamDevice *d = FROM_SYSBUS(RamDevice, dev);

    memory_region_init_ram(&d->ram, "sun4u.ram", d->size);
    vmstate_register_ram_global(&d->ram);
    sysbus_init_mmio(dev, &d->ram);
    return 0;
}

static void ram_init(hwaddr addr, ram_addr_t RAM_size)
{
    DeviceState *dev;
    SysBusDevice *s;
    RamDevice *d;

    /* allocate RAM */
    dev = qdev_create(NULL, "memory");
    s = sysbus_from_qdev(dev);

    d = FROM_SYSBUS(RamDevice, s);
    d->size = RAM_size;
    qdev_init_nofail(dev);

    sysbus_mmio_map(s, 0, addr);
}

static Property ram_properties[] = {
    DEFINE_PROP_UINT64("size", RamDevice, size, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void ram_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);

    k->init = ram_init1;
    dc->props = ram_properties;
}

static const TypeInfo ram_info = {
    .name          = "memory",
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(RamDevice),
    .class_init    = ram_class_init,
};

static SPARCCPU *cpu_devinit(const char *cpu_model, const struct hwdef *hwdef)
{
    SPARCCPU *cpu;
    CPUSPARCState *env;
    ResetData *reset_info;

    uint32_t   tick_frequency = 100*1000000;
    uint32_t  stick_frequency = 100*1000000;
    uint32_t hstick_frequency = 100*1000000;

    if (cpu_model == NULL) {
        cpu_model = hwdef->default_cpu_model;
    }
    cpu = cpu_sparc_init(cpu_model);
    if (cpu == NULL) {
        fprintf(stderr, "Unable to find Sparc CPU definition\n");
        exit(1);
    }
    env = &cpu->env;

    env->tick = cpu_timer_create("tick", cpu, tick_irq,
                                  tick_frequency, TICK_NPT_MASK);

    env->stick = cpu_timer_create("stick", cpu, stick_irq,
                                   stick_frequency, TICK_INT_DIS);

    env->hstick = cpu_timer_create("hstick", cpu, hstick_irq,
                                    hstick_frequency, TICK_INT_DIS);

    reset_info = g_malloc0(sizeof(ResetData));
    reset_info->cpu = cpu;
    reset_info->prom_addr = hwdef->prom_addr;
    qemu_register_reset(main_cpu_reset, reset_info);

    return cpu;
}

static void sun4uv_init(MemoryRegion *address_space_mem,
                        ram_addr_t RAM_size,
                        const char *boot_devices,
                        const char *kernel_filename, const char *kernel_cmdline,
                        const char *initrd_filename, const char *cpu_model,
                        const struct hwdef *hwdef)
{
    SPARCCPU *cpu;
    M48t59State *nvram;
    unsigned int i;
    uint64_t initrd_addr, initrd_size, kernel_addr, kernel_size, kernel_entry;
    PCIBus *pci_bus, *pci_bus2, *pci_bus3;
    ISABus *isa_bus;
    qemu_irq *ivec_irqs, *pbm_irqs;
    DriveInfo *hd[MAX_IDE_BUS * MAX_IDE_DEVS];
    DriveInfo *fd[MAX_FD];
    void *fw_cfg;

    /* init CPUs */
    cpu = cpu_devinit(cpu_model, hwdef);

    /* set up devices */
    ram_init(0, RAM_size);

    prom_init(hwdef->prom_addr, bios_name);

    ivec_irqs = qemu_allocate_irqs(cpu_set_ivec_irq, cpu, IVEC_MAX);
    pci_bus = pci_apb_init(APB_SPECIAL_BASE, APB_MEM_BASE, ivec_irqs, &pci_bus2,
                           &pci_bus3, &pbm_irqs);
    pci_vga_init(pci_bus);

    // XXX Should be pci_bus3
    isa_bus = pci_ebus_init(pci_bus, -1, pbm_irqs);

    i = 0;
    if (hwdef->console_serial_base) {
        serial_mm_init(address_space_mem, hwdef->console_serial_base, 0,
                       NULL, 115200, serial_hds[i], DEVICE_BIG_ENDIAN);
        i++;
    }
    for(; i < MAX_SERIAL_PORTS; i++) {
        if (serial_hds[i]) {
            serial_isa_init(isa_bus, i, serial_hds[i]);
        }
    }

    for(i = 0; i < MAX_PARALLEL_PORTS; i++) {
        if (parallel_hds[i]) {
            parallel_init(isa_bus, i, parallel_hds[i]);
        }
    }

    for(i = 0; i < nb_nics; i++)
        pci_nic_init_nofail(&nd_table[i], "ne2k_pci", NULL);

    ide_drive_get(hd, MAX_IDE_BUS);

    pci_cmd646_ide_init(pci_bus, hd, 1);

    isa_create_simple(isa_bus, "i8042");
    for(i = 0; i < MAX_FD; i++) {
        fd[i] = drive_get(IF_FLOPPY, 0, i);
    }
    fdctrl_init_isa(isa_bus, fd);
    nvram = m48t59_init_isa(isa_bus, 0x0074, NVRAM_SIZE, 59);

    initrd_size = 0;
    initrd_addr = 0;
    kernel_size = sun4u_load_kernel(kernel_filename, initrd_filename,
                                    ram_size, &initrd_size, &initrd_addr,
                                    &kernel_addr, &kernel_entry);

    sun4u_NVRAM_set_params(nvram, NVRAM_SIZE, "Sun4u", RAM_size, boot_devices,
                           kernel_addr, kernel_size,
                           kernel_cmdline,
                           initrd_addr, initrd_size,
                           /* XXX: need an option to load a NVRAM image */
                           0,
                           graphic_width, graphic_height, graphic_depth,
                           (uint8_t *)&nd_table[0].macaddr);

    fw_cfg = fw_cfg_init(BIOS_CFG_IOPORT, BIOS_CFG_IOPORT + 1, 0, 0);
    fw_cfg_add_i32(fw_cfg, FW_CFG_ID, 1);
    fw_cfg_add_i64(fw_cfg, FW_CFG_RAM_SIZE, (uint64_t)ram_size);
    fw_cfg_add_i16(fw_cfg, FW_CFG_MACHINE_ID, hwdef->machine_id);
    fw_cfg_add_i64(fw_cfg, FW_CFG_KERNEL_ADDR, kernel_entry);
    fw_cfg_add_i64(fw_cfg, FW_CFG_KERNEL_SIZE, kernel_size);
    if (kernel_cmdline) {
        fw_cfg_add_i32(fw_cfg, FW_CFG_CMDLINE_SIZE,
                       strlen(kernel_cmdline) + 1);
        fw_cfg_add_bytes(fw_cfg, FW_CFG_CMDLINE_DATA,
                         (uint8_t*)strdup(kernel_cmdline),
                         strlen(kernel_cmdline) + 1);
    } else {
        fw_cfg_add_i32(fw_cfg, FW_CFG_CMDLINE_SIZE, 0);
    }
    fw_cfg_add_i64(fw_cfg, FW_CFG_INITRD_ADDR, initrd_addr);
    fw_cfg_add_i64(fw_cfg, FW_CFG_INITRD_SIZE, initrd_size);
    fw_cfg_add_i16(fw_cfg, FW_CFG_BOOT_DEVICE, boot_devices[0]);

    fw_cfg_add_i16(fw_cfg, FW_CFG_SPARC64_WIDTH, graphic_width);
    fw_cfg_add_i16(fw_cfg, FW_CFG_SPARC64_HEIGHT, graphic_height);
    fw_cfg_add_i16(fw_cfg, FW_CFG_SPARC64_DEPTH, graphic_depth);

    qemu_register_boot_set(fw_cfg_boot_set, fw_cfg);
}

enum {
    sun4u_id = 0,
    sun4v_id = 64,
    niagara_id,
};

static const struct hwdef hwdefs[] = {
    /* Sun4u generic PC-like machine */
    {
        .default_cpu_model = "TI UltraSparc IIi",
        .machine_id = sun4u_id,
        .prom_addr = 0x1fff0000000ULL,
        .console_serial_base = 0,
    },
    /* Sun4v generic PC-like machine */
    {
        .default_cpu_model = "Sun UltraSparc T1",
        .machine_id = sun4v_id,
        .prom_addr = 0x1fff0000000ULL,
        .console_serial_base = 0,
    },
    /* Sun4v generic Niagara machine */
    {
        .default_cpu_model = "Sun UltraSparc T1",
        .machine_id = niagara_id,
        .prom_addr = 0xfff0000000ULL,
        .console_serial_base = 0xfff0c2c000ULL,
    },
};

/* Sun4u hardware initialisation */
static void sun4u_init(QEMUMachineInitArgs *args)
{
    ram_addr_t RAM_size = args->ram_size;
    const char *cpu_model = args->cpu_model;
    const char *kernel_filename = args->kernel_filename;
    const char *kernel_cmdline = args->kernel_cmdline;
    const char *initrd_filename = args->initrd_filename;
    const char *boot_devices = args->boot_device;
    sun4uv_init(get_system_memory(), RAM_size, boot_devices, kernel_filename,
                kernel_cmdline, initrd_filename, cpu_model, &hwdefs[0]);
}

/* Sun4v hardware initialisation */
static void sun4v_init(QEMUMachineInitArgs *args)
{
    ram_addr_t RAM_size = args->ram_size;
    const char *cpu_model = args->cpu_model;
    const char *kernel_filename = args->kernel_filename;
    const char *kernel_cmdline = args->kernel_cmdline;
    const char *initrd_filename = args->initrd_filename;
    const char *boot_devices = args->boot_device;
    sun4uv_init(get_system_memory(), RAM_size, boot_devices, kernel_filename,
                kernel_cmdline, initrd_filename, cpu_model, &hwdefs[1]);
}

/* Niagara hardware initialisation */
static void niagara_init(QEMUMachineInitArgs *args)
{
    ram_addr_t RAM_size = args->ram_size;
    const char *cpu_model = args->cpu_model;
    const char *kernel_filename = args->kernel_filename;
    const char *kernel_cmdline = args->kernel_cmdline;
    const char *initrd_filename = args->initrd_filename;
    const char *boot_devices = args->boot_device;
    sun4uv_init(get_system_memory(), RAM_size, boot_devices, kernel_filename,
                kernel_cmdline, initrd_filename, cpu_model, &hwdefs[2]);
}

static QEMUMachine sun4u_machine = {
    .name = "sun4u",
    .desc = "Sun4u platform",
    .init = sun4u_init,
    .max_cpus = 1, // XXX for now
    .is_default = 1,
};

static QEMUMachine sun4v_machine = {
    .name = "sun4v",
    .desc = "Sun4v platform",
    .init = sun4v_init,
    .max_cpus = 1, // XXX for now
};

static QEMUMachine niagara_machine = {
    .name = "Niagara",
    .desc = "Sun4v platform, Niagara",
    .init = niagara_init,
    .max_cpus = 1, // XXX for now
};

static void sun4u_register_types(void)
{
    type_register_static(&ebus_info);
    type_register_static(&prom_info);
    type_register_static(&ram_info);
}

static void sun4u_machine_init(void)
{
    qemu_register_machine(&sun4u_machine);
    qemu_register_machine(&sun4v_machine);
    qemu_register_machine(&niagara_machine);
}

type_init(sun4u_register_types)
machine_init(sun4u_machine_init);
