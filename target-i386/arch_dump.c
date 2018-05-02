/*
 * i386 memory mapping
 *
 * Copyright Fujitsu, Corp. 2011, 2012
 *
 * Authors:
 *     Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "cpu.h"
#include "cpu-all.h"
#include "elf.h"

#ifdef TARGET_X86_64
typedef struct {
    target_ulong r15, r14, r13, r12, rbp, rbx, r11, r10;
    target_ulong r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax;
    target_ulong rip, cs, eflags;
    target_ulong rsp, ss;
    target_ulong fs_base, gs_base;
    target_ulong ds, es, fs, gs;
} x86_64_user_regs_struct;

typedef struct {
    char pad1[32];
    uint32_t pid;
    char pad2[76];
    x86_64_user_regs_struct regs;
    char pad3[8];
} x86_64_elf_prstatus;

static int x86_64_write_elf64_note(write_core_dump_function f,
                                   CPUArchState *env, int id,
                                   void *opaque)
{
    x86_64_user_regs_struct regs;
    Elf64_Nhdr *note;
    char *buf;
    int descsz, note_size, name_size = 5;
    const char *name = "CORE";
    int ret;

    regs.r15 = env->regs[15];
    regs.r14 = env->regs[14];
    regs.r13 = env->regs[13];
    regs.r12 = env->regs[12];
    regs.r11 = env->regs[11];
    regs.r10 = env->regs[10];
    regs.r9  = env->regs[9];
    regs.r8  = env->regs[8];
    regs.rbp = env->regs[R_EBP];
    regs.rsp = env->regs[R_ESP];
    regs.rdi = env->regs[R_EDI];
    regs.rsi = env->regs[R_ESI];
    regs.rdx = env->regs[R_EDX];
    regs.rcx = env->regs[R_ECX];
    regs.rbx = env->regs[R_EBX];
    regs.rax = env->regs[R_EAX];
    regs.rip = env->eip;
    regs.eflags = env->eflags;

    regs.orig_rax = 0; /* FIXME */
    regs.cs = env->segs[R_CS].selector;
    regs.ss = env->segs[R_SS].selector;
    regs.fs_base = env->segs[R_FS].base;
    regs.gs_base = env->segs[R_GS].base;
    regs.ds = env->segs[R_DS].selector;
    regs.es = env->segs[R_ES].selector;
    regs.fs = env->segs[R_FS].selector;
    regs.gs = env->segs[R_GS].selector;

    descsz = sizeof(x86_64_elf_prstatus);
    note_size = ((sizeof(Elf64_Nhdr) + 3) / 4 + (name_size + 3) / 4 +
                (descsz + 3) / 4) * 4;
    note = g_malloc(note_size);

    memset(note, 0, note_size);
    note->n_namesz = cpu_to_le32(name_size);
    note->n_descsz = cpu_to_le32(descsz);
    note->n_type = cpu_to_le32(NT_PRSTATUS);
    buf = (char *)note;
    buf += ((sizeof(Elf64_Nhdr) + 3) / 4) * 4;
    memcpy(buf, name, name_size);
    buf += ((name_size + 3) / 4) * 4;
    memcpy(buf + 32, &id, 4); /* pr_pid */
    buf += descsz - sizeof(x86_64_user_regs_struct)-sizeof(target_ulong);
    memcpy(buf, &regs, sizeof(x86_64_user_regs_struct));

    ret = f(note, note_size, opaque);
    g_free(note);
    if (ret < 0) {
        return -1;
    }

    return 0;
}
#endif

typedef struct {
    uint32_t ebx, ecx, edx, esi, edi, ebp, eax;
    unsigned short ds, __ds, es, __es;
    unsigned short fs, __fs, gs, __gs;
    uint32_t orig_eax, eip;
    unsigned short cs, __cs;
    uint32_t eflags, esp;
    unsigned short ss, __ss;
} x86_user_regs_struct;

typedef struct {
    char pad1[24];
    uint32_t pid;
    char pad2[44];
    x86_user_regs_struct regs;
    char pad3[4];
} x86_elf_prstatus;

static void x86_fill_elf_prstatus(x86_elf_prstatus *prstatus, CPUArchState *env,
                                  int id)
{
    memset(prstatus, 0, sizeof(x86_elf_prstatus));
    prstatus->regs.ebp = env->regs[R_EBP] & 0xffffffff;
    prstatus->regs.esp = env->regs[R_ESP] & 0xffffffff;
    prstatus->regs.edi = env->regs[R_EDI] & 0xffffffff;
    prstatus->regs.esi = env->regs[R_ESI] & 0xffffffff;
    prstatus->regs.edx = env->regs[R_EDX] & 0xffffffff;
    prstatus->regs.ecx = env->regs[R_ECX] & 0xffffffff;
    prstatus->regs.ebx = env->regs[R_EBX] & 0xffffffff;
    prstatus->regs.eax = env->regs[R_EAX] & 0xffffffff;
    prstatus->regs.eip = env->eip & 0xffffffff;
    prstatus->regs.eflags = env->eflags & 0xffffffff;

    prstatus->regs.cs = env->segs[R_CS].selector;
    prstatus->regs.ss = env->segs[R_SS].selector;
    prstatus->regs.ds = env->segs[R_DS].selector;
    prstatus->regs.es = env->segs[R_ES].selector;
    prstatus->regs.fs = env->segs[R_FS].selector;
    prstatus->regs.gs = env->segs[R_GS].selector;

    prstatus->pid = id;
}

static int x86_write_elf64_note(write_core_dump_function f, CPUArchState *env,
                                int id, void *opaque)
{
    x86_elf_prstatus prstatus;
    Elf64_Nhdr *note;
    char *buf;
    int descsz, note_size, name_size = 5;
    const char *name = "CORE";
    int ret;

    x86_fill_elf_prstatus(&prstatus, env, id);
    descsz = sizeof(x86_elf_prstatus);
    note_size = ((sizeof(Elf64_Nhdr) + 3) / 4 + (name_size + 3) / 4 +
                (descsz + 3) / 4) * 4;
    note = g_malloc(note_size);

    memset(note, 0, note_size);
    note->n_namesz = cpu_to_le32(name_size);
    note->n_descsz = cpu_to_le32(descsz);
    note->n_type = cpu_to_le32(NT_PRSTATUS);
    buf = (char *)note;
    buf += ((sizeof(Elf64_Nhdr) + 3) / 4) * 4;
    memcpy(buf, name, name_size);
    buf += ((name_size + 3) / 4) * 4;
    memcpy(buf, &prstatus, sizeof(prstatus));

    ret = f(note, note_size, opaque);
    g_free(note);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int cpu_write_elf64_note(write_core_dump_function f, CPUArchState *env,
                         int cpuid, void *opaque)
{
    int ret;
#ifdef TARGET_X86_64
    bool lma = !!(first_cpu->hflags & HF_LMA_MASK);

    if (lma) {
        ret = x86_64_write_elf64_note(f, env, cpuid, opaque);
    } else {
#endif
        ret = x86_write_elf64_note(f, env, cpuid, opaque);
#ifdef TARGET_X86_64
    }
#endif

    return ret;
}

int cpu_write_elf32_note(write_core_dump_function f, CPUArchState *env,
                         int cpuid, void *opaque)
{
    x86_elf_prstatus prstatus;
    Elf32_Nhdr *note;
    char *buf;
    int descsz, note_size, name_size = 5;
    const char *name = "CORE";
    int ret;

    x86_fill_elf_prstatus(&prstatus, env, cpuid);
    descsz = sizeof(x86_elf_prstatus);
    note_size = ((sizeof(Elf32_Nhdr) + 3) / 4 + (name_size + 3) / 4 +
                (descsz + 3) / 4) * 4;
    note = g_malloc(note_size);

    memset(note, 0, note_size);
    note->n_namesz = cpu_to_le32(name_size);
    note->n_descsz = cpu_to_le32(descsz);
    note->n_type = cpu_to_le32(NT_PRSTATUS);
    buf = (char *)note;
    buf += ((sizeof(Elf32_Nhdr) + 3) / 4) * 4;
    memcpy(buf, name, name_size);
    buf += ((name_size + 3) / 4) * 4;
    memcpy(buf, &prstatus, sizeof(prstatus));

    ret = f(note, note_size, opaque);
    g_free(note);
    if (ret < 0) {
        return -1;
    }

    return 0;
}
