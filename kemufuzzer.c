#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <zlib.h>
#include <signal.h>
#include <linux/limits.h>

#include "x86_cpustate.h"
#define  KEMUFUZZER_PRE_STATE      0
#define  KEMUFUZZER_POST_STATE     1

#define EXPECTED_MAGIC    0xEFEF
#define EXPECTED_VERSION  0x0001

typedef floatx80 CPU86_LDouble;
typedef CPU_LDoubleU CPU86_LDoubleU;

typedef struct {
  CPUArchState *env;
  int initialized;
  int signalled;
} t_kemufuzzer_state;

int snprintf(char *str, size_t size, const char *format, ...);
int rename(const char *oldpath, const char *newpath);

inline void stw_(uint8_t *, uint16_t);
inline void stl_(uint8_t *, uint32_t);
inline void stq_(uint8_t *, uint64_t);
inline uint16_t lduw_(uint8_t *);
inline uint32_t ldl_(uint8_t *);
inline uint64_t ldq_(uint8_t *);
inline CPU86_LDouble fldt_(target_ulong);

void fxsave_(CPUX86State *env, uint8_t *);
void fxrstor_(CPUX86State *env, uint8_t *);
void kemufuzzer_save(CPUX86State *env, int, unsigned int, int);
void kemufuzzer_sigusr2_handler(int);
void kemufuzzer_init(CPUArchState*);
void kemufuzzer_exception(CPUX86State *env, int, target_ulong, int);
uint64_t kemufuzzer_rdmsr(uint32_t index);
void kemufuzzer_wrmsr(CPUX86State *env, uint32_t index, uint64_t val);
void kemufuzzer_hlt(CPUX86State *env);

static t_kemufuzzer_state kemufuzzer_state = {
  .env = NULL, 
  .initialized = 0, 
  .signalled = 0
};

#define kenv (kemufuzzer_state.env)


#define get_qemu_segment(dst, src) {			\
    dst.base = src.base;				\
    dst.limit = src.limit;				\
    dst.selector = src.selector;			\
    dst.type = (src.flags >> DESC_TYPE_SHIFT) & 15;	\
    dst.present = (src.flags & DESC_P_MASK) != 0;	\
    dst.dpl = (src.flags >> DESC_DPL_SHIFT) & 3;	\
    dst.db = (src.flags >> DESC_B_SHIFT) & 1;		\
    dst.s = (src.flags & DESC_S_MASK) != 0;		\
    dst.l = (src.flags >> DESC_L_SHIFT) & 1;		\
    dst.g = (src.flags & DESC_G_MASK) != 0;		\
    dst.avl = (src.flags & DESC_AVL_MASK) != 0;		\
    dst.unusable = 0;					\
  }

#define get_qemu_table(dst, src) {		\
    dst.base = src.base;			\
    dst.limit = src.limit;			\
  }

#define set_qemu_segment(dst, src) {			\
    dst.base = src.base;				\
    dst.limit = src.limit;				\
    dst.selector = src.selector;			\
    dst.flags =						\
      (src.type << DESC_TYPE_SHIFT) |			\
      (src.s ? DESC_S_MASK : 0) |			\
      (src.dpl  << DESC_DPL_SHIFT) |			\
      (src.present ? DESC_P_MASK : 0) |			\
      (src.avl ? DESC_AVL_MASK : 0) |			\
      ((src.l != 0)    << DESC_L_SHIFT) |		\
      ((src.db != 0)   << DESC_B_SHIFT) |		\
      (src.g ? DESC_G_MASK : 0);			\
  }

#define set_qemu_table(dst, src) {		\
  dst.base = src.base;				\
  dst.limit = src.limit;			\
  }


inline void stw_(uint8_t *dst, uint16_t v) {
  memcpy((void*) dst, (void*) &v, 2); 
}

inline void stl_(uint8_t *dst, uint32_t v) { 
  memcpy((void*) dst, (void*) &v, 4); 
}

inline void stq_(uint8_t *dst, uint64_t v) { 
  memcpy((void*) dst, (void*) &v, 8); 
}

inline uint16_t lduw_(uint8_t *dst) { 
  return *(uint16_t*)dst;
}

inline uint32_t ldl_(uint8_t *dst) {
  return *(uint32_t*)dst;
}

inline uint64_t ldq_(uint8_t *dst) {
  return *(uint64_t*)dst;
}

void fxsave_(CPUX86State *env, uint8_t *ptr) {
    int fpus, fptag, i, nb_xmm_regs;
    CPU86_LDouble tmp;
    uint8_t *addr;

    fpus = (kenv->fpus & ~0x3800) | (kenv->fpstt & 0x7) << 11;
    fptag = 0;
    for(i = 0; i < 8; i++) {
        fptag |= (kenv->fptags[i] << i);
    }
    stw_(ptr, kenv->fpuc);
    stw_(ptr + 2, fpus);
    stw_(ptr + 4, fptag ^ 0xff);

    addr = ptr + 0x20;
    for(i = 0;i < 8; i++) {
        tmp = ST(i);

        /* helper_fstt(tmp, addr); */
        {
          CPU86_LDoubleU temp;
          int e;

          temp.d = tmp;
          /* mantissa */
          stq_(addr, (MANTD(temp) << 11) | (1LL << 63));
          /* exponent + sign */
          e = EXPD(temp) - EXPBIAS + 16383;
          e |= SIGND(temp) >> 16;
          stw_(addr + 8, e);
        }
        /* end of helper_fstt() */

        addr += 16;
    }

    if (kenv->cr[4] & CR4_OSFXSR_MASK) {
        /* XXX: finish it */
        stl_(ptr + 0x18, kenv->mxcsr); /* mxcsr */
        stl_(ptr + 0x1c, 0x0000ffff); /* mxcsr_mask */
        nb_xmm_regs = 8;
        addr = ptr + 0xa0;
        for(i = 0; i < nb_xmm_regs; i++) {
            stq_(addr, kenv->xmm_regs[i].ZMM_Q(0));
            stq_(addr + 8, kenv->xmm_regs[i].ZMM_Q(1));
            addr += 16;
        }
    }
}

inline CPU86_LDouble fldt_(target_ulong ptr)
{
    CPU86_LDoubleU temp;
    temp.l.lower = ldq_((uint8_t*)&ptr);
    temp.l.upper = lduw_((uint8_t*)(&ptr + 8));
    return temp.d;
}

void fxrstor_(CPUX86State *env, uint8_t *ptr)
{
  int i, fpus, fptag, nb_xmm_regs;
  CPU86_LDouble tmp;
  target_ulong addr;

  kenv->fpuc = lduw_(ptr);
  fpus = lduw_(ptr + 2);
  fptag = lduw_(ptr + 4);
  kenv->fpstt = (fpus >> 11) & 7;
  kenv->fpus = fpus & ~0x3800;
  fptag ^= 0xff;
  for(i = 0;i < 8; i++) {
    kenv->fptags[i] = ((fptag >> i) & 1);
  }

  addr = ((target_ulong)*ptr) + 0x20;
  for(i = 0;i < 8; i++) {
    tmp = fldt_(addr);
    ST(i) = tmp;
    addr += 16;
  }

  if (kenv->cr[4] & CR4_OSFXSR_MASK) {
    /* XXX: finish it */
    kenv->mxcsr = ldl_(ptr + 0x18);
    //ldl(ptr + 0x1c);
    if (kenv->hflags & HF_CS64_MASK)
      nb_xmm_regs = 16;
    else
      nb_xmm_regs = 8;
    addr = ((target_ulong)*ptr) + 0xa0;
    /* Fast FXRESTORE leaves out the XMM registers */
    if (!(kenv->efer & MSR_EFER_FFXSR)
	|| (kenv->hflags & HF_CPL_MASK)
	|| !(kenv->hflags & HF_LMA_MASK)) {
      for(i = 0; i < nb_xmm_regs; i++) {
	kenv->xmm_regs[i].ZMM_Q(0) = ldq_((uint8_t*)&addr);
	kenv->xmm_regs[i].ZMM_Q(1) = ldq_((uint8_t*)(&addr + 8));
	addr += 16;
      }
    }
  }
}


void kemufuzzer_save(CPUX86State *env, int t, unsigned int eip, int e) {
  header_t h;
  cpu_state_t s;
  char outfile[PATH_MAX], tempfile[PATH_MAX];
  file f;
  int r, i;
  unsigned char tmp[1024];
  CPUX86State *original_env;

  /* We have to backup the original 'env' global and replace it with
     kemufuzzer's environment. Otherwise, helper_cc_compute_all() and other
     functions that use 'env' will fail. */
  original_env = env;
  env = kenv;

  // Initialization
  memset(&s, 0, sizeof(s));

  // Get output file name
  assert(getenv("KEMUFUZZER_PRE_STATE"));
  assert(getenv("KEMUFUZZER_POST_STATE"));
  assert(getenv("KEMUFUZZER_KERNEL_VERSION"));
  assert(getenv("KEMUFUZZER_KERNEL_CHECKSUM"));
  assert(getenv("KEMUFUZZER_TESTCASE_CHECKSUM"));

  strncpy(tempfile, "/tmp/kemufuzzer-XXXXXX", PATH_MAX - 1);
  strncpy(outfile, !t ?
	  getenv("KEMUFUZZER_PRE_STATE") : getenv("KEMUFUZZER_POST_STATE"), 
	  PATH_MAX - 1);

  mkstemp(tempfile);
  f = fopen(tempfile, "w");
  assert(f);

  // Fill header
  h.magic    = 0xefef;
  h.version  = 0x0001;
  h.emulator = EMULATOR_QEMU;
  strncpy(h.kernel_version, getenv("KEMUFUZZER_KERNEL_VERSION"), sizeof(h.kernel_version));
  strncpy(h.kernel_checksum, getenv("KEMUFUZZER_KERNEL_CHECKSUM"), sizeof(h.kernel_checksum));
  strncpy(h.testcase_checksum, getenv("KEMUFUZZER_TESTCASE_CHECKSUM"), sizeof(h.testcase_checksum));
  h.type     = !t ? PRE_TESTCASE : POST_TESTCASE;
  h.mem_size = ram_size;
  h.cpusno   = 1;
  h.ioports[0] = KEMUFUZZER_HYPERCALL_START_TESTCASE; h.ioports[1] = KEMUFUZZER_HYPERCALL_STOP_TESTCASE;

  // Dump header to disk
  r = fwrite(f, &h, sizeof(h));
  assert(r == sizeof(h));

  // General purpose registers
  s.regs_state.rax = kenv->regs[R_EAX];
  s.regs_state.rbx = kenv->regs[R_EBX];
  s.regs_state.rcx = kenv->regs[R_ECX];
  s.regs_state.rdx = kenv->regs[R_EDX];
  s.regs_state.rsi = kenv->regs[R_ESI];
  s.regs_state.rdi = kenv->regs[R_EDI];
  s.regs_state.rsp = kenv->regs[R_ESP];
  s.regs_state.rbp = kenv->regs[R_EBP];

  s.regs_state.rflags = cpu_cc_compute_all(env, CC_OP) |	\
    (kenv->df & DF_MASK) |					\
    kenv->eflags;

  s.regs_state.rip = eip;

  printf("RIP: %.16lx\n", PAD64(eip));
#if 0
  r = cpu_memory_rw_debug(kenv, eip, tmp, 8, 0);
  assert(r == 0);
  for (r = 0; r < 8; r++) {
    printf("\\x%.2x", tmp[r]);
  }
  printf("\n");
#endif
  printf("RSP: %.16lx\n", PAD64(kenv->regs[R_ESP]));
  printf("RSI: %.16lx\n", PAD64(kenv->regs[R_ESI]));

  // System registers
  s.sregs_state.cr0 = kenv->cr[0];
  s.sregs_state.cr2 = kenv->cr[2];
  s.sregs_state.cr3 = kenv->cr[3];
  s.sregs_state.cr4 = kenv->cr[4];
  s.sregs_state.dr0 = kenv->dr[0];
  s.sregs_state.dr1 = kenv->dr[1];
  s.sregs_state.dr2 = kenv->dr[2];
  s.sregs_state.dr3 = kenv->dr[3];
  s.sregs_state.dr6 = kenv->dr[6];
  s.sregs_state.dr7 = kenv->dr[7];

  get_qemu_segment(s.sregs_state.cs, kenv->segs[R_CS]);
  get_qemu_segment(s.sregs_state.ds, kenv->segs[R_DS]);
  get_qemu_segment(s.sregs_state.es, kenv->segs[R_ES]);
  get_qemu_segment(s.sregs_state.fs, kenv->segs[R_FS]);
  get_qemu_segment(s.sregs_state.gs, kenv->segs[R_GS]);
  get_qemu_segment(s.sregs_state.ss, kenv->segs[R_SS]);
  get_qemu_segment(s.sregs_state.tr, kenv->tr);
  // Bug in QEMU?
  s.sregs_state.tr.type = 11;
  get_qemu_segment(s.sregs_state.ldt, kenv->ldt);
  get_qemu_table(s.sregs_state.idtr, kenv->idt);
  get_qemu_table(s.sregs_state.gdtr, kenv->gdt);
  s.sregs_state.efer = kenv->efer;

  s.exception_state.vector = e;
  s.exception_state.error_code = 0;

  // Fpu
  fxsave_(env, (uint8_t *) &s.fpu_state);

  // Dump MSR registers
  s.msrs_state.n = sizeof(MSRs_to_save)/sizeof(int);
  assert(s.msrs_state.n < MAX_MSRS);

  // These are modified by helper_rdmsr()
  for (i = 0; i < s.msrs_state.n; i++) {
    s.msrs_state.msr_regs[i].idx = MSRs_to_save[i];
    s.msrs_state.msr_regs[i].val = kemufuzzer_rdmsr(MSRs_to_save[i]);
  }

  // Dump cpu state
  r = fwrite(f, &s, sizeof(s));
  assert(r == sizeof(s));

  // Dump mem state
  for (i = 0; i < ram_size; i += sizeof(tmp)) {
    memset(tmp, 0, sizeof(tmp));
    cpu_physical_memory_rw(i, tmp, sizeof(tmp), 0);
    r = fwrite(f, &tmp, sizeof(tmp));
    assert(r == sizeof(tmp));
  }

  fclose(f);

  rename(tempfile, outfile);
  printf("Dumped CPU & MEM state to (%s -> %s)\n", tempfile, outfile);

  /* Restore original CPU environment */
  env = original_env;
}

uint64_t kemufuzzer_rdmsr(uint32_t index)
{
  uint64_t val;
  switch(index) {
  case MSR_IA32_SYSENTER_CS:
    val = kenv->sysenter_cs;
    break;
  case MSR_IA32_SYSENTER_ESP:
    val = kenv->sysenter_esp;
    break;
  case MSR_IA32_SYSENTER_EIP:
    val = kenv->sysenter_eip;
    break;
  case MSR_IA32_APICBASE:
    val = cpu_get_apic_base(x86_env_get_cpu(kenv)->apic_state);
    break;
  case MSR_EFER:
    val = kenv->efer;
    break;
  case MSR_STAR:
    val = kenv->star;
    break;
  case MSR_PAT:
    val = kenv->pat;
    break;
  case MSR_VM_HSAVE_PA:
    val = kenv->vm_hsave;
    break;
  case MSR_IA32_PERF_STATUS:
    /* tsc_increment_by_tick */
    val = 1000ULL;
    /* CPU multiplier */
    val |= (((uint64_t)4ULL) << 40);
    break;
  default:
    printf("[!] unknown MSR #%.8x\n", index);
    assert(0);
  }

  return val;
}

void kemufuzzer_wrmsr(CPUX86State *env, uint32_t index, uint64_t val)
{
  switch(index) {
  case MSR_IA32_SYSENTER_CS:
    kenv->sysenter_cs = val & 0xffff;
    break;
  case MSR_IA32_SYSENTER_ESP:
    kenv->sysenter_esp = val;
    break;
  case MSR_IA32_SYSENTER_EIP:
    kenv->sysenter_eip = val;
    break;
  case MSR_IA32_APICBASE:
    cpu_set_apic_base(kenv, val);
    break;
  case MSR_EFER:
    {
      uint64_t update_mask;
      update_mask = 0;
      if (kenv->features[FEAT_8000_0001_EDX] & CPUID_EXT2_SYSCALL)
	update_mask |= MSR_EFER_SCE;
      if (kenv->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM)
	update_mask |= MSR_EFER_LME;
      if (kenv->features[FEAT_8000_0001_EDX] & CPUID_EXT2_FFXSR)
	update_mask |= MSR_EFER_FFXSR;
      if (kenv->features[FEAT_8000_0001_EDX] & CPUID_EXT2_NX)
	update_mask |= MSR_EFER_NXE;
      if (kenv->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM)
	update_mask |= MSR_EFER_SVME;
      if (kenv->features[FEAT_8000_0001_EDX] & CPUID_EXT2_FFXSR)
	update_mask |= MSR_EFER_FFXSR;
      cpu_load_efer(kenv, (kenv->efer & ~update_mask) |
		    (val & update_mask));
    }
    break;
  case MSR_STAR:
    kenv->star = val;
    break;
  case MSR_PAT:
    kenv->pat = val;
    break;
  case MSR_VM_HSAVE_PA:
    kenv->vm_hsave = val;
    break;
#ifdef TARGET_X86_64
  case MSR_LSTAR:
    kenv->lstar = val;
    break;
  case MSR_CSTAR:
    kenv->cstar = val;
    break;
  case MSR_FMASK:
    kenv->fmask = val;
    break;
  case MSR_FSBASE:
    kenv->segs[R_FS].base = val;
    break;
  case MSR_GSBASE:
    kenv->segs[R_GS].base = val;
    break;
  case MSR_KERNELGSBASE:
    kenv->kernelgsbase = val;
    break;
#endif
  case MSR_MTRRphysBase(0):
  case MSR_MTRRphysBase(1):
  case MSR_MTRRphysBase(2):
  case MSR_MTRRphysBase(3):
  case MSR_MTRRphysBase(4):
  case MSR_MTRRphysBase(5):
  case MSR_MTRRphysBase(6):
  case MSR_MTRRphysBase(7):
    kenv->mtrr_var[((uint32_t)kenv->regs[R_ECX] - MSR_MTRRphysBase(0)) / 2].base = val;
    break;
  case MSR_MTRRphysMask(0):
  case MSR_MTRRphysMask(1):
  case MSR_MTRRphysMask(2):
  case MSR_MTRRphysMask(3):
  case MSR_MTRRphysMask(4):
  case MSR_MTRRphysMask(5):
  case MSR_MTRRphysMask(6):
  case MSR_MTRRphysMask(7):
    kenv->mtrr_var[((uint32_t)kenv->regs[R_ECX] - MSR_MTRRphysMask(0)) / 2].mask = val;
    break;
  case MSR_MTRRfix64K_00000:
    kenv->mtrr_fixed[(uint32_t)kenv->regs[R_ECX] - MSR_MTRRfix64K_00000] = val;
    break;
  case MSR_MTRRfix16K_80000:
  case MSR_MTRRfix16K_A0000:
    kenv->mtrr_fixed[(uint32_t)kenv->regs[R_ECX] - MSR_MTRRfix16K_80000 + 1] = val;
    break;
  case MSR_MTRRfix4K_C0000:
  case MSR_MTRRfix4K_C8000:
  case MSR_MTRRfix4K_D0000:
  case MSR_MTRRfix4K_D8000:
  case MSR_MTRRfix4K_E0000:
  case MSR_MTRRfix4K_E8000:
  case MSR_MTRRfix4K_F0000:
  case MSR_MTRRfix4K_F8000:
    kenv->mtrr_fixed[(uint32_t)kenv->regs[R_ECX] - MSR_MTRRfix4K_C0000 + 3] = val;
    break;
  case MSR_MTRRdefType:
    kenv->mtrr_deftype = val;
    break;
  case MSR_MCG_STATUS:
    kenv->mcg_status = val;
    break;
  case MSR_MCG_CTL:
    if ((kenv->mcg_cap & MCG_CTL_P)
	&& (val == 0 || val == ~(uint64_t)0))
      kenv->mcg_ctl = val;
    break;
  default:
    if ((uint32_t)kenv->regs[R_ECX] >= MSR_MC0_CTL
	&& (uint32_t)kenv->regs[R_ECX] < MSR_MC0_CTL + (4 * kenv->mcg_cap & 0xff)) {
      uint32_t offset = (uint32_t)kenv->regs[R_ECX] - MSR_MC0_CTL;
      if ((offset & 0x3) != 0
	  || (val == 0 || val == ~(uint64_t)0))
	kenv->mce_banks[offset] = val;
      break;
    }
    /* XXX: exception ? */
    break;
  }
}


void kemufuzzer_exception(CPUX86State *env, int e, target_ulong nexteip, int isint) {
  if (e == KEMUFUZZER_HYPERCALL_START_TESTCASE || kemufuzzer_state.signalled)
    printf("Exception %x @ %.8x\n", e, nexteip);

  if (kemufuzzer_state.signalled == 0 && 
      e == KEMUFUZZER_HYPERCALL_START_TESTCASE) {
    // Dump the state
    kemufuzzer_save(env, KEMUFUZZER_PRE_STATE, nexteip, EXCEPTION_NONE);
    kemufuzzer_state.signalled = 1;
    // Force QEMU to ignore the interrupt
    kenv->eip = nexteip;
    kenv->old_exception = -1;
    ENV_GET_CPU(kenv)->exception_index = -1;
    siglongjmp(ENV_GET_CPU(kenv)->jmp_env, 1);
  } else if (!isint && kemufuzzer_state.signalled >= 1) {
//    kemufuzzer_save(env, KEMUFUZZER_POST_STATE, kenv->eip, e);
//    exit(0);
  }
}


void kemufuzzer_hlt(CPUX86State *env) {
  if (kemufuzzer_state.signalled >= 1) {
	  printf("CPU HALTED\n");
	  kemufuzzer_save(env, KEMUFUZZER_POST_STATE, kenv->eip - 1, EXCEPTION_NONE);
	  exit(0);
}
}

void kemufuzzer_init(CPUArchState *e) {
  if (kemufuzzer_state.initialized) {
    /* Already initialized */
    return;
  }

  kenv = e;
  kemufuzzer_state.initialized = 1;
}

#undef kenv
