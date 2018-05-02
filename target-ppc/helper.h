#include "def-helper.h"

DEF_HELPER_3(raise_exception_err, void, env, i32, i32)
DEF_HELPER_2(raise_exception, void, env, i32)
DEF_HELPER_4(tw, void, env, tl, tl, i32)
#if defined(TARGET_PPC64)
DEF_HELPER_4(td, void, env, tl, tl, i32)
#endif
#if !defined(CONFIG_USER_ONLY)
DEF_HELPER_2(store_msr, void, env, tl)
DEF_HELPER_1(rfi, void, env)
DEF_HELPER_1(rfsvc, void, env)
DEF_HELPER_1(40x_rfci, void, env)
DEF_HELPER_1(rfci, void, env)
DEF_HELPER_1(rfdi, void, env)
DEF_HELPER_1(rfmci, void, env)
#if defined(TARGET_PPC64)
DEF_HELPER_1(rfid, void, env)
DEF_HELPER_1(hrfid, void, env)
#endif
#endif

DEF_HELPER_2(lmw, void, tl, i32)
DEF_HELPER_2(stmw, void, tl, i32)
DEF_HELPER_3(lsw, void, tl, i32, i32)
DEF_HELPER_4(lswx, void, tl, i32, i32, i32)
DEF_HELPER_3(stsw, void, tl, i32, i32)
DEF_HELPER_1(dcbz, void, tl)
DEF_HELPER_1(dcbz_970, void, tl)
DEF_HELPER_1(icbi, void, tl)
DEF_HELPER_4(lscbx, tl, tl, i32, i32, i32)

#if defined(TARGET_PPC64)
DEF_HELPER_FLAGS_2(mulhd, TCG_CALL_CONST | TCG_CALL_PURE, i64, i64, i64)
DEF_HELPER_FLAGS_2(mulhdu, TCG_CALL_CONST | TCG_CALL_PURE, i64, i64, i64)
DEF_HELPER_2(mulldo, i64, i64, i64)
#endif

DEF_HELPER_FLAGS_1(cntlzw, TCG_CALL_CONST | TCG_CALL_PURE, tl, tl)
DEF_HELPER_FLAGS_1(popcntb, TCG_CALL_CONST | TCG_CALL_PURE, tl, tl)
DEF_HELPER_FLAGS_1(popcntw, TCG_CALL_CONST | TCG_CALL_PURE, tl, tl)
DEF_HELPER_2(sraw, tl, tl, tl)
#if defined(TARGET_PPC64)
DEF_HELPER_FLAGS_1(cntlzd, TCG_CALL_CONST | TCG_CALL_PURE, tl, tl)
DEF_HELPER_FLAGS_1(popcntd, TCG_CALL_CONST | TCG_CALL_PURE, tl, tl)
DEF_HELPER_2(srad, tl, tl, tl)
#endif

DEF_HELPER_FLAGS_1(cntlsw32, TCG_CALL_CONST | TCG_CALL_PURE, i32, i32)
DEF_HELPER_FLAGS_1(cntlzw32, TCG_CALL_CONST | TCG_CALL_PURE, i32, i32)
DEF_HELPER_FLAGS_2(brinc, TCG_CALL_CONST | TCG_CALL_PURE, tl, tl, tl)

DEF_HELPER_0(float_check_status, void)
DEF_HELPER_0(reset_fpstatus, void)
DEF_HELPER_2(compute_fprf, i32, i64, i32)
DEF_HELPER_2(store_fpscr, void, i64, i32)
DEF_HELPER_1(fpscr_clrbit, void, i32)
DEF_HELPER_1(fpscr_setbit, void, i32)
DEF_HELPER_1(float64_to_float32, i32, i64)
DEF_HELPER_1(float32_to_float64, i64, i32)

DEF_HELPER_3(fcmpo, void, i64, i64, i32)
DEF_HELPER_3(fcmpu, void, i64, i64, i32)

DEF_HELPER_1(fctiw, i64, i64)
DEF_HELPER_1(fctiwz, i64, i64)
#if defined(TARGET_PPC64)
DEF_HELPER_1(fcfid, i64, i64)
DEF_HELPER_1(fctid, i64, i64)
DEF_HELPER_1(fctidz, i64, i64)
#endif
DEF_HELPER_1(frsp, i64, i64)
DEF_HELPER_1(frin, i64, i64)
DEF_HELPER_1(friz, i64, i64)
DEF_HELPER_1(frip, i64, i64)
DEF_HELPER_1(frim, i64, i64)

DEF_HELPER_2(fadd, i64, i64, i64)
DEF_HELPER_2(fsub, i64, i64, i64)
DEF_HELPER_2(fmul, i64, i64, i64)
DEF_HELPER_2(fdiv, i64, i64, i64)
DEF_HELPER_3(fmadd, i64, i64, i64, i64)
DEF_HELPER_3(fmsub, i64, i64, i64, i64)
DEF_HELPER_3(fnmadd, i64, i64, i64, i64)
DEF_HELPER_3(fnmsub, i64, i64, i64, i64)
DEF_HELPER_1(fabs, i64, i64)
DEF_HELPER_1(fnabs, i64, i64)
DEF_HELPER_1(fneg, i64, i64)
DEF_HELPER_1(fsqrt, i64, i64)
DEF_HELPER_1(fre, i64, i64)
DEF_HELPER_1(fres, i64, i64)
DEF_HELPER_1(frsqrte, i64, i64)
DEF_HELPER_3(fsel, i64, i64, i64, i64)

#define dh_alias_avr ptr
#define dh_ctype_avr ppc_avr_t *
#define dh_is_signed_avr dh_is_signed_ptr

DEF_HELPER_3(vaddubm, void, avr, avr, avr)
DEF_HELPER_3(vadduhm, void, avr, avr, avr)
DEF_HELPER_3(vadduwm, void, avr, avr, avr)
DEF_HELPER_3(vsububm, void, avr, avr, avr)
DEF_HELPER_3(vsubuhm, void, avr, avr, avr)
DEF_HELPER_3(vsubuwm, void, avr, avr, avr)
DEF_HELPER_3(vavgub, void, avr, avr, avr)
DEF_HELPER_3(vavguh, void, avr, avr, avr)
DEF_HELPER_3(vavguw, void, avr, avr, avr)
DEF_HELPER_3(vavgsb, void, avr, avr, avr)
DEF_HELPER_3(vavgsh, void, avr, avr, avr)
DEF_HELPER_3(vavgsw, void, avr, avr, avr)
DEF_HELPER_3(vminsb, void, avr, avr, avr)
DEF_HELPER_3(vminsh, void, avr, avr, avr)
DEF_HELPER_3(vminsw, void, avr, avr, avr)
DEF_HELPER_3(vmaxsb, void, avr, avr, avr)
DEF_HELPER_3(vmaxsh, void, avr, avr, avr)
DEF_HELPER_3(vmaxsw, void, avr, avr, avr)
DEF_HELPER_3(vminub, void, avr, avr, avr)
DEF_HELPER_3(vminuh, void, avr, avr, avr)
DEF_HELPER_3(vminuw, void, avr, avr, avr)
DEF_HELPER_3(vmaxub, void, avr, avr, avr)
DEF_HELPER_3(vmaxuh, void, avr, avr, avr)
DEF_HELPER_3(vmaxuw, void, avr, avr, avr)
DEF_HELPER_3(vcmpequb, void, avr, avr, avr)
DEF_HELPER_3(vcmpequh, void, avr, avr, avr)
DEF_HELPER_3(vcmpequw, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtub, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtuh, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtuw, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtsb, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtsh, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtsw, void, avr, avr, avr)
DEF_HELPER_3(vcmpeqfp, void, avr, avr, avr)
DEF_HELPER_3(vcmpgefp, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtfp, void, avr, avr, avr)
DEF_HELPER_3(vcmpbfp, void, avr, avr, avr)
DEF_HELPER_3(vcmpequb_dot, void, avr, avr, avr)
DEF_HELPER_3(vcmpequh_dot, void, avr, avr, avr)
DEF_HELPER_3(vcmpequw_dot, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtub_dot, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtuh_dot, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtuw_dot, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtsb_dot, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtsh_dot, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtsw_dot, void, avr, avr, avr)
DEF_HELPER_3(vcmpeqfp_dot, void, avr, avr, avr)
DEF_HELPER_3(vcmpgefp_dot, void, avr, avr, avr)
DEF_HELPER_3(vcmpgtfp_dot, void, avr, avr, avr)
DEF_HELPER_3(vcmpbfp_dot, void, avr, avr, avr)
DEF_HELPER_3(vmrglb, void, avr, avr, avr)
DEF_HELPER_3(vmrglh, void, avr, avr, avr)
DEF_HELPER_3(vmrglw, void, avr, avr, avr)
DEF_HELPER_3(vmrghb, void, avr, avr, avr)
DEF_HELPER_3(vmrghh, void, avr, avr, avr)
DEF_HELPER_3(vmrghw, void, avr, avr, avr)
DEF_HELPER_3(vmulesb, void, avr, avr, avr)
DEF_HELPER_3(vmulesh, void, avr, avr, avr)
DEF_HELPER_3(vmuleub, void, avr, avr, avr)
DEF_HELPER_3(vmuleuh, void, avr, avr, avr)
DEF_HELPER_3(vmulosb, void, avr, avr, avr)
DEF_HELPER_3(vmulosh, void, avr, avr, avr)
DEF_HELPER_3(vmuloub, void, avr, avr, avr)
DEF_HELPER_3(vmulouh, void, avr, avr, avr)
DEF_HELPER_3(vsrab, void, avr, avr, avr)
DEF_HELPER_3(vsrah, void, avr, avr, avr)
DEF_HELPER_3(vsraw, void, avr, avr, avr)
DEF_HELPER_3(vsrb, void, avr, avr, avr)
DEF_HELPER_3(vsrh, void, avr, avr, avr)
DEF_HELPER_3(vsrw, void, avr, avr, avr)
DEF_HELPER_3(vslb, void, avr, avr, avr)
DEF_HELPER_3(vslh, void, avr, avr, avr)
DEF_HELPER_3(vslw, void, avr, avr, avr)
DEF_HELPER_3(vslo, void, avr, avr, avr)
DEF_HELPER_3(vsro, void, avr, avr, avr)
DEF_HELPER_3(vaddcuw, void, avr, avr, avr)
DEF_HELPER_3(vsubcuw, void, avr, avr, avr)
DEF_HELPER_2(lvsl, void, avr, tl);
DEF_HELPER_2(lvsr, void, avr, tl);
DEF_HELPER_3(vaddsbs, void, avr, avr, avr)
DEF_HELPER_3(vaddshs, void, avr, avr, avr)
DEF_HELPER_3(vaddsws, void, avr, avr, avr)
DEF_HELPER_3(vsubsbs, void, avr, avr, avr)
DEF_HELPER_3(vsubshs, void, avr, avr, avr)
DEF_HELPER_3(vsubsws, void, avr, avr, avr)
DEF_HELPER_3(vaddubs, void, avr, avr, avr)
DEF_HELPER_3(vadduhs, void, avr, avr, avr)
DEF_HELPER_3(vadduws, void, avr, avr, avr)
DEF_HELPER_3(vsububs, void, avr, avr, avr)
DEF_HELPER_3(vsubuhs, void, avr, avr, avr)
DEF_HELPER_3(vsubuws, void, avr, avr, avr)
DEF_HELPER_3(vrlb, void, avr, avr, avr)
DEF_HELPER_3(vrlh, void, avr, avr, avr)
DEF_HELPER_3(vrlw, void, avr, avr, avr)
DEF_HELPER_3(vsl, void, avr, avr, avr)
DEF_HELPER_3(vsr, void, avr, avr, avr)
DEF_HELPER_4(vsldoi, void, avr, avr, avr, i32)
DEF_HELPER_2(vspltisb, void, avr, i32)
DEF_HELPER_2(vspltish, void, avr, i32)
DEF_HELPER_2(vspltisw, void, avr, i32)
DEF_HELPER_3(vspltb, void, avr, avr, i32)
DEF_HELPER_3(vsplth, void, avr, avr, i32)
DEF_HELPER_3(vspltw, void, avr, avr, i32)
DEF_HELPER_2(vupkhpx, void, avr, avr)
DEF_HELPER_2(vupklpx, void, avr, avr)
DEF_HELPER_2(vupkhsb, void, avr, avr)
DEF_HELPER_2(vupkhsh, void, avr, avr)
DEF_HELPER_2(vupklsb, void, avr, avr)
DEF_HELPER_2(vupklsh, void, avr, avr)
DEF_HELPER_4(vmsumubm, void, avr, avr, avr, avr)
DEF_HELPER_4(vmsummbm, void, avr, avr, avr, avr)
DEF_HELPER_4(vsel, void, avr, avr, avr, avr)
DEF_HELPER_4(vperm, void, avr, avr, avr, avr)
DEF_HELPER_3(vpkshss, void, avr, avr, avr)
DEF_HELPER_3(vpkshus, void, avr, avr, avr)
DEF_HELPER_3(vpkswss, void, avr, avr, avr)
DEF_HELPER_3(vpkswus, void, avr, avr, avr)
DEF_HELPER_3(vpkuhus, void, avr, avr, avr)
DEF_HELPER_3(vpkuwus, void, avr, avr, avr)
DEF_HELPER_3(vpkuhum, void, avr, avr, avr)
DEF_HELPER_3(vpkuwum, void, avr, avr, avr)
DEF_HELPER_3(vpkpx, void, avr, avr, avr)
DEF_HELPER_4(vmhaddshs, void, avr, avr, avr, avr)
DEF_HELPER_4(vmhraddshs, void, avr, avr, avr, avr)
DEF_HELPER_4(vmsumuhm, void, avr, avr, avr, avr)
DEF_HELPER_4(vmsumuhs, void, avr, avr, avr, avr)
DEF_HELPER_4(vmsumshm, void, avr, avr, avr, avr)
DEF_HELPER_4(vmsumshs, void, avr, avr, avr, avr)
DEF_HELPER_4(vmladduhm, void, avr, avr, avr, avr)
DEF_HELPER_1(mtvscr, void, avr);
DEF_HELPER_2(lvebx, void, avr, tl)
DEF_HELPER_2(lvehx, void, avr, tl)
DEF_HELPER_2(lvewx, void, avr, tl)
DEF_HELPER_2(stvebx, void, avr, tl)
DEF_HELPER_2(stvehx, void, avr, tl)
DEF_HELPER_2(stvewx, void, avr, tl)
DEF_HELPER_3(vsumsws, void, avr, avr, avr)
DEF_HELPER_3(vsum2sws, void, avr, avr, avr)
DEF_HELPER_3(vsum4sbs, void, avr, avr, avr)
DEF_HELPER_3(vsum4shs, void, avr, avr, avr)
DEF_HELPER_3(vsum4ubs, void, avr, avr, avr)
DEF_HELPER_3(vaddfp, void, avr, avr, avr)
DEF_HELPER_3(vsubfp, void, avr, avr, avr)
DEF_HELPER_3(vmaxfp, void, avr, avr, avr)
DEF_HELPER_3(vminfp, void, avr, avr, avr)
DEF_HELPER_2(vrefp, void, avr, avr)
DEF_HELPER_2(vrsqrtefp, void, avr, avr)
DEF_HELPER_4(vmaddfp, void, avr, avr, avr, avr)
DEF_HELPER_4(vnmsubfp, void, avr, avr, avr, avr)
DEF_HELPER_2(vexptefp, void, avr, avr)
DEF_HELPER_2(vlogefp, void, avr, avr)
DEF_HELPER_2(vrfim, void, avr, avr)
DEF_HELPER_2(vrfin, void, avr, avr)
DEF_HELPER_2(vrfip, void, avr, avr)
DEF_HELPER_2(vrfiz, void, avr, avr)
DEF_HELPER_3(vcfux, void, avr, avr, i32)
DEF_HELPER_3(vcfsx, void, avr, avr, i32)
DEF_HELPER_3(vctuxs, void, avr, avr, i32)
DEF_HELPER_3(vctsxs, void, avr, avr, i32)

DEF_HELPER_1(efscfsi, i32, i32)
DEF_HELPER_1(efscfui, i32, i32)
DEF_HELPER_1(efscfuf, i32, i32)
DEF_HELPER_1(efscfsf, i32, i32)
DEF_HELPER_1(efsctsi, i32, i32)
DEF_HELPER_1(efsctui, i32, i32)
DEF_HELPER_1(efsctsiz, i32, i32)
DEF_HELPER_1(efsctuiz, i32, i32)
DEF_HELPER_1(efsctsf, i32, i32)
DEF_HELPER_1(efsctuf, i32, i32)
DEF_HELPER_1(evfscfsi, i64, i64)
DEF_HELPER_1(evfscfui, i64, i64)
DEF_HELPER_1(evfscfuf, i64, i64)
DEF_HELPER_1(evfscfsf, i64, i64)
DEF_HELPER_1(evfsctsi, i64, i64)
DEF_HELPER_1(evfsctui, i64, i64)
DEF_HELPER_1(evfsctsiz, i64, i64)
DEF_HELPER_1(evfsctuiz, i64, i64)
DEF_HELPER_1(evfsctsf, i64, i64)
DEF_HELPER_1(evfsctuf, i64, i64)
DEF_HELPER_2(efsadd, i32, i32, i32)
DEF_HELPER_2(efssub, i32, i32, i32)
DEF_HELPER_2(efsmul, i32, i32, i32)
DEF_HELPER_2(efsdiv, i32, i32, i32)
DEF_HELPER_2(evfsadd, i64, i64, i64)
DEF_HELPER_2(evfssub, i64, i64, i64)
DEF_HELPER_2(evfsmul, i64, i64, i64)
DEF_HELPER_2(evfsdiv, i64, i64, i64)
DEF_HELPER_2(efststlt, i32, i32, i32)
DEF_HELPER_2(efststgt, i32, i32, i32)
DEF_HELPER_2(efststeq, i32, i32, i32)
DEF_HELPER_2(efscmplt, i32, i32, i32)
DEF_HELPER_2(efscmpgt, i32, i32, i32)
DEF_HELPER_2(efscmpeq, i32, i32, i32)
DEF_HELPER_2(evfststlt, i32, i64, i64)
DEF_HELPER_2(evfststgt, i32, i64, i64)
DEF_HELPER_2(evfststeq, i32, i64, i64)
DEF_HELPER_2(evfscmplt, i32, i64, i64)
DEF_HELPER_2(evfscmpgt, i32, i64, i64)
DEF_HELPER_2(evfscmpeq, i32, i64, i64)
DEF_HELPER_1(efdcfsi, i64, i32)
DEF_HELPER_1(efdcfsid, i64, i64)
DEF_HELPER_1(efdcfui, i64, i32)
DEF_HELPER_1(efdcfuid, i64, i64)
DEF_HELPER_1(efdctsi, i32, i64)
DEF_HELPER_1(efdctui, i32, i64)
DEF_HELPER_1(efdctsiz, i32, i64)
DEF_HELPER_1(efdctsidz, i64, i64)
DEF_HELPER_1(efdctuiz, i32, i64)
DEF_HELPER_1(efdctuidz, i64, i64)
DEF_HELPER_1(efdcfsf, i64, i32)
DEF_HELPER_1(efdcfuf, i64, i32)
DEF_HELPER_1(efdctsf, i32, i64)
DEF_HELPER_1(efdctuf, i32, i64)
DEF_HELPER_1(efscfd, i32, i64)
DEF_HELPER_1(efdcfs, i64, i32)
DEF_HELPER_2(efdadd, i64, i64, i64)
DEF_HELPER_2(efdsub, i64, i64, i64)
DEF_HELPER_2(efdmul, i64, i64, i64)
DEF_HELPER_2(efddiv, i64, i64, i64)
DEF_HELPER_2(efdtstlt, i32, i64, i64)
DEF_HELPER_2(efdtstgt, i32, i64, i64)
DEF_HELPER_2(efdtsteq, i32, i64, i64)
DEF_HELPER_2(efdcmplt, i32, i64, i64)
DEF_HELPER_2(efdcmpgt, i32, i64, i64)
DEF_HELPER_2(efdcmpeq, i32, i64, i64)

#if !defined(CONFIG_USER_ONLY)
DEF_HELPER_1(4xx_tlbre_hi, tl, tl)
DEF_HELPER_1(4xx_tlbre_lo, tl, tl)
DEF_HELPER_2(4xx_tlbwe_hi, void, tl, tl)
DEF_HELPER_2(4xx_tlbwe_lo, void, tl, tl)
DEF_HELPER_1(4xx_tlbsx, tl, tl)
DEF_HELPER_2(440_tlbre, tl, i32, tl)
DEF_HELPER_3(440_tlbwe, void, i32, tl, tl)
DEF_HELPER_1(440_tlbsx, tl, tl)
DEF_HELPER_0(booke206_tlbre, void)
DEF_HELPER_0(booke206_tlbwe, void)
DEF_HELPER_1(booke206_tlbsx, void, tl)
DEF_HELPER_1(booke206_tlbivax, void, tl)
DEF_HELPER_1(booke206_tlbilx0, void, tl)
DEF_HELPER_1(booke206_tlbilx1, void, tl)
DEF_HELPER_1(booke206_tlbilx3, void, tl)
DEF_HELPER_1(booke206_tlbflush, void, i32)
DEF_HELPER_2(booke_setpid, void, i32, tl)
DEF_HELPER_1(6xx_tlbd, void, tl)
DEF_HELPER_1(6xx_tlbi, void, tl)
DEF_HELPER_1(74xx_tlbd, void, tl)
DEF_HELPER_1(74xx_tlbi, void, tl)
DEF_HELPER_FLAGS_0(tlbia, TCG_CALL_CONST, void)
DEF_HELPER_FLAGS_1(tlbie, TCG_CALL_CONST, void, tl)
#if defined(TARGET_PPC64)
DEF_HELPER_FLAGS_2(store_slb, TCG_CALL_CONST, void, tl, tl)
DEF_HELPER_1(load_slb_esid, tl, tl)
DEF_HELPER_1(load_slb_vsid, tl, tl)
DEF_HELPER_FLAGS_0(slbia, TCG_CALL_CONST, void)
DEF_HELPER_FLAGS_1(slbie, TCG_CALL_CONST, void, tl)
#endif
DEF_HELPER_FLAGS_1(load_sr, TCG_CALL_CONST, tl, tl);
DEF_HELPER_FLAGS_2(store_sr, TCG_CALL_CONST, void, tl, tl)

DEF_HELPER_FLAGS_1(602_mfrom, TCG_CALL_CONST | TCG_CALL_PURE, tl, tl)
DEF_HELPER_1(msgsnd, void, tl)
DEF_HELPER_2(msgclr, void, env, tl)
#endif

DEF_HELPER_3(dlmzb, tl, tl, tl, i32)
DEF_HELPER_FLAGS_1(clcs, TCG_CALL_CONST | TCG_CALL_PURE, tl, i32)
#if !defined(CONFIG_USER_ONLY)
DEF_HELPER_1(rac, tl, tl)
#endif
DEF_HELPER_2(div, tl, tl, tl)
DEF_HELPER_2(divo, tl, tl, tl)
DEF_HELPER_2(divs, tl, tl, tl)
DEF_HELPER_2(divso, tl, tl, tl)

DEF_HELPER_1(load_dcr, tl, tl);
DEF_HELPER_2(store_dcr, void, tl, tl)

DEF_HELPER_1(load_dump_spr, void, i32)
DEF_HELPER_1(store_dump_spr, void, i32)
DEF_HELPER_0(load_tbl, tl)
DEF_HELPER_0(load_tbu, tl)
DEF_HELPER_0(load_atbl, tl)
DEF_HELPER_0(load_atbu, tl)
DEF_HELPER_0(load_601_rtcl, tl)
DEF_HELPER_0(load_601_rtcu, tl)
#if !defined(CONFIG_USER_ONLY)
#if defined(TARGET_PPC64)
DEF_HELPER_1(store_asr, void, tl)
DEF_HELPER_0(load_purr, tl)
#endif
DEF_HELPER_1(store_sdr1, void, tl)
DEF_HELPER_1(store_tbl, void, tl)
DEF_HELPER_1(store_tbu, void, tl)
DEF_HELPER_1(store_atbl, void, tl)
DEF_HELPER_1(store_atbu, void, tl)
DEF_HELPER_1(store_601_rtcl, void, tl)
DEF_HELPER_1(store_601_rtcu, void, tl)
DEF_HELPER_0(load_decr, tl)
DEF_HELPER_1(store_decr, void, tl)
DEF_HELPER_1(store_hid0_601, void, tl)
DEF_HELPER_2(store_403_pbr, void, i32, tl)
DEF_HELPER_0(load_40x_pit, tl)
DEF_HELPER_1(store_40x_pit, void, tl)
DEF_HELPER_1(store_40x_dbcr0, void, tl)
DEF_HELPER_1(store_40x_sler, void, tl)
DEF_HELPER_1(store_booke_tcr, void, tl)
DEF_HELPER_1(store_booke_tsr, void, tl)
DEF_HELPER_2(store_ibatl, void, i32, tl)
DEF_HELPER_2(store_ibatu, void, i32, tl)
DEF_HELPER_2(store_dbatl, void, i32, tl)
DEF_HELPER_2(store_dbatu, void, i32, tl)
DEF_HELPER_2(store_601_batl, void, i32, tl)
DEF_HELPER_2(store_601_batu, void, i32, tl)
#endif

#include "def-helper.h"
