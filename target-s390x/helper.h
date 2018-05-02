#include "exec/def-helper.h"

DEF_HELPER_2(exception, void, env, i32)
DEF_HELPER_FLAGS_4(nc, TCG_CALL_NO_WG, i32, env, i32, i64, i64)
DEF_HELPER_FLAGS_4(oc, TCG_CALL_NO_WG, i32, env, i32, i64, i64)
DEF_HELPER_FLAGS_4(xc, TCG_CALL_NO_WG, i32, env, i32, i64, i64)
DEF_HELPER_FLAGS_4(mvc, TCG_CALL_NO_WG, void, env, i32, i64, i64)
DEF_HELPER_FLAGS_4(clc, TCG_CALL_NO_WG, i32, env, i32, i64, i64)
DEF_HELPER_3(mvcl, i32, env, i32, i32)
DEF_HELPER_FLAGS_4(clm, TCG_CALL_NO_WG, i32, env, i32, i32, i64)
DEF_HELPER_FLAGS_3(mul128, TCG_CALL_NO_RWG, i64, env, i64, i64)
DEF_HELPER_3(divs32, s64, env, s64, s64)
DEF_HELPER_3(divu32, i64, env, i64, i64)
DEF_HELPER_3(divs64, s64, env, s64, s64)
DEF_HELPER_4(divu64, i64, env, i64, i64, i64)
DEF_HELPER_4(srst, i64, env, i64, i64, i64)
DEF_HELPER_4(clst, i64, env, i64, i64, i64)
DEF_HELPER_4(mvpg, void, env, i64, i64, i64)
DEF_HELPER_4(mvst, i64, env, i64, i64, i64)
DEF_HELPER_5(ex, i32, env, i32, i64, i64, i64)
DEF_HELPER_FLAGS_1(abs_i32, TCG_CALL_NO_RWG_SE, i32, s32)
DEF_HELPER_FLAGS_1(nabs_i32, TCG_CALL_NO_RWG_SE, s32, s32)
DEF_HELPER_FLAGS_1(abs_i64, TCG_CALL_NO_RWG_SE, i64, s64)
DEF_HELPER_FLAGS_1(nabs_i64, TCG_CALL_NO_RWG_SE, s64, s64)
DEF_HELPER_FLAGS_4(stam, TCG_CALL_NO_WG, void, env, i32, i64, i32)
DEF_HELPER_FLAGS_4(lam, TCG_CALL_NO_WG, void, env, i32, i64, i32)
DEF_HELPER_4(mvcle, i32, env, i32, i64, i32)
DEF_HELPER_4(clcle, i32, env, i32, i64, i32)
DEF_HELPER_3(cegb, i64, env, s64, i32)
DEF_HELPER_3(cdgb, i64, env, s64, i32)
DEF_HELPER_3(cxgb, i64, env, s64, i32)
DEF_HELPER_3(celgb, i64, env, i64, i32)
DEF_HELPER_3(cdlgb, i64, env, i64, i32)
DEF_HELPER_3(cxlgb, i64, env, i64, i32)
DEF_HELPER_3(aeb, i64, env, i64, i64)
DEF_HELPER_3(adb, i64, env, i64, i64)
DEF_HELPER_5(axb, i64, env, i64, i64, i64, i64)
DEF_HELPER_3(seb, i64, env, i64, i64)
DEF_HELPER_3(sdb, i64, env, i64, i64)
DEF_HELPER_5(sxb, i64, env, i64, i64, i64, i64)
DEF_HELPER_3(deb, i64, env, i64, i64)
DEF_HELPER_3(ddb, i64, env, i64, i64)
DEF_HELPER_5(dxb, i64, env, i64, i64, i64, i64)
DEF_HELPER_3(meeb, i64, env, i64, i64)
DEF_HELPER_3(mdeb, i64, env, i64, i64)
DEF_HELPER_3(mdb, i64, env, i64, i64)
DEF_HELPER_5(mxb, i64, env, i64, i64, i64, i64)
DEF_HELPER_4(mxdb, i64, env, i64, i64, i64)
DEF_HELPER_2(ldeb, i64, env, i64)
DEF_HELPER_3(ldxb, i64, env, i64, i64)
DEF_HELPER_2(lxdb, i64, env, i64)
DEF_HELPER_2(lxeb, i64, env, i64)
DEF_HELPER_2(ledb, i64, env, i64)
DEF_HELPER_3(lexb, i64, env, i64, i64)
DEF_HELPER_FLAGS_3(ceb, TCG_CALL_NO_WG_SE, i32, env, i64, i64)
DEF_HELPER_FLAGS_3(cdb, TCG_CALL_NO_WG_SE, i32, env, i64, i64)
DEF_HELPER_FLAGS_5(cxb, TCG_CALL_NO_WG_SE, i32, env, i64, i64, i64, i64)
DEF_HELPER_3(cgeb, i64, env, i64, i32)
DEF_HELPER_3(cgdb, i64, env, i64, i32)
DEF_HELPER_4(cgxb, i64, env, i64, i64, i32)
DEF_HELPER_3(cfeb, i64, env, i64, i32)
DEF_HELPER_3(cfdb, i64, env, i64, i32)
DEF_HELPER_4(cfxb, i64, env, i64, i64, i32)
DEF_HELPER_3(clgeb, i64, env, i64, i32)
DEF_HELPER_3(clgdb, i64, env, i64, i32)
DEF_HELPER_4(clgxb, i64, env, i64, i64, i32)
DEF_HELPER_3(clfeb, i64, env, i64, i32)
DEF_HELPER_3(clfdb, i64, env, i64, i32)
DEF_HELPER_4(clfxb, i64, env, i64, i64, i32)
DEF_HELPER_4(maeb, i64, env, i64, i64, i64)
DEF_HELPER_4(madb, i64, env, i64, i64, i64)
DEF_HELPER_4(mseb, i64, env, i64, i64, i64)
DEF_HELPER_4(msdb, i64, env, i64, i64, i64)
DEF_HELPER_FLAGS_2(tceb, TCG_CALL_NO_RWG_SE, i32, i64, i64)
DEF_HELPER_FLAGS_2(tcdb, TCG_CALL_NO_RWG_SE, i32, i64, i64)
DEF_HELPER_FLAGS_3(tcxb, TCG_CALL_NO_RWG_SE, i32, i64, i64, i64)
DEF_HELPER_FLAGS_1(clz, TCG_CALL_NO_RWG_SE, i64, i64)
DEF_HELPER_2(sqeb, i64, env, i64)
DEF_HELPER_2(sqdb, i64, env, i64)
DEF_HELPER_3(sqxb, i64, env, i64, i64)
DEF_HELPER_FLAGS_1(cvd, TCG_CALL_NO_RWG_SE, i64, s32)
DEF_HELPER_FLAGS_4(unpk, TCG_CALL_NO_WG, void, env, i32, i64, i64)
DEF_HELPER_FLAGS_4(tr, TCG_CALL_NO_WG, void, env, i32, i64, i64)
DEF_HELPER_4(cksm, i64, env, i64, i64, i64)
DEF_HELPER_FLAGS_5(calc_cc, TCG_CALL_NO_RWG_SE, i32, env, i32, i64, i64, i64)
DEF_HELPER_FLAGS_2(sfpc, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_2(sfas, TCG_CALL_NO_WG, void, env, i64)
DEF_HELPER_FLAGS_1(popcnt, TCG_CALL_NO_RWG_SE, i64, i64)

#ifndef CONFIG_USER_ONLY
DEF_HELPER_3(servc, i32, env, i64, i64)
DEF_HELPER_4(diag, i64, env, i32, i64, i64)
DEF_HELPER_3(load_psw, void, env, i64, i64)
DEF_HELPER_FLAGS_2(spx, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_1(stck, TCG_CALL_NO_RWG_SE, i64, env)
DEF_HELPER_FLAGS_2(sckc, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_1(stckc, TCG_CALL_NO_RWG, i64, env)
DEF_HELPER_FLAGS_2(spt, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_1(stpt, TCG_CALL_NO_RWG, i64, env)
DEF_HELPER_4(stsi, i32, env, i64, i64, i64)
DEF_HELPER_FLAGS_4(lctl, TCG_CALL_NO_WG, void, env, i32, i64, i32)
DEF_HELPER_FLAGS_4(lctlg, TCG_CALL_NO_WG, void, env, i32, i64, i32)
DEF_HELPER_FLAGS_4(stctl, TCG_CALL_NO_WG, void, env, i32, i64, i32)
DEF_HELPER_FLAGS_4(stctg, TCG_CALL_NO_WG, void, env, i32, i64, i32)
DEF_HELPER_FLAGS_2(tprot, TCG_CALL_NO_RWG, i32, i64, i64)
DEF_HELPER_FLAGS_2(iske, TCG_CALL_NO_RWG_SE, i64, env, i64)
DEF_HELPER_FLAGS_3(sske, TCG_CALL_NO_RWG, void, env, i64, i64)
DEF_HELPER_FLAGS_2(rrbe, TCG_CALL_NO_RWG, i32, env, i64)
DEF_HELPER_3(csp, i32, env, i32, i64)
DEF_HELPER_4(mvcs, i32, env, i64, i64, i64)
DEF_HELPER_4(mvcp, i32, env, i64, i64, i64)
DEF_HELPER_4(sigp, i32, env, i64, i32, i64)
DEF_HELPER_2(sacf, void, env, i64)
DEF_HELPER_FLAGS_3(ipte, TCG_CALL_NO_RWG, void, env, i64, i64)
DEF_HELPER_FLAGS_1(ptlb, TCG_CALL_NO_RWG, void, env)
DEF_HELPER_2(lra, i64, env, i64)
DEF_HELPER_FLAGS_3(stura, TCG_CALL_NO_WG, void, env, i64, i64)
#endif

#include "exec/def-helper.h"
