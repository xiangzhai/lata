#include "qemu/osdep.h"
#include "qemu/log.h"

#include "target/arm/lata/include/dataflow.h"
#include "target/arm/lata/include/ir1.h"
#include "target/arm/lata/include/lata-options.h"
#ifdef CONFIG_LATA_TU
#include "target/arm/lata/include/tu.h"
#endif

typedef struct LataActiveDF {
    TranslationBlock *tb;
    uint32_t next_index;
} LataActiveDF;

static __thread LataActiveDF active_df;

enum {
    LATA_NZCV_N = 1u << 3,
    LATA_NZCV_Z = 1u << 2,
    LATA_NZCV_C = 1u << 1,
    LATA_NZCV_V = 1u << 0,
    LATA_NZCV_ALL = LATA_NZCV_N | LATA_NZCV_Z | LATA_NZCV_C | LATA_NZCV_V,
};

typedef struct LataNZCVRule {
    uint32_t pattern;
    uint32_t mask;
    uint8_t use;
    uint8_t def;
} LataNZCVRule;

typedef void (*LataGPRFactFn)(LataIR1Facts *fact, DisasContext *ir1);

typedef struct LataGPRRule {
    AARCH64_INSN_TYPE_A64 type;
    LataGPRFactFn fn;
} LataGPRRule;

static const LataNZCVRule nzcv_rules[] = {
    { 0x31000000, 0x3f800000, 0, LATA_NZCV_ALL }, /* ADDS/SUBS immediate */
    { 0x2b000000, 0x3f200000, 0, LATA_NZCV_ALL }, /* ADDS/SUBS shifted */
    { 0x2b200000, 0x3fe00000, 0, LATA_NZCV_ALL }, /* ADDS/SUBS extended */
    { 0x3a000000, 0x3fe0fc00, LATA_NZCV_C, LATA_NZCV_ALL }, /* ADCS/SBCS */
    { 0x1a000000, 0x3fe0fc00, LATA_NZCV_C, 0 }, /* ADC/SBC */
    { 0x72000000, 0x7f800000, 0, LATA_NZCV_ALL }, /* ANDS immediate */
    { 0x6a000000, 0x7f000000, 0, LATA_NZCV_ALL }, /* ANDS/BICS shifted */
    { 0x1e202000, 0x5f203c00, 0, LATA_NZCV_ALL }, /* FCMP/FCMPE */
    { 0x1e200400, 0x5f200c00, LATA_NZCV_ALL, LATA_NZCV_ALL }, /* FCCMP */
    { 0xba000400, 0xffe07c10, LATA_NZCV_ALL, 0 }, /* RMIF def is mask-based */
    { 0x3a400800, 0x3e400400, LATA_NZCV_ALL, LATA_NZCV_ALL }, /* CCMP/CCMN */
    { 0xd500401f, 0xfffffc1f, LATA_NZCV_C, LATA_NZCV_C }, /* CFINV */
    { 0xd500403f, 0xfffffc1f, LATA_NZCV_ALL, LATA_NZCV_ALL }, /* XAFLAG */
    { 0xd500405f, 0xfffffc1f, LATA_NZCV_ALL, LATA_NZCV_ALL }, /* AXFLAG */
    { 0x3a000800, 0x7fe0fc00, 0,
      LATA_NZCV_N | LATA_NZCV_Z | LATA_NZCV_V }, /* SETF8/SETF16 */
    { 0, 0, 0, 0 },
};

static inline uint32_t reg_bit(unsigned reg)
{
    return reg < 31 ? (1u << reg) : 0;
}

static inline void fact_use(LataIR1Facts *fact, unsigned reg, bool x_use)
{
    fact->gpr_use |= reg_bit(reg);
    if (x_use) {
        fact->gpr_x_use |= reg_bit(reg);
    }
}

static inline void fact_def(LataIR1Facts *fact, unsigned reg, bool is_w)
{
    fact->gpr_def |= reg_bit(reg);
    if (is_w) {
        fact->gpr_wdef |= reg_bit(reg);
    }
}

static inline void fact_vec_use(LataIR1Facts *fact, unsigned reg)
{
    if (reg < 32) {
        fact->vec_use |= 1u << reg;
    }
}

static inline void fact_vec_def(LataIR1Facts *fact, unsigned reg)
{
    if (reg < 32) {
        fact->vec_def |= 1u << reg;
    }
}

static inline void fact_use_sp_addr(LataIR1Facts *fact, unsigned reg)
{
    if (reg < 31) {
        fact_use(fact, reg, true);
    }
}

static inline void fact_mem_reg_addr(LataIR1Facts *fact, arg_ldst *a)
{
    fact_use_sp_addr(fact, a->rn);
    fact_use(fact, a->rm, true);
}

static inline void fact_mem_imm_addr(LataIR1Facts *fact, arg_ldst_imm *a)
{
    fact_use_sp_addr(fact, a->rn);
    if (a->w) {
        fact_def(fact, a->rn, false);
    }
}

static inline void fact_mem_stlr_addr(LataIR1Facts *fact, arg_stlr *a)
{
    fact_use_sp_addr(fact, a->rn);
}

static inline void fact_mem_stxr_addr(LataIR1Facts *fact, arg_stxr *a)
{
    fact_use_sp_addr(fact, a->rn);
}

static inline void fact_mem_ldapr_stlr_addr(LataIR1Facts *fact,
                                            arg_ldapr_stlr_i *a)
{
    fact_use_sp_addr(fact, a->rn);
}

static inline void fact_atomic_addr(LataIR1Facts *fact, arg_atomic *a)
{
    fact_use_sp_addr(fact, a->rn);
}

static inline void fact_cas_addr(LataIR1Facts *fact, arg_CAS *a)
{
    fact_use_sp_addr(fact, a->rn);
}

static inline void fact_ldapr_addr(LataIR1Facts *fact,
                                   arg_decode_insn3227 *a)
{
    fact_use_sp_addr(fact, a->rn);
}

static inline void fact_mem_pair_addr(LataIR1Facts *fact, arg_ldstpair *a)
{
    fact_use_sp_addr(fact, a->rn);
    if (a->w) {
        fact_def(fact, a->rn, false);
    }
}

static inline void fact_mem_mult_addr(LataIR1Facts *fact, arg_ldst_mult *a)
{
    fact_use_sp_addr(fact, a->rn);
    if (a->p) {
        fact_use(fact, a->rm, true);
        fact_def(fact, a->rn, false);
    }
}

static inline void fact_mem_single_addr(LataIR1Facts *fact, arg_ldst_single *a)
{
    fact_use_sp_addr(fact, a->rn);
    if (a->p) {
        fact_use(fact, a->rm, true);
        fact_def(fact, a->rn, false);
    }
}

static void fact_vec_range_use(LataIR1Facts *fact, unsigned first,
                               unsigned count)
{
    for (unsigned i = 0; i < count; i++) {
        fact_vec_use(fact, (first + i) & 31);
    }
}

static void fact_vec_range_def(LataIR1Facts *fact, unsigned first,
                               unsigned count)
{
    for (unsigned i = 0; i < count; i++) {
        fact_vec_def(fact, (first + i) & 31);
    }
}

static void fact_rri_sf(LataIR1Facts *fact, DisasContext *ir1)
{
    arg_rri_sf *a = &ir1->arg.f_rri_sf;

    fact_use_sp_addr(fact, a->rn);
    if (a->rn < 31) {
        fact_use(fact, a->rn, a->sf);
    }
    fact_def(fact, a->rd, !a->sf);
}

static void fact_rri_log(LataIR1Facts *fact, DisasContext *ir1)
{
    arg_rri_log *a = &ir1->arg.f_rri_log;

    fact_use(fact, a->rn, a->sf);
    fact_def(fact, a->rd, !a->sf);
}

static void fact_bitfield(LataIR1Facts *fact, DisasContext *ir1)
{
    arg_bitfield *a = &ir1->arg.f_bitfield;

    if (ir1->insn_type == AARCH64_A64_BFM) {
        fact_use(fact, a->rd, a->sf);
    }
    fact_use(fact, a->rn, a->sf);
    fact_def(fact, a->rd, !a->sf);
}

static void fact_extract(LataIR1Facts *fact, DisasContext *ir1)
{
    arg_extract *a = &ir1->arg.f_extract;

    fact_use(fact, a->rn, a->sf);
    fact_use(fact, a->rm, a->sf);
    fact_def(fact, a->rd, !a->sf);
}

static void fact_movw(LataIR1Facts *fact, DisasContext *ir1)
{
    arg_movw *a = &ir1->arg.f_movw;

    if (ir1->insn_type == AARCH64_A64_MOVK) {
        fact_use(fact, a->rd, a->sf);
    }
    fact_def(fact, a->rd, !a->sf);
}

static void fact_sys(LataIR1Facts *fact, DisasContext *ir1)
{
    arg_SYS *a = &ir1->arg.f_decode_insn3218;

    if (a->l) {
        fact_def(fact, a->rt, true);
    } else {
        fact_use(fact, a->rt, true);
    }
}

static void fact_dataproc_reg(LataIR1Facts *fact, DisasContext *ir1)
{
    uint32_t insn = ir1->insn;
    bool sf = extract32(insn, 31, 1);
    unsigned rd = extract32(insn, 0, 5);
    unsigned rn = extract32(insn, 5, 5);
    unsigned rm = extract32(insn, 16, 5);
    unsigned op1 = extract32(insn, 28, 1);
    unsigned op2 = extract32(insn, 21, 4);
    unsigned op3 = extract32(insn, 10, 6);

    if (!op1) {
        fact_use(fact, rn, sf);
        fact_use(fact, rm, sf);
        fact_def(fact, rd, !sf);
        return;
    }

    if (op2 == 0 && op3 == 0) {
        fact_use(fact, rn, sf);
        fact_use(fact, rm, sf);
        fact_def(fact, rd, !sf);
        return;
    }

    if (op2 == 2) {
        fact_use(fact, rn, sf);
        if (!extract32(insn, 11, 1)) {
            fact_use(fact, rm, sf);
        }
        return;
    }

    if (op2 == 4) {
        fact_use(fact, rn, sf);
        fact_use(fact, rm, sf);
        fact_def(fact, rd, !sf);
        return;
    }

    if (op2 == 6) {
        if (extract32(insn, 30, 1)) {
            fact_use(fact, rn, sf);
            fact_def(fact, rd, !sf);
        } else {
            fact_use(fact, rn, sf);
            fact_use(fact, rm, sf);
            fact_def(fact, rd, !sf);
        }
        return;
    }

    if (op2 >= 8) {
        unsigned ra = extract32(insn, 10, 5);

        fact_use(fact, rn, sf);
        fact_use(fact, rm, sf);
        if (ra != 31) {
            fact_use(fact, ra, sf);
        }
        fact_def(fact, rd, !sf);
    }
}

static bool simd_fp_uses_helper(uint32_t insn)
{
    /* FJCVTZS is mostly inline, but still falls back to helper for NaN/Inf
     * and huge finite inputs.  TBL/TBX and the legacy helper-backed vector
     * conversion/saturating paths also need a full state boundary. */
    if ((insn & 0xfffffc00) == 0x1e7e0000) {
        return true;
    }
    if ((insn & 0xbf208c00) == 0x0e000000) {
        return true;
    }
    return false;
}

static void fact_simd_fp(LataIR1Facts *fact, DisasContext *ir1)
{
    uint32_t insn = ir1->insn;
    unsigned rd = extract32(insn, 0, 5);
    unsigned rn = extract32(insn, 5, 5);
    unsigned ra = extract32(insn, 10, 5);
    unsigned rm = extract32(insn, 16, 5);

    fact_vec_def(fact, rd);
    fact_vec_use(fact, rn);
    fact_vec_use(fact, rm);

    if ((insn & 0x1f000000) == 0x1f000000) {
        fact_vec_use(fact, ra);
    }
    if ((insn & 0xbf208c00) == 0x0e000000 &&
        extract32(insn, 12, 1)) {
        fact_vec_use(fact, rd);
    }
    if (simd_fp_uses_helper(insn)) {
        fact->helper_boundary = true;
        fact->state_boundary = true;
    }
}

static const LataGPRRule gpr_rules[] = {
    { AARCH64_A64_ADD_i, fact_rri_sf },
    { AARCH64_A64_ADDS_i, fact_rri_sf },
    { AARCH64_A64_SUB_i, fact_rri_sf },
    { AARCH64_A64_SUBS_i, fact_rri_sf },
    { AARCH64_A64_AND_i, fact_rri_log },
    { AARCH64_A64_ANDS_i, fact_rri_log },
    { AARCH64_A64_ORR_i, fact_rri_log },
    { AARCH64_A64_EOR_i, fact_rri_log },
    { AARCH64_A64_SBFM, fact_bitfield },
    { AARCH64_A64_UBFM, fact_bitfield },
    { AARCH64_A64_BFM, fact_bitfield },
    { AARCH64_A64_EXTR, fact_extract },
    { AARCH64_A64_MOVN, fact_movw },
    { AARCH64_A64_MOVZ, fact_movw },
    { AARCH64_A64_MOVK, fact_movw },
    { AARCH64_A64_SYS, fact_sys },
    { AARCH64_A64_DATA_PROC_REG, fact_dataproc_reg },
    { AARCH64_A64_DATA_PROC_SIMD_FD, fact_simd_fp },
    { AARCH64_A64_EXCP_ILLEGAL, NULL },
    { AARCH64_A64_EXCP_BTI, NULL },
    { AARCH64_A64_NULL, NULL },
};

static uint8_t nzcv_mask_from_rmif(uint32_t insn)
{
    return extract32(insn, 0, 4) & LATA_NZCV_ALL;
}

static uint8_t nzcv_mask_from_cond(unsigned cond)
{
    switch (cond & 0xe) {
    case 0x0: /* EQ/NE */
        return LATA_NZCV_Z;
    case 0x2: /* CS/CC */
        return LATA_NZCV_C;
    case 0x4: /* MI/PL */
        return LATA_NZCV_N;
    case 0x6: /* VS/VC */
        return LATA_NZCV_V;
    case 0x8: /* HI/LS */
        return LATA_NZCV_C | LATA_NZCV_Z;
    case 0xa: /* GE/LT */
        return LATA_NZCV_N | LATA_NZCV_V;
    case 0xc: /* GT/LE */
        return LATA_NZCV_N | LATA_NZCV_Z | LATA_NZCV_V;
    default: /* AL/NV */
        return 0;
    }
}

static bool sysreg_is_nzcv(DisasContext *ir1)
{
    arg_SYS *a = &ir1->arg.f_decode_insn3218;

    return ir1->insn_type == AARCH64_A64_SYS &&
           a->op0 == 3 && a->op1 == 3 && a->crn == 4 &&
           a->crm == 2 && a->op2 == 0;
}

static void analyze_nzcv_fact(LataIR1Facts *fact, DisasContext *ir1)
{
    uint32_t insn = ir1->insn;

    for (const LataNZCVRule *rule = nzcv_rules; rule->mask; rule++) {
        if ((insn & rule->mask) == rule->pattern) {
            fact->nzcv_use |= rule->use;
            fact->nzcv_def |= rule->def;
        }
    }

    if ((insn & 0xff000010) == 0x54000000) {
        fact->nzcv_use |= nzcv_mask_from_cond(extract32(insn, 0, 4));
    }
    if ((insn & 0x1fe00000) == 0x1a800000) {
        fact->nzcv_use |= nzcv_mask_from_cond(extract32(insn, 12, 4));
    }
    if ((insn & 0x5f200c00) == 0x1e200c00) {
        fact->nzcv_use |= nzcv_mask_from_cond(extract32(insn, 12, 4));
    }
    if ((insn & 0xffe07c10) == 0xba000400) {
        fact->nzcv_def |= nzcv_mask_from_rmif(insn);
    }
    if (sysreg_is_nzcv(ir1)) {
        if (ir1->arg.f_decode_insn3218.l) {
            fact->nzcv_use |= LATA_NZCV_ALL;
        } else {
            fact->nzcv_def |= LATA_NZCV_ALL;
        }
    }
}

static void analyze_gpr_common(LataIR1Facts *fact, DisasContext *ir1)
{
    uint32_t insn = ir1->insn;
    unsigned op0 = extract32(insn, 25, 4);
    bool sf = extract32(insn, 31, 1);
    bool table_handled = false;

    for (const LataGPRRule *rule = gpr_rules; rule->fn; rule++) {
        if (rule->type == ir1->insn_type) {
            rule->fn(fact, ir1);
            table_handled = true;
            break;
        }
    }

    switch (ir1->insn_type) {
    case AARCH64_A64_B:
    case AARCH64_A64_B_cond:
    case AARCH64_A64_SVC:
    case AARCH64_A64_BRK:
        break;
    case AARCH64_A64_CBZ:
        fact_use(fact, extract32(insn, 0, 5), sf);
        break;
    case AARCH64_A64_TBZ:
        fact_use(fact, extract32(insn, 0, 5), true);
        break;
    case AARCH64_A64_BR:
    case AARCH64_A64_BLR:
    case AARCH64_A64_RET:
        fact_use(fact, extract32(insn, 5, 5), true);
        fact->state_boundary = true;
        break;
    case AARCH64_A64_BL:
        fact_def(fact, 30, false);
        fact->state_boundary = true;
        break;
    case AARCH64_A64_ADR:
    case AARCH64_A64_ADRP:
        fact_def(fact, extract32(insn, 0, 5), !sf);
        break;
    case AARCH64_A64_LD_lit:
        fact_def(fact, extract32(insn, 0, 5), !sf);
        break;
    case AARCH64_A64_LDP:
        fact_mem_pair_addr(fact, &ir1->arg.f_ldstpair);
        fact_def(fact, ir1->arg.f_ldstpair.rt,
                 ir1->arg.f_ldstpair.sz != 3);
        fact_def(fact, ir1->arg.f_ldstpair.rt2,
                 ir1->arg.f_ldstpair.sz != 3);
        break;
    case AARCH64_A64_LDR:
        fact_mem_reg_addr(fact, &ir1->arg.f_ldst);
        fact_def(fact, ir1->arg.f_ldst.rt, ir1->arg.f_ldst.sz != 3);
        break;
    case AARCH64_A64_LDR_i:
        fact_mem_imm_addr(fact, &ir1->arg.f_ldst_imm);
        fact_def(fact, ir1->arg.f_ldst_imm.rt,
                 ir1->arg.f_ldst_imm.sz != 3);
        break;
    case AARCH64_A64_LDAR:
        fact_mem_stlr_addr(fact, &ir1->arg.f_stlr);
        fact_def(fact, ir1->arg.f_stlr.rt, ir1->arg.f_stlr.sz != 3);
        break;
    case AARCH64_A64_LDAPR:
        fact_ldapr_addr(fact, &ir1->arg.f_decode_insn3227);
        fact_def(fact, ir1->arg.f_decode_insn3227.rt,
                 ir1->arg.f_decode_insn3227.sz != 3);
        break;
    case AARCH64_A64_LDAPR_i:
        fact_mem_ldapr_stlr_addr(fact, &ir1->arg.f_ldapr_stlr_i);
        fact_def(fact, ir1->arg.f_ldapr_stlr_i.rt,
                 ir1->arg.f_ldapr_stlr_i.sz != 3);
        break;
    case AARCH64_A64_LDXR:
        fact_mem_stxr_addr(fact, &ir1->arg.f_stxr);
        fact_def(fact, ir1->arg.f_stxr.rt, ir1->arg.f_stxr.sz != 3);
        fact->state_boundary = true;
        break;
    case AARCH64_A64_LDXP:
        fact_mem_stxr_addr(fact, &ir1->arg.f_stxr);
        fact_def(fact, ir1->arg.f_stxr.rt, false);
        fact_def(fact, ir1->arg.f_stxr.rt2, false);
        fact->state_boundary = true;
        break;
    case AARCH64_A64_STR:
        fact_mem_reg_addr(fact, &ir1->arg.f_ldst);
        fact_use(fact, ir1->arg.f_ldst.rt, ir1->arg.f_ldst.sz == 3);
        break;
    case AARCH64_A64_STP:
        fact_mem_pair_addr(fact, &ir1->arg.f_ldstpair);
        fact_use(fact, ir1->arg.f_ldstpair.rt,
                 ir1->arg.f_ldstpair.sz == 3);
        fact_use(fact, ir1->arg.f_ldstpair.rt2,
                 ir1->arg.f_ldstpair.sz == 3);
        break;
    case AARCH64_A64_STR_i:
        fact_mem_imm_addr(fact, &ir1->arg.f_ldst_imm);
        fact_use(fact, ir1->arg.f_ldst_imm.rt,
                 ir1->arg.f_ldst_imm.sz == 3);
        break;
    case AARCH64_A64_STLR:
        fact_mem_stlr_addr(fact, &ir1->arg.f_stlr);
        fact_use(fact, ir1->arg.f_stlr.rt, ir1->arg.f_stlr.sz == 3);
        break;
    case AARCH64_A64_STLR_i:
        fact_mem_ldapr_stlr_addr(fact, &ir1->arg.f_ldapr_stlr_i);
        fact_use(fact, ir1->arg.f_ldapr_stlr_i.rt,
                 ir1->arg.f_ldapr_stlr_i.sz == 3);
        break;
    case AARCH64_A64_STXR:
        fact_mem_stxr_addr(fact, &ir1->arg.f_stxr);
        fact_use(fact, ir1->arg.f_stxr.rt, ir1->arg.f_stxr.sz == 3);
        fact_def(fact, ir1->arg.f_stxr.rs, true);
        fact->state_boundary = true;
        break;
    case AARCH64_A64_STXP:
        fact_mem_stxr_addr(fact, &ir1->arg.f_stxr);
        fact_use(fact, ir1->arg.f_stxr.rt, true);
        fact_use(fact, ir1->arg.f_stxr.rt2, true);
        fact_def(fact, ir1->arg.f_stxr.rs, true);
        fact->state_boundary = true;
        break;
    case AARCH64_A64_LDR_v:
        fact_mem_reg_addr(fact, &ir1->arg.f_ldst);
        fact_vec_def(fact, ir1->arg.f_ldst.rt);
        break;
    case AARCH64_A64_LDR_v_i:
        fact_mem_imm_addr(fact, &ir1->arg.f_ldst_imm);
        fact_vec_def(fact, ir1->arg.f_ldst_imm.rt);
        break;
    case AARCH64_A64_LDP_v:
        fact_mem_pair_addr(fact, &ir1->arg.f_ldstpair);
        fact_vec_def(fact, ir1->arg.f_ldstpair.rt);
        fact_vec_def(fact, ir1->arg.f_ldstpair.rt2);
        break;
    case AARCH64_A64_LD_lit_v:
        fact_vec_def(fact, extract32(insn, 0, 5));
        break;
    case AARCH64_A64_LD_mult:
        fact_mem_mult_addr(fact, &ir1->arg.f_ldst_mult);
        fact_vec_range_def(fact, ir1->arg.f_ldst_mult.rt,
                           ir1->arg.f_ldst_mult.rpt *
                           ir1->arg.f_ldst_mult.selem);
        break;
    case AARCH64_A64_LD_single:
    case AARCH64_A64_LD_single_repl:
        fact_mem_single_addr(fact, &ir1->arg.f_ldst_single);
        fact_vec_range_def(fact, ir1->arg.f_ldst_single.rt,
                           ir1->arg.f_ldst_single.selem);
        break;
    case AARCH64_A64_STR_v:
        fact_mem_reg_addr(fact, &ir1->arg.f_ldst);
        fact_vec_use(fact, ir1->arg.f_ldst.rt);
        break;
    case AARCH64_A64_STR_v_i:
        fact_mem_imm_addr(fact, &ir1->arg.f_ldst_imm);
        fact_vec_use(fact, ir1->arg.f_ldst_imm.rt);
        break;
    case AARCH64_A64_STP_v:
        fact_mem_pair_addr(fact, &ir1->arg.f_ldstpair);
        fact_vec_use(fact, ir1->arg.f_ldstpair.rt);
        fact_vec_use(fact, ir1->arg.f_ldstpair.rt2);
        break;
    case AARCH64_A64_ST_mult:
        fact_mem_mult_addr(fact, &ir1->arg.f_ldst_mult);
        fact_vec_range_use(fact, ir1->arg.f_ldst_mult.rt,
                           ir1->arg.f_ldst_mult.rpt *
                           ir1->arg.f_ldst_mult.selem);
        break;
    case AARCH64_A64_ST_single:
        fact_mem_single_addr(fact, &ir1->arg.f_ldst_single);
        fact_vec_range_use(fact, ir1->arg.f_ldst_single.rt,
                           ir1->arg.f_ldst_single.selem);
        break;
    case AARCH64_A64_LDADD:
    case AARCH64_A64_LDCLR:
    case AARCH64_A64_LDEOR:
    case AARCH64_A64_LDSET:
    case AARCH64_A64_LDSMAX:
    case AARCH64_A64_LDSMIN:
    case AARCH64_A64_LDUMAX:
    case AARCH64_A64_LDUMIN:
    case AARCH64_A64_SWP:
        fact_atomic_addr(fact, &ir1->arg.f_atomic);
        fact_use(fact, ir1->arg.f_atomic.rs, ir1->arg.f_atomic.sz == 3);
        fact_def(fact, ir1->arg.f_atomic.rt, ir1->arg.f_atomic.sz != 3);
        break;
    case AARCH64_A64_CAS:
        fact_cas_addr(fact, &ir1->arg.f_decode_insn3221);
        fact_use(fact, ir1->arg.f_decode_insn3221.rs,
                 ir1->arg.f_decode_insn3221.sz == 3);
        fact_use(fact, ir1->arg.f_decode_insn3221.rt,
                 ir1->arg.f_decode_insn3221.sz == 3);
        fact_def(fact, ir1->arg.f_decode_insn3221.rs,
                 ir1->arg.f_decode_insn3221.sz != 3);
        break;
    case AARCH64_A64_CASP:
        fact_cas_addr(fact, &ir1->arg.f_decode_insn3221);
        fact_use(fact, ir1->arg.f_decode_insn3221.rs, true);
        fact_use(fact, ir1->arg.f_decode_insn3221.rs + 1, true);
        fact_use(fact, ir1->arg.f_decode_insn3221.rt, true);
        fact_use(fact, ir1->arg.f_decode_insn3221.rt + 1, true);
        fact_def(fact, ir1->arg.f_decode_insn3221.rs, false);
        fact_def(fact, ir1->arg.f_decode_insn3221.rs + 1, false);
        fact->state_boundary = true;
        break;
    default:
        break;
    }

    if (!table_handled &&
        ir1->insn_type != AARCH64_A64_DATA_PROC_REG &&
        (op0 == 0x4 || op0 == 0x6 || op0 == 0x8 || op0 == 0xa)) {
        unsigned rd = extract32(insn, 0, 5);
        unsigned rn = extract32(insn, 5, 5);
        unsigned rm = extract32(insn, 16, 5);

        fact_use(fact, rn, sf);
        if (extract32(insn, 24, 1) || extract32(insn, 21, 3) != 4) {
            fact_use(fact, rm, sf);
        }
        fact_def(fact, rd, !sf);
    }

    if (!table_handled &&
        ((insn & 0x1f000000) == 0x11000000 ||
         (insn & 0x1f000000) == 0x12000000)) {
        unsigned rd = extract32(insn, 0, 5);
        unsigned rn = extract32(insn, 5, 5);

        fact_use(fact, rn, sf);
        fact_def(fact, rd, !sf);
    }

    if (!table_handled &&
        ir1->insn_type != AARCH64_A64_DATA_PROC_REG &&
        ((insn & 0x1f000000) == 0x0a000000 ||
         (insn & 0x1f000000) == 0x1a000000)) {
        unsigned rd = extract32(insn, 0, 5);
        unsigned rn = extract32(insn, 5, 5);
        unsigned rm = extract32(insn, 16, 5);

        fact_use(fact, rn, sf);
        fact_use(fact, rm, sf);
        fact_def(fact, rd, !sf);
    }
}

static void lata_df_analyze_ir1(LataIR1Facts *fact, DisasContext *ir1)
{
    memset(fact, 0, sizeof(*fact));

    analyze_nzcv_fact(fact, ir1);
    analyze_gpr_common(fact, ir1);

    switch (ir1->insn_type) {
    case AARCH64_A64_SVC:
    case AARCH64_A64_BRK:
    case AARCH64_A64_HLT:
    case AARCH64_A64_SYS:
    case AARCH64_A64_CRYPTO:
    case AARCH64_A64_EXCP_ILLEGAL:
    case AARCH64_A64_EXCP_BTI:
        fact->helper_boundary = true;
        fact->state_boundary = true;
        break;
    default:
        break;
    }
}

void lata_df_reset_tb(TranslationBlock *tb)
{
    if (!tb) {
        return;
    }
    tb->lata_df_ir1 = NULL;
    tb->lata_df_ir1_count = 0;
}

void lata_df_free_tb(TranslationBlock *tb)
{
    if (!tb || !tb->lata_df_ir1) {
        return;
    }
    g_free(tb->lata_df_ir1);
    lata_df_reset_tb(tb);
}

static LataIR1DF *lata_df_alloc_ir1(TranslationBlock *tb)
{
    lsassert(tb->icount <= TCG_MAX_INSNS);
    if (tb->lata_df_ir1_count != tb->icount) {
        g_free(tb->lata_df_ir1);
        tb->lata_df_ir1 = NULL;
        tb->lata_df_ir1_count = 0;
    }
    if (!tb->lata_df_ir1 && tb->icount) {
        tb->lata_df_ir1 = g_new0(LataIR1DF, tb->icount);
        tb->lata_df_ir1_count = tb->icount;
    }
    return tb->lata_df_ir1;
}

static void lata_df_store_summary(TranslationBlock *tb, LataIR1DF *df)
{
    uint32_t live = 0;
    uint32_t x_live = 0;
    uint32_t vec_live = 0;
    uint8_t nzcv_live = 0;
    bool helper_boundary = false;
    bool state_boundary = false;
    uint32_t gpr_up_use = 0;
    uint32_t gpr_up_x_use = 0;
    uint32_t gpr_def = 0;
    uint32_t gpr_wdef = 0;
    uint32_t gpr_all_use = 0;
    uint32_t gpr_all_x_use = 0;
    uint32_t vec_up_use = 0;
    uint32_t vec_def = 0;
    uint8_t nzcv_up_use = 0;
    uint8_t nzcv_def = 0;

    for (int i = tb->icount - 1; i >= 0; i--) {
        LataIR1Facts *fact = &df[i].fact;

        df[i].gpr_live_after = live;
        df[i].gpr_x_live_after = x_live;
        df[i].vec_live_after = vec_live;
        df[i].nzcv_live_after = nzcv_live;
        live = fact->gpr_use | (live & ~fact->gpr_def);
        x_live = fact->gpr_x_use | (x_live & ~fact->gpr_def);
        vec_live = fact->vec_use | (vec_live & ~fact->vec_def);
        nzcv_live = fact->nzcv_use | (nzcv_live & ~fact->nzcv_def);
        helper_boundary |= fact->helper_boundary;
        state_boundary |= fact->state_boundary;
        gpr_up_use = fact->gpr_use | (gpr_up_use & ~fact->gpr_def);
        gpr_up_x_use = fact->gpr_x_use | (gpr_up_x_use & ~fact->gpr_def);
        vec_up_use = fact->vec_use | (vec_up_use & ~fact->vec_def);
        nzcv_up_use = fact->nzcv_use | (nzcv_up_use & ~fact->nzcv_def);
        gpr_def |= fact->gpr_def;
        gpr_wdef |= fact->gpr_wdef;
        gpr_all_use |= fact->gpr_use;
        gpr_all_x_use |= fact->gpr_x_use;
        vec_def |= fact->vec_def;
        nzcv_def |= fact->nzcv_def;
    }

    tb->lata_df_gpr_use = gpr_up_use;
    tb->lata_df_gpr_x_use = gpr_up_x_use;
    tb->lata_df_gpr_def = gpr_def;
    tb->lata_df_gpr_wdef = gpr_wdef;
    tb->lata_df_gpr_all_use = gpr_all_use;
    tb->lata_df_gpr_all_x_use = gpr_all_x_use;
    tb->lata_df_gpr_live_in = live;
    tb->lata_df_gpr_live_out = UINT32_MAX;
    tb->lata_df_gpr_x_live_in = x_live;
    tb->lata_df_gpr_x_live_out = UINT32_MAX;
    tb->lata_df_vec_use = vec_up_use;
    tb->lata_df_vec_def = vec_def;
    tb->lata_df_vec_live_in = vec_live;
    tb->lata_df_vec_live_out = UINT32_MAX;
    tb->lata_df_nzcv_use_mask = nzcv_up_use;
    tb->lata_df_nzcv_def_mask = nzcv_def;
    tb->lata_df_nzcv_live_in_mask = nzcv_live;
    tb->lata_df_nzcv_live_out_mask = LATA_NZCV_ALL;
    tb->lata_df_nzcv_use = nzcv_up_use != 0;
    tb->lata_df_nzcv_def = nzcv_def != 0;
    tb->lata_df_nzcv_live_in = nzcv_live != 0;
    tb->lata_df_nzcv_live_out = true;
    tb->lata_df_helper_boundary = helper_boundary;
    tb->lata_df_state_boundary = state_boundary;

#ifdef CONFIG_LATA_INSTS_PATTERN
    tb->nzcv_use = tb->lata_df_nzcv_live_in;
#endif
}

static void lata_df_refresh_ir1_live_after(TranslationBlock *tb)
{
    LataIR1DF *df = tb ? tb->lata_df_ir1 : NULL;
    uint32_t live;
    uint32_t x_live;
    uint32_t vec_live;
    uint8_t nzcv_live;

    if (!tb || !df || !tb->icount) {
        return;
    }

    live = tb->lata_df_gpr_live_out;
    x_live = tb->lata_df_gpr_x_live_out;
    vec_live = tb->lata_df_vec_live_out;
    nzcv_live = tb->lata_df_nzcv_live_out_mask;

    for (int i = tb->icount - 1; i >= 0; i--) {
        LataIR1Facts *fact = &df[i].fact;

        df[i].gpr_live_after = live;
        df[i].gpr_x_live_after = x_live;
        df[i].vec_live_after = vec_live;
        df[i].nzcv_live_after = nzcv_live;
        live = fact->gpr_use | (live & ~fact->gpr_def);
        x_live = fact->gpr_x_use | (x_live & ~fact->gpr_def);
        vec_live = fact->vec_use | (vec_live & ~fact->vec_def);
        nzcv_live = fact->nzcv_use | (nzcv_live & ~fact->nzcv_def);
    }
}

void lata_df_analyze_tb(TranslationBlock *tb)
{
    DisasContext *ir1 = tb ? tb->ir1 : NULL;

    if (!tb || !ir1 || !tb->icount) {
        return;
    }

    LataIR1DF *df = lata_df_alloc_ir1(tb);
    memset(df, 0, sizeof(*df) * tb->icount);
    for (uint32_t i = 0; i < tb->icount; i++) {
        lata_df_analyze_ir1(&df[i].fact, &ir1[i]);
    }
    lata_df_store_summary(tb, df);
    lata_df_refresh_ir1_live_after(tb);
}

#ifdef CONFIG_LATA_TU
static void lata_df_get_successors(TranslationBlock *tb,
                                   TranslationBlock **succ,
                                   unsigned *succ_count)
{
    *succ_count = 0;
    if (tb->next_tb[TU_TB_INDEX_NEXT]) {
        succ[(*succ_count)++] = tb->next_tb[TU_TB_INDEX_NEXT];
    }
    if (tb->next_tb[TU_TB_INDEX_TARGET] &&
        tb->next_tb[TU_TB_INDEX_TARGET] != tb->next_tb[TU_TB_INDEX_NEXT]) {
        succ[(*succ_count)++] = tb->next_tb[TU_TB_INDEX_TARGET];
    }
}

void lata_df_analyze_tu(TranslationBlock **tb_list, uint32_t tb_count)
{
    bool changed;

    for (uint32_t i = 0; i < tb_count; i++) {
        lata_df_analyze_tb(tb_list[i]);
    }

    do {
        changed = false;
        for (int i = tb_count - 1; i >= 0; i--) {
            TranslationBlock *tb = tb_list[i];
            TranslationBlock *succ[2];
            unsigned succ_count;
            uint32_t old_live_out = tb->lata_df_gpr_live_out;
            uint32_t old_x_live_out = tb->lata_df_gpr_x_live_out;
            uint32_t old_vec_live_out = tb->lata_df_vec_live_out;
            uint8_t old_nzcv_live_out = tb->lata_df_nzcv_live_out_mask;
            bool has_external_exit = false;

            tb->lata_df_gpr_live_out = 0;
            tb->lata_df_gpr_x_live_out = 0;
            tb->lata_df_vec_live_out = 0;
            tb->lata_df_nzcv_live_out_mask = 0;
            lata_df_get_successors(tb, succ, &succ_count);

            for (unsigned j = 0; j < succ_count; j++) {
                tb->lata_df_gpr_live_out |= succ[j]->lata_df_gpr_live_in;
                tb->lata_df_gpr_x_live_out |= succ[j]->lata_df_gpr_x_live_in;
                tb->lata_df_vec_live_out |= succ[j]->lata_df_vec_live_in;
                tb->lata_df_nzcv_live_out_mask |=
                    succ[j]->lata_df_nzcv_live_in_mask;
            }

            switch (tb->last_ir1_type) {
            case IR1_TYPE_NORMAL:
                has_external_exit = !tb->next_tb[TU_TB_INDEX_NEXT];
                break;
            case IR1_TYPE_BRANCH:
                has_external_exit = !tb->next_tb[TU_TB_INDEX_NEXT] ||
                                    !tb->next_tb[TU_TB_INDEX_TARGET];
                break;
            case IR1_TYPE_JMP:
                has_external_exit = !tb->next_tb[TU_TB_INDEX_TARGET];
                break;
            default:
                has_external_exit = true;
                break;
            }

            if (has_external_exit || tb->lata_df_state_boundary ||
                tb->lata_df_helper_boundary) {
                tb->lata_df_gpr_live_out = UINT32_MAX;
                tb->lata_df_gpr_x_live_out = UINT32_MAX;
                tb->lata_df_vec_live_out = UINT32_MAX;
                tb->lata_df_nzcv_live_out_mask = LATA_NZCV_ALL;
            }

            tb->lata_df_gpr_live_in =
                tb->lata_df_gpr_use |
                (tb->lata_df_gpr_live_out & ~tb->lata_df_gpr_def);
            tb->lata_df_gpr_x_live_in =
                tb->lata_df_gpr_x_use |
                (tb->lata_df_gpr_x_live_out & ~tb->lata_df_gpr_def);
            tb->lata_df_vec_live_in =
                tb->lata_df_vec_use |
                (tb->lata_df_vec_live_out & ~tb->lata_df_vec_def);
            tb->lata_df_nzcv_live_in_mask =
                tb->lata_df_nzcv_use_mask |
                (tb->lata_df_nzcv_live_out_mask &
                 ~tb->lata_df_nzcv_def_mask);
            tb->lata_df_nzcv_live_in = tb->lata_df_nzcv_live_in_mask != 0;
            tb->lata_df_nzcv_live_out = tb->lata_df_nzcv_live_out_mask != 0;
#ifdef CONFIG_LATA_INSTS_PATTERN
            tb->nzcv_use = tb->lata_df_nzcv_live_in;
#endif

            changed |= old_live_out != tb->lata_df_gpr_live_out ||
                       old_x_live_out != tb->lata_df_gpr_x_live_out ||
                       old_vec_live_out != tb->lata_df_vec_live_out ||
                       old_nzcv_live_out != tb->lata_df_nzcv_live_out_mask;
        }
    } while (changed);

    for (uint32_t i = 0; i < tb_count; i++) {
        lata_df_refresh_ir1_live_after(tb_list[i]);
    }
}
#endif

void lata_df_begin_translate(TranslationBlock *tb)
{
    active_df.tb = tb;
    active_df.next_index = 0;
}

void lata_df_end_translate(void)
{
    active_df.tb = NULL;
    active_df.next_index = 0;
}

void lata_df_advance_insn(void)
{
    if (active_df.tb && active_df.next_index < TCG_MAX_INSNS) {
        active_df.next_index++;
    }
}

void lata_df_mark_helper_boundary(void)
{
    TranslationBlock *tb = active_df.tb;
    LataIR1DF *df;

    if (!tb || active_df.next_index >= tb->icount ||
        active_df.next_index >= TCG_MAX_INSNS) {
        return;
    }
    df = tb->lata_df_ir1;
    if (!df) {
        return;
    }
    df[active_df.next_index].fact.helper_boundary = true;
    df[active_df.next_index].fact.state_boundary = true;
    tb->lata_df_helper_boundary = true;
    tb->lata_df_state_boundary = true;
}

bool lata_df_reg_high_live_after_write(unsigned reg)
{
    TranslationBlock *tb = active_df.tb;
    uint32_t index = active_df.next_index;
    LataIR1DF *df;

    if (!option_lata_dataflow_opt || !tb || reg >= 31) {
        return true;
    }
    if (tb->lata_df_helper_boundary || tb->lata_df_state_boundary) {
        return true;
    }
    if (index >= tb->icount || index >= TCG_MAX_INSNS) {
        return true;
    }
    df = tb->lata_df_ir1;
    if (!df) {
        return true;
    }
    return (df[index].gpr_x_live_after & (1u << reg)) != 0;
}

bool lata_df_should_save_nzcv_for_edge(TranslationBlock *tb, unsigned edge)
{
    if (!option_lata_dataflow_opt || !tb || edge > 1) {
        return true;
    }
#ifdef CONFIG_LATA_TU
    TranslationBlock *next = tb->next_tb[edge];
    if (next) {
        return next->lata_df_nzcv_live_in_mask != 0;
    }
#endif
    return tb->lata_df_nzcv_live_out_mask != 0;
}

#ifdef CONFIG_LATA_DEBUG
static void lata_df_dump_fact(uint32_t index, DisasContext *ir1,
                              LataIR1Facts *fact, LataIR1DF *df)
{
    qemu_log("[LATA df]   IR1[%03u] pc=0x%016" PRIx64
             " insn=0x%08x type=%d"
             " use=0x%08x def=0x%08x wdef=0x%08x xuse=0x%08x"
             " vec_use=0x%08x vec_def=0x%08x"
             " live_after=0x%08x x_live_after=0x%08x"
             " vec_live_after=0x%08x"
             " nzcv(use=0x%x def=0x%x after=0x%x) helper=%d state=%d\n",
             index, (uint64_t)ir1->pc_curr, ir1->insn, ir1->insn_type,
             fact->gpr_use, fact->gpr_def, fact->gpr_wdef,
             fact->gpr_x_use, fact->vec_use, fact->vec_def,
             df->gpr_live_after, df->gpr_x_live_after, df->vec_live_after,
             fact->nzcv_use, fact->nzcv_def, df->nzcv_live_after,
             fact->helper_boundary, fact->state_boundary);
}

void lata_df_dump_tb(TranslationBlock *tb)
{
    if (!tb || (!option_lata_dump_ir1 && !option_lata_dump_tu)) {
        return;
    }

    qemu_log("[LATA df] pc=0x%016" PRIx64
             " up_use=0x%08x def=0x%08x wdef=0x%08x"
             " up_xuse=0x%08x all_use=0x%08x all_xuse=0x%08x"
             " live_in=0x%08x live_out=0x%08x"
             " x_live_in=0x%08x x_live_out=0x%08x"
             " vec(use=0x%08x def=0x%08x in=0x%08x out=0x%08x)"
             " nzcv(use=0x%x def=0x%x in=0x%x out=0x%x)"
             " helper=%d state=%d\n",
             (uint64_t)tb->pc, tb->lata_df_gpr_use, tb->lata_df_gpr_def,
             tb->lata_df_gpr_wdef, tb->lata_df_gpr_x_use,
             tb->lata_df_gpr_all_use, tb->lata_df_gpr_all_x_use,
             tb->lata_df_gpr_live_in,
             tb->lata_df_gpr_live_out, tb->lata_df_gpr_x_live_in,
             tb->lata_df_gpr_x_live_out, tb->lata_df_vec_use,
             tb->lata_df_vec_def, tb->lata_df_vec_live_in,
             tb->lata_df_vec_live_out, tb->lata_df_nzcv_use_mask,
             tb->lata_df_nzcv_def_mask, tb->lata_df_nzcv_live_in_mask,
             tb->lata_df_nzcv_live_out_mask, tb->lata_df_helper_boundary,
             tb->lata_df_state_boundary);
}

void lata_df_dump_ir1_facts(TranslationBlock *tb)
{
    DisasContext *ir1 = tb ? tb->ir1 : NULL;
    LataIR1DF *df = tb ? tb->lata_df_ir1 : NULL;

    if (!tb || !ir1 || !df || !option_lata_dump_ir1) {
        return;
    }
    for (uint32_t i = 0; i < tb->icount; i++) {
        lata_df_dump_fact(i, &ir1[i], &df[i].fact, &df[i]);
    }
}
#endif
