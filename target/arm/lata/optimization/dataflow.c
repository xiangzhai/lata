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

enum {
    LATA_VEC_GT_B = 0,
    LATA_VEC_GT_H = 1,
    LATA_VEC_GT_S = 2,
    LATA_VEC_GT_D = 3,
    LATA_VEC_HIGH_CLASSES = 4,
    LATA_VEC_HIGH_ALL = (1u << LATA_VEC_HIGH_CLASSES) - 1,
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

static uint8_t nzcv_mask_from_cond(unsigned cond);

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
    { 0xba000400, 0xffe07c10, 0, 0 }, /* RMIF def is mask-based */
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

static inline void fact_state_boundary(LataIR1Facts *fact)
{
    fact->state_boundary = true;
}

static inline void fact_helper_boundary(LataIR1Facts *fact)
{
    fact->helper_boundary = true;
    fact->state_boundary = true;
}

static inline void fact_exception_boundary(LataIR1Facts *fact)
{
    fact->helper_boundary = true;
}

static inline bool df_ldst_iss_sf(int size, bool sign, bool ext)
{
    return sign ? !ext : size == 3;
}

static inline bool df_load_high_zero(int size, bool sign, bool ext)
{
    return !df_ldst_iss_sf(size, sign, ext);
}

static inline bool df_pair_load_high_zero(arg_ldstpair *a)
{
    return a->sz != 3 && !a->sign;
}

static inline bool df_ldst_imm_wback_alias(arg_ldst_imm *a)
{
    return a->w && a->rt == a->rn && a->rn != 31;
}

static inline bool df_ldstpair_wback_alias(arg_ldstpair *a)
{
    return a->w && (a->rt == a->rn || a->rt2 == a->rn) && a->rn != 31;
}

static inline void fact_vec_use(LataIR1Facts *fact, unsigned reg)
{
    if (reg < 32) {
        fact->vec_use |= 1u << reg;
        for (unsigned i = 0; i < LATA_VEC_HIGH_CLASSES; i++) {
            fact->vec_high_use[i] |= 1u << reg;
        }
    }
}

static inline void fact_vec_def(LataIR1Facts *fact, unsigned reg)
{
    if (reg < 32) {
        fact->vec_def |= 1u << reg;
        for (unsigned i = 0; i < LATA_VEC_HIGH_CLASSES; i++) {
            fact->vec_high_def[i] |= 1u << reg;
        }
    }
}

static inline unsigned vec_high_use_mask_for_low_size(unsigned size)
{
    switch (size) {
    case 0: /* B reads only byte 0. */
        return 0;
    case 1: /* H reads bytes [1:0]. */
        return 1u << LATA_VEC_GT_B;
    case 2: /* S reads bytes [3:0]. */
        return (1u << LATA_VEC_GT_B) | (1u << LATA_VEC_GT_H);
    case 3: /* D reads bytes [7:0]. */
        return (1u << LATA_VEC_GT_B) | (1u << LATA_VEC_GT_H) |
               (1u << LATA_VEC_GT_S);
    default:
        return LATA_VEC_HIGH_ALL;
    }
}

static inline void fact_vec_low_use(LataIR1Facts *fact, unsigned reg,
                                    unsigned size)
{
    uint32_t bit = reg < 32 ? (1u << reg) : 0;
    unsigned mask = vec_high_use_mask_for_low_size(size);

    if (!bit) {
        return;
    }
    fact->vec_use |= bit;
    for (unsigned i = 0; i < LATA_VEC_HIGH_CLASSES; i++) {
        if (mask & (1u << i)) {
            fact->vec_high_use[i] |= bit;
        }
    }
}

static inline void fact_vec_low_def(LataIR1Facts *fact, unsigned reg)
{
    fact_vec_def(fact, reg);
}

static inline unsigned fp_type_to_vec_size(unsigned type)
{
    return type == 3 ? 1 : type == 0 ? 2 : 3;
}

static inline void fact_vec_store_use(LataIR1Facts *fact, unsigned reg,
                                      unsigned size)
{
    if (size >= 4) {
        fact_vec_use(fact, reg);
    } else {
        fact_vec_low_use(fact, reg, size);
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
    fact_use(fact, a->rm, extract32(a->opt, 0, 2) == 3);
    if (!extract32(a->opt, 1, 1)) {
        fact_helper_boundary(fact);
    }
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

static inline bool df_stlr_unallocated(arg_stlr *a)
{
    return !a->lasr;
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
    bool high_zero = !a->sf;

    if (ir1->insn_type == AARCH64_A64_MOVK) {
        fact_use(fact, a->rd, a->sf);
    }
    if (ir1->insn_type == AARCH64_A64_MOVZ && a->sf && a->hw < 2) {
        high_zero = true;
    }
    fact_def(fact, a->rd, high_zero);
}

static bool sys_args_are_nzcv(const arg_SYS *a)
{
    return a->op0 == 3 && a->op1 == 3 && a->crn == 4 &&
           a->crm == 2 && a->op2 == 0;
}

static void fact_sys(LataIR1Facts *fact, DisasContext *ir1)
{
    arg_SYS *a = &ir1->arg.f_decode_insn3218;
    bool is_nzcv = sys_args_are_nzcv(a);

    if (a->l) {
        fact_def(fact, a->rt, is_nzcv);
    } else {
        fact_use(fact, a->rt, !is_nzcv);
    }
    if (!is_nzcv) {
        fact_helper_boundary(fact);
    }
}

static void fact_rmif(LataIR1Facts *fact, DisasContext *ir1)
{
    fact_use(fact, extract32(ir1->insn, 5, 5), true);
}

static void fact_fcadd(LataIR1Facts *fact, DisasContext *ir1)
{
    uint32_t insn = ir1->insn;

    fact_vec_def(fact, extract32(insn, 0, 5));
    fact_vec_use(fact, extract32(insn, 5, 5));
    fact_vec_use(fact, extract32(insn, 16, 5));
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
        bool invalid;

        if (op2 & 8) {
            if (op2 & 1) {
                invalid = extract32(insn, 10, 3) > 4 ||
                          extract32(insn, 22, 2) != 0;
            } else {
                invalid = extract32(insn, 22, 2) == 3 ||
                          (!sf && extract32(insn, 10, 6) > 31);
            }
        } else {
            invalid = !sf && extract32(insn, 15, 1);
        }
        if (invalid) {
            fact_helper_boundary(fact);
            return;
        }
        fact_use(fact, rn, sf);
        fact_use(fact, rm, sf);
        fact_def(fact, rd, !sf);
        return;
    }

    if (op2 == 0) {
        if (op3 == 0) {
            fact_use(fact, rn, sf);
            fact_use(fact, rm, sf);
            fact_def(fact, rd, !sf);
        } else if (op3 == 2 || op3 == 0x12 ||
                   op3 == 0x22 || op3 == 0x32) {
            fact_use(fact, rn, false);
        } else {
            fact_helper_boundary(fact);
        }
        return;
    }

    if (op2 == 2) {
        if (!extract32(insn, 29, 1) ||
            extract32(insn, 10, 1) || extract32(insn, 4, 1)) {
            fact_helper_boundary(fact);
            return;
        }
        fact_use(fact, rn, sf);
        if (!extract32(insn, 11, 1)) {
            fact_use(fact, rm, sf);
        }
        return;
    }

    if (op2 == 4) {
        if (extract32(insn, 29, 1) || extract32(insn, 11, 1)) {
            fact_helper_boundary(fact);
            return;
        }
        fact_use(fact, rn, sf);
        fact_use(fact, rm, sf);
        fact_def(fact, rd, !sf);
        return;
    }

    if (op2 == 6) {
        if (extract32(insn, 30, 1)) {
            unsigned opcode = extract32(insn, 10, 6);

            if (extract32(insn, 29, 1) || extract32(insn, 16, 5) != 0 ||
                opcode > 5 || (opcode == 3 && !sf)) {
                fact_helper_boundary(fact);
                return;
            }
            fact_use(fact, rn, sf);
            fact_def(fact, rd, !sf);
        } else {
            unsigned opcode = extract32(insn, 10, 6);

            if (!(opcode == 2 || opcode == 3 ||
                  (opcode >= 8 && opcode <= 11) ||
                  (opcode >= 16 && opcode <= 23))) {
                fact_helper_boundary(fact);
                return;
            }
            fact_use(fact, rn, sf);
            if (opcode >= 16 && opcode <= 23) {
                bool crc_x = extract32(insn, 31, 1);
                unsigned size = opcode & 3;

                fact_use(fact, rm, crc_x && size == 3);
                fact_def(fact, rd, true);
            } else {
                fact_use(fact, rm, sf);
                fact_def(fact, rd, !sf);
            }
        }
        return;
    }

    if (op2 >= 8) {
        unsigned ra = extract32(insn, 10, 5);
        unsigned op_id = (extract32(insn, 29, 3) << 4) |
                         (extract32(insn, 21, 3) << 1) |
                         extract32(insn, 15, 1);
        bool long_word_mul = op_id == 0x42 || op_id == 0x43 ||
                             op_id == 0x4a || op_id == 0x4b;
        bool high_mul = op_id == 0x44 || op_id == 0x4c;
        bool madd = op_id == 0x0 || op_id == 0x1 ||
                    op_id == 0x40 || op_id == 0x41;

        if (!madd && !long_word_mul && !high_mul) {
            fact_helper_boundary(fact);
            return;
        }

        if (high_mul) {
            fact_use(fact, rn, true);
            fact_use(fact, rm, true);
        } else if (long_word_mul) {
            fact_use(fact, rn, false);
            fact_use(fact, rm, false);
            if (ra != 31) {
                fact_use(fact, ra, true);
            }
        } else {
            fact_use(fact, rn, sf);
            fact_use(fact, rm, sf);
            if (ra != 31) {
                fact_use(fact, ra, sf);
            }
        }
        fact_def(fact, rd, !sf && !long_word_mul && !high_mul);
    }
}

static bool simd_fp_is_scalar_fp(uint32_t insn)
{
    return extract32(insn, 28, 1) && !extract32(insn, 30, 1);
}

static bool scalar_fp_type_is_32_64(unsigned type)
{
    return type == 0 || type == 1;
}

static bool scalar_fp_type_is_16_32_64(DisasContext *ir1, unsigned type)
{
    return scalar_fp_type_is_32_64(type) ||
           (type == 3 && dc_isar_feature(aa64_fp16, ir1));
}

static bool scalar_fp_3src_supported(uint32_t insn)
{
    return !extract32(insn, 29, 3) &&
           scalar_fp_type_is_32_64(extract32(insn, 22, 2));
}

static bool scalar_fp_compare_supported(uint32_t insn)
{
    return !extract32(insn, 29, 3) &&
           !extract32(insn, 14, 2) &&
           !extract32(insn, 0, 3) &&
           scalar_fp_type_is_32_64(extract32(insn, 22, 2));
}

static bool scalar_fp_ccomp_supported(uint32_t insn)
{
    return !extract32(insn, 29, 3) &&
           scalar_fp_type_is_32_64(extract32(insn, 22, 2));
}

static bool scalar_fp_csel_supported(uint32_t insn)
{
    return !extract32(insn, 29, 3) &&
           scalar_fp_type_is_32_64(extract32(insn, 22, 2));
}

static bool scalar_fp_2src_supported(uint32_t insn)
{
    return !extract32(insn, 29, 3) &&
           scalar_fp_type_is_32_64(extract32(insn, 22, 2)) &&
           extract32(insn, 12, 4) <= 8;
}

static bool scalar_fp_imm_supported(DisasContext *ir1, uint32_t insn)
{
    return !extract32(insn, 29, 3) &&
           !extract32(insn, 5, 5) &&
           scalar_fp_type_is_16_32_64(ir1, extract32(insn, 22, 2));
}

static bool scalar_fp_1src_supported(DisasContext *ir1, uint32_t insn)
{
    unsigned type = extract32(insn, 22, 2);
    unsigned opcode = extract32(insn, 15, 6);

    if (extract32(insn, 29, 3)) {
        return false;
    }

    switch (opcode) {
    case 0x4:
    case 0x5:
    case 0x7:
    {
        unsigned dtype = opcode & 3;

        return type != 2 && dtype != type &&
               ((type != 3 && dtype != 3) ||
                dc_isar_feature(aa64_fp16, ir1));
    }
    case 0x0 ... 0x3:
    case 0x8 ... 0xc:
    case 0xe ... 0xf:
        return scalar_fp_type_is_16_32_64(ir1, type);
    default:
        return false;
    }
}

static bool fact_fp_int_conv(LataIR1Facts *fact, DisasContext *ir1)
{
    uint32_t insn = ir1->insn;
    bool sf = extract32(insn, 31, 1);
    bool sbit = extract32(insn, 29, 1);
    unsigned type = extract32(insn, 22, 2);
    unsigned rmode = extract32(insn, 19, 2);
    unsigned opcode = extract32(insn, 16, 3);
    unsigned rn = extract32(insn, 5, 5);
    unsigned rd = extract32(insn, 0, 5);

    if (sbit || !scalar_fp_type_is_16_32_64(ir1, type)) {
        fact_exception_boundary(fact);
        return true;
    }

    switch (opcode) {
    case 2: /* SCVTF */
    case 3: /* UCVTF */
        if (rmode != 0) {
            fact_exception_boundary(fact);
            return true;
        }
        fact_use(fact, rn, sf);
        fact_vec_low_def(fact, rd);
        return true;
    case 0: /* FCVT[NPMZ]S */
    case 1: /* FCVT[NPMZ]U */
    case 4: /* FCVTAS */
    case 5: /* FCVTAU */
    {
        bool is_signed = !(opcode & 1);
        bool helper_possible;

        if ((opcode & 4) && rmode != 0) {
            fact_exception_boundary(fact);
            return true;
        }
        fact_vec_low_use(fact, rn, fp_type_to_vec_size(type));
        fact_def(fact, rd, !sf);
        if (is_signed) {
            helper_possible = (opcode & 4) && type != 0;
        } else {
            helper_possible = type == 3 ||
                              !((!sf && type == 0) ||
                                (rmode == 3 && type <= 1));
        }
        if (helper_possible) {
            fact_helper_boundary(fact);
        }
        return true;
    }
    default:
        break;
    }

    switch ((sf << 7) | (type << 5) | (rmode << 3) | opcode) {
    case 0b01100110: /* FMOV half -> 32-bit int */
    case 0b11100110: /* FMOV half -> 64-bit int */
        fact_vec_low_use(fact, rn, 1);
        fact_def(fact, rd, true);
        return true;
    case 0b00000110: /* FMOV 32-bit */
        fact_vec_low_use(fact, rn, 2);
        fact_def(fact, rd, true);
        return true;
    case 0b10100110: /* FMOV 64-bit */
        fact_vec_low_use(fact, rn, 3);
        fact_def(fact, rd, false);
        return true;
    case 0b11001110: /* FMOV top half of 128-bit */
        fact_vec_use(fact, rn);
        fact_def(fact, rd, false);
        return true;
    case 0b01100111: /* FMOV 32-bit int -> half */
    case 0b00000111: /* FMOV 32-bit int -> float */
        fact_use(fact, rn, false);
        fact_vec_low_def(fact, rd);
        return true;
    case 0b11100111: /* FMOV 64-bit int -> half */
        fact_use(fact, rn, false);
        fact_vec_low_def(fact, rd);
        return true;
    case 0b10100111: /* FMOV 64-bit int -> double */
        fact_use(fact, rn, true);
        fact_vec_low_def(fact, rd);
        return true;
    case 0b11001111: /* FMOV 64-bit int -> top half of 128-bit */
        fact_use(fact, rn, true);
        fact_vec_use(fact, rd);
        fact_vec_def(fact, rd);
        return true;
    case 0b00111110: /* FJCVTZS */
        fact_vec_low_use(fact, rn, 3);
        fact_def(fact, rd, true);
        fact->nzcv_def |= LATA_NZCV_ALL;
        fact_exception_boundary(fact);
        return true;
    default:
        fact_exception_boundary(fact);
        return true;
    }
}

static bool fact_fp_int_conv_encoding(uint32_t insn)
{
    return (insn & 0x5f20fc00) == 0x1e200000;
}

static bool fact_fp_fixed_conv(LataIR1Facts *fact, DisasContext *ir1)
{
    uint32_t insn = ir1->insn;
    bool sf = extract32(insn, 31, 1);
    bool sbit = extract32(insn, 29, 1);
    unsigned type = extract32(insn, 22, 2);
    unsigned rmode = extract32(insn, 19, 2);
    unsigned opcode = extract32(insn, 16, 3);
    unsigned scale = extract32(insn, 10, 6);
    unsigned rn = extract32(insn, 5, 5);
    unsigned rd = extract32(insn, 0, 5);

    if (sbit || (!sf && scale < 32) ||
        !scalar_fp_type_is_16_32_64(ir1, type)) {
        fact_exception_boundary(fact);
        return true;
    }

    switch ((rmode << 3) | opcode) {
    case 0x2: /* SCVTF */
    case 0x3: /* UCVTF */
        fact_use(fact, rn, sf);
        fact_vec_low_def(fact, rd);
        return true;
    case 0x18: /* FCVTZS */
    case 0x19: /* FCVTZU */
        fact_vec_low_use(fact, rn, fp_type_to_vec_size(type));
        fact_def(fact, rd, !sf);
        if (type == 3 || opcode == 1 || scale != 64) {
            fact_helper_boundary(fact);
        }
        return true;
    default:
        fact_exception_boundary(fact);
        return true;
    }
}

static void fact_scalar_fp(LataIR1Facts *fact, DisasContext *ir1)
{
    uint32_t insn = ir1->insn;
    unsigned rd = extract32(insn, 0, 5);
    unsigned rn = extract32(insn, 5, 5);
    unsigned ra = extract32(insn, 10, 5);
    unsigned rm = extract32(insn, 16, 5);

    if (extract32(insn, 24, 1)) {
        unsigned type = extract32(insn, 22, 2);
        unsigned size = fp_type_to_vec_size(type);

        if (!scalar_fp_3src_supported(insn)) {
            fact_helper_boundary(fact);
            return;
        }
        fact_vec_low_def(fact, rd);
        fact_vec_low_use(fact, rn, size);
        fact_vec_low_use(fact, rm, size);
        fact_vec_low_use(fact, ra, size);
        return;
    }

    if (!extract32(insn, 21, 1)) {
        fact_fp_fixed_conv(fact, ir1);
        return;
    }

    if (fact_fp_int_conv_encoding(insn)) {
        fact_fp_int_conv(fact, ir1);
        return;
    }

    switch (extract32(insn, 10, 2)) {
    case 1: /* Floating point conditional compare */
    {
        unsigned type = extract32(insn, 22, 2);
        unsigned size = fp_type_to_vec_size(type);

        if (!scalar_fp_ccomp_supported(insn)) {
            fact_helper_boundary(fact);
            break;
        }
        fact_vec_low_use(fact, rn, size);
        fact_vec_low_use(fact, rm, size);
        fact->nzcv_use |= nzcv_mask_from_cond(extract32(insn, 12, 4));
        fact->nzcv_def |= LATA_NZCV_ALL;
        break;
    }
    case 2: /* Floating point data-processing (2 source) */
    {
        unsigned type = extract32(insn, 22, 2);
        unsigned size = fp_type_to_vec_size(type);

        if (!scalar_fp_2src_supported(insn)) {
            fact_helper_boundary(fact);
            break;
        }
        fact_vec_low_def(fact, rd);
        fact_vec_low_use(fact, rn, size);
        fact_vec_low_use(fact, rm, size);
        break;
    }
    case 3: /* Floating point conditional select */
    {
        unsigned type = extract32(insn, 22, 2);
        unsigned size = fp_type_to_vec_size(type);

        if (!scalar_fp_csel_supported(insn)) {
            fact_helper_boundary(fact);
            break;
        }
        fact_vec_low_def(fact, rd);
        fact_vec_low_use(fact, rn, size);
        fact_vec_low_use(fact, rm, size);
        fact->nzcv_use |= nzcv_mask_from_cond(extract32(insn, 12, 4));
        break;
    }
    case 0:
        switch (ctz32(extract32(insn, 12, 4))) {
        case 0: /* Floating point immediate */
            if (!scalar_fp_imm_supported(ir1, insn)) {
                fact_helper_boundary(fact);
                break;
            }
            fact_vec_low_def(fact, rd);
            break;
        case 1: { /* Floating point compare */
            bool cmp_with_zero = extract32(insn, 3, 2) & 1;
            unsigned type = extract32(insn, 22, 2);
            unsigned size = fp_type_to_vec_size(type);

            if (!scalar_fp_compare_supported(insn)) {
                fact_helper_boundary(fact);
                break;
            }
            fact_vec_low_use(fact, rn, size);
            if (!cmp_with_zero) {
                fact_vec_low_use(fact, rm, size);
            }
            fact->nzcv_def |= LATA_NZCV_ALL;
            break;
        }
        case 2: /* Floating point data-processing (1 source) */
        {
            unsigned type = extract32(insn, 22, 2);
            unsigned src_size = fp_type_to_vec_size(type);

            if (!scalar_fp_1src_supported(ir1, insn)) {
                fact_helper_boundary(fact);
                break;
            }
            fact_vec_low_def(fact, rd);
            fact_vec_low_use(fact, rn, src_size);
            break;
        }
        case 3:
            fact_helper_boundary(fact);
            break;
        default:
            fact_fp_int_conv(fact, ir1);
            break;
        }
        break;
    }
}

static bool fact_simd_copy(LataIR1Facts *fact, uint32_t insn)
{
    unsigned rd = extract32(insn, 0, 5);
    unsigned rn = extract32(insn, 5, 5);
    unsigned imm4 = extract32(insn, 11, 4);
    unsigned imm5 = extract32(insn, 16, 5);
    bool op = extract32(insn, 29, 1);
    bool is_q = extract32(insn, 30, 1);
    unsigned size = imm5 ? ctz32(imm5) : 4;

    if ((insn & 0x9fe08400) != 0x0e000400) {
        return false;
    }

    if (op) {
        if (!is_q || size > 3) {
            fact_helper_boundary(fact);
            return true;
        }
        fact_vec_use(fact, rd);
        fact_vec_use(fact, rn);
        fact_vec_def(fact, rd);
        return true;
    }

    switch (imm4) {
    case 0: /* DUP element */
        if (size > 3 || (size == 3 && !is_q)) {
            fact_helper_boundary(fact);
            break;
        }
        fact_vec_use(fact, rn);
        fact_vec_def(fact, rd);
        break;
    case 1: /* DUP general */
        if (size > 3 || (size == 3 && !is_q)) {
            fact_helper_boundary(fact);
            break;
        }
        fact_use(fact, rn, size == 3);
        fact_vec_def(fact, rd);
        break;
    case 3: /* INS general */
        if (!is_q || size > 3) {
            fact_helper_boundary(fact);
            break;
        }
        fact_vec_use(fact, rd);
        fact_use(fact, rn, size == 3);
        fact_vec_def(fact, rd);
        break;
    case 5: /* SMOV */
    case 7: { /* UMOV */
        bool is_signed = imm4 == 5;
        bool high_zero = is_signed ? !is_q : !(is_q && size == 3);
        bool invalid = is_signed ?
                       size > 2 || (size == 2 && !is_q) :
                       size > 3 || (size < 3 && is_q) ||
                       (size == 3 && !is_q);

        if (invalid) {
            fact_helper_boundary(fact);
            break;
        }
        fact_vec_use(fact, rn);
        fact_def(fact, rd, high_zero);
        break;
    }
    default:
        fact_helper_boundary(fact);
        break;
    }
    return true;
}

static bool fact_simd_scalar_copy(LataIR1Facts *fact, uint32_t insn)
{
    unsigned rd = extract32(insn, 0, 5);
    unsigned rn = extract32(insn, 5, 5);
    unsigned imm5 = extract32(insn, 16, 5);
    unsigned size = imm5 ? ctz32(imm5) : 4;

    if ((insn & 0xdfe08400) != 0x5e000400) {
        return false;
    }
    if (extract32(insn, 29, 1) || extract32(insn, 11, 4) != 0 ||
        size > 3) {
        fact_helper_boundary(fact);
        return true;
    }
    fact_vec_use(fact, rn);
    fact_vec_def(fact, rd);
    return true;
}

static bool fact_simd_crypto(LataIR1Facts *fact, uint32_t insn)
{
    unsigned top = insn >> 24;
    unsigned rd = extract32(insn, 0, 5);
    unsigned rn = extract32(insn, 5, 5);
    unsigned rm = extract32(insn, 16, 5);
    unsigned ra = extract32(insn, 10, 5);

    if (top == 0x4e) {
        if ((insn & 0xff3e0c00) != 0x4e280800) {
            return false;
        }
        fact_vec_use(fact, rd);
        fact_vec_use(fact, rn);
        fact_vec_def(fact, rd);
        fact_exception_boundary(fact);
        return true;
    }

    if (top == 0x5e) {
        if ((insn & 0xff208c00) == 0x5e000000) {
            fact_vec_use(fact, rd);
            fact_vec_use(fact, rn);
            fact_vec_use(fact, rm);
            fact_vec_def(fact, rd);
            fact_helper_boundary(fact);
            return true;
        }
        if ((insn & 0xff3e0c00) == 0x5e280800) {
            fact_vec_use(fact, rd);
            fact_vec_use(fact, rn);
            fact_vec_def(fact, rd);
            fact_helper_boundary(fact);
            return true;
        }
        return false;
    }

    if (top == 0xce) {
        fact_vec_use(fact, rn);
        fact_vec_use(fact, rm);
        if ((insn & 0xff808000) == 0xce000000) {
            fact_vec_use(fact, ra);
        }
        fact_vec_def(fact, rd);
        if ((insn & 0xff808000) != 0xce000000 &&
            (insn & 0xffe00000) != 0xce800000) {
            fact_helper_boundary(fact);
        }
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

    if (simd_fp_is_scalar_fp(insn)) {
        fact_scalar_fp(fact, ir1);
        return;
    }
    if (fact_simd_crypto(fact, insn) ||
        fact_simd_copy(fact, insn) ||
        fact_simd_scalar_copy(fact, insn)) {
        return;
    }

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
    if ((insn & 0xbf208c00) == 0x0e000000) {
        fact_helper_boundary(fact);
    }
}

static void fact_crypto(LataIR1Facts *fact, DisasContext *ir1)
{
    if (!fact_simd_crypto(fact, ir1->insn)) {
        fact_helper_boundary(fact);
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
    { AARCH64_A64_CRYPTO, fact_crypto },
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

    return ir1->insn_type == AARCH64_A64_SYS && sys_args_are_nzcv(a);
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
    if ((insn & 0xfffffc00) == 0x1e7e0000) {
        fact->nzcv_def |= LATA_NZCV_ALL;
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
    bool exclusive_state;
    bool table_handled = false;

    for (const LataGPRRule *rule = gpr_rules; rule->fn; rule++) {
        if (rule->type == ir1->insn_type) {
            rule->fn(fact, ir1);
            table_handled = true;
            break;
        }
    }

    switch (ir1->insn_type) {
    case AARCH64_A64_NULL:
        fact_helper_boundary(fact);
        return;
    case AARCH64_A64_NOP:
    case AARCH64_A64_ESB:
    case AARCH64_A64_XPACLRI:
    case AARCH64_A64_PACIA1716:
    case AARCH64_A64_PACIB1716:
    case AARCH64_A64_AUTIA1716:
    case AARCH64_A64_AUTIB1716:
    case AARCH64_A64_PACIAZ:
    case AARCH64_A64_PACIASP:
    case AARCH64_A64_PACIBZ:
    case AARCH64_A64_PACIBSP:
    case AARCH64_A64_AUTIAZ:
    case AARCH64_A64_AUTIASP:
    case AARCH64_A64_AUTIBZ:
    case AARCH64_A64_AUTIBSP:
    case AARCH64_A64_CFINV:
    case AARCH64_A64_XAFLAG:
    case AARCH64_A64_AXFLAG:
        break;
    case AARCH64_A64_RMIF:
        fact_rmif(fact, ir1);
        break;
    case AARCH64_A64_FCADD:
        fact_fcadd(fact, ir1);
        break;
    case AARCH64_A64_B:
    case AARCH64_A64_B_cond:
    case AARCH64_A64_SVC:
    case AARCH64_A64_BRK:
        break;
    case AARCH64_A64_CBZ:
        fact_use(fact, extract32(insn, 0, 5), sf);
        break;
    case AARCH64_A64_TBZ:
        fact_use(fact, extract32(insn, 0, 5),
                 ir1->arg.f_tbz.bitpos >= 32);
        break;
    case AARCH64_A64_BR:
    case AARCH64_A64_RET:
        fact_use(fact, extract32(insn, 5, 5), true);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_BLR:
        fact_use(fact, extract32(insn, 5, 5), true);
        fact_def(fact, 30, false);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_BL:
        fact_def(fact, 30, false);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_ADR:
    case AARCH64_A64_ADRP:
        fact_def(fact, extract32(insn, 0, 5), false);
        break;
    case AARCH64_A64_LD_lit:
        if (ir1->arg.f_ldlit.sz != 3 || ir1->arg.f_ldlit.sign) {
            fact_helper_boundary(fact);
            break;
        }
        fact_def(fact, ir1->arg.f_ldlit.rt,
                 ir1->arg.f_ldlit.sz != 3 && !ir1->arg.f_ldlit.sign);
        break;
    case AARCH64_A64_LDP:
        if (df_ldstpair_wback_alias(&ir1->arg.f_ldstpair)) {
            fact_helper_boundary(fact);
            break;
        }
        fact_mem_pair_addr(fact, &ir1->arg.f_ldstpair);
        fact_def(fact, ir1->arg.f_ldstpair.rt,
                 df_pair_load_high_zero(&ir1->arg.f_ldstpair));
        fact_def(fact, ir1->arg.f_ldstpair.rt2,
                 df_pair_load_high_zero(&ir1->arg.f_ldstpair));
        break;
    case AARCH64_A64_LDR:
        fact_mem_reg_addr(fact, &ir1->arg.f_ldst);
        fact_def(fact, ir1->arg.f_ldst.rt,
                 df_load_high_zero(ir1->arg.f_ldst.sz,
                                   ir1->arg.f_ldst.sign,
                                   ir1->arg.f_ldst.ext));
        break;
    case AARCH64_A64_LDR_i:
        if (df_ldst_imm_wback_alias(&ir1->arg.f_ldst_imm)) {
            fact_helper_boundary(fact);
            break;
        }
        fact_mem_imm_addr(fact, &ir1->arg.f_ldst_imm);
        fact_def(fact, ir1->arg.f_ldst_imm.rt,
                 df_load_high_zero(ir1->arg.f_ldst_imm.sz,
                                   ir1->arg.f_ldst_imm.sign,
                                   ir1->arg.f_ldst_imm.ext));
        break;
    case AARCH64_A64_LDAR:
        fact_mem_stlr_addr(fact, &ir1->arg.f_stlr);
        fact_def(fact, ir1->arg.f_stlr.rt, ir1->arg.f_stlr.sz != 3);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_LDAPR:
        fact_ldapr_addr(fact, &ir1->arg.f_decode_insn3227);
        fact_def(fact, ir1->arg.f_decode_insn3227.rt,
                 ir1->arg.f_decode_insn3227.sz != 3);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_LDAPR_i:
        fact_mem_ldapr_stlr_addr(fact, &ir1->arg.f_ldapr_stlr_i);
        fact_def(fact, ir1->arg.f_ldapr_stlr_i.rt,
                 df_load_high_zero(ir1->arg.f_ldapr_stlr_i.sz,
                                   ir1->arg.f_ldapr_stlr_i.sign,
                                   ir1->arg.f_ldapr_stlr_i.ext));
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_LDXR:
        fact_mem_stxr_addr(fact, &ir1->arg.f_stxr);
        fact_def(fact, ir1->arg.f_stxr.rt, ir1->arg.f_stxr.sz != 3);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_LDXP:
        fact_mem_stxr_addr(fact, &ir1->arg.f_stxr);
        fact_def(fact, ir1->arg.f_stxr.rt, ir1->arg.f_stxr.sz == 2);
        fact_def(fact, ir1->arg.f_stxr.rt2, ir1->arg.f_stxr.sz == 2);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_STR:
        fact_mem_reg_addr(fact, &ir1->arg.f_ldst);
        fact_use(fact, ir1->arg.f_ldst.rt, ir1->arg.f_ldst.sz == 3);
        break;
    case AARCH64_A64_STP:
        if (df_ldstpair_wback_alias(&ir1->arg.f_ldstpair)) {
            fact_helper_boundary(fact);
            break;
        }
        fact_mem_pair_addr(fact, &ir1->arg.f_ldstpair);
        fact_use(fact, ir1->arg.f_ldstpair.rt,
                 ir1->arg.f_ldstpair.sz == 3);
        fact_use(fact, ir1->arg.f_ldstpair.rt2,
                 ir1->arg.f_ldstpair.sz == 3);
        break;
    case AARCH64_A64_STR_i:
        if (df_ldst_imm_wback_alias(&ir1->arg.f_ldst_imm)) {
            fact_helper_boundary(fact);
            break;
        }
        fact_mem_imm_addr(fact, &ir1->arg.f_ldst_imm);
        fact_use(fact, ir1->arg.f_ldst_imm.rt,
                 ir1->arg.f_ldst_imm.sz == 3);
        break;
    case AARCH64_A64_STLR:
        if (df_stlr_unallocated(&ir1->arg.f_stlr)) {
            fact_helper_boundary(fact);
            break;
        }
        fact_mem_stlr_addr(fact, &ir1->arg.f_stlr);
        fact_use(fact, ir1->arg.f_stlr.rt, ir1->arg.f_stlr.sz == 3);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_STLR_i:
        fact_mem_ldapr_stlr_addr(fact, &ir1->arg.f_ldapr_stlr_i);
        fact_use(fact, ir1->arg.f_ldapr_stlr_i.rt,
                 ir1->arg.f_ldapr_stlr_i.sz == 3);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_STXR:
        fact_mem_stxr_addr(fact, &ir1->arg.f_stxr);
        fact_use(fact, ir1->arg.f_stxr.rt, ir1->arg.f_stxr.sz == 3);
        fact_def(fact, ir1->arg.f_stxr.rs, true);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_STXP:
        fact_mem_stxr_addr(fact, &ir1->arg.f_stxr);
        fact_use(fact, ir1->arg.f_stxr.rt, ir1->arg.f_stxr.sz == 3);
        fact_use(fact, ir1->arg.f_stxr.rt2, ir1->arg.f_stxr.sz == 3);
        fact_def(fact, ir1->arg.f_stxr.rs, true);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_LDR_v:
        fact_mem_reg_addr(fact, &ir1->arg.f_ldst);
        fact_vec_low_def(fact, ir1->arg.f_ldst.rt);
        break;
    case AARCH64_A64_LDR_v_i:
        fact_mem_imm_addr(fact, &ir1->arg.f_ldst_imm);
        fact_vec_low_def(fact, ir1->arg.f_ldst_imm.rt);
        break;
    case AARCH64_A64_LDP_v:
        fact_mem_pair_addr(fact, &ir1->arg.f_ldstpair);
        fact_vec_low_def(fact, ir1->arg.f_ldstpair.rt);
        fact_vec_low_def(fact, ir1->arg.f_ldstpair.rt2);
        break;
    case AARCH64_A64_LD_lit_v:
        fact_helper_boundary(fact);
        break;
    case AARCH64_A64_LD_mult:
        fact_mem_mult_addr(fact, &ir1->arg.f_ldst_mult);
        fact_vec_range_def(fact, ir1->arg.f_ldst_mult.rt,
                           ir1->arg.f_ldst_mult.rpt *
                           ir1->arg.f_ldst_mult.selem);
        break;
    case AARCH64_A64_LD_single:
        fact_mem_single_addr(fact, &ir1->arg.f_ldst_single);
        fact_vec_range_def(fact, ir1->arg.f_ldst_single.rt,
                           ir1->arg.f_ldst_single.selem);
        break;
    case AARCH64_A64_LD_single_repl:
        fact_use_sp_addr(fact, ir1->arg.f_decode_insn3232.rn);
        if (ir1->arg.f_decode_insn3232.p) {
            fact_use(fact, ir1->arg.f_decode_insn3232.rm, true);
            fact_def(fact, ir1->arg.f_decode_insn3232.rn, false);
        }
        fact_vec_range_def(fact, ir1->arg.f_decode_insn3232.rt,
                           ir1->arg.f_decode_insn3232.selem);
        break;
    case AARCH64_A64_STR_v:
        fact_mem_reg_addr(fact, &ir1->arg.f_ldst);
        fact_vec_store_use(fact, ir1->arg.f_ldst.rt, ir1->arg.f_ldst.sz);
        break;
    case AARCH64_A64_STR_v_i:
        fact_mem_imm_addr(fact, &ir1->arg.f_ldst_imm);
        fact_vec_store_use(fact, ir1->arg.f_ldst_imm.rt,
                           ir1->arg.f_ldst_imm.sz);
        break;
    case AARCH64_A64_STP_v:
        fact_mem_pair_addr(fact, &ir1->arg.f_ldstpair);
        fact_vec_store_use(fact, ir1->arg.f_ldstpair.rt,
                           ir1->arg.f_ldstpair.sz);
        fact_vec_store_use(fact, ir1->arg.f_ldstpair.rt2,
                           ir1->arg.f_ldstpair.sz);
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
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_CAS:
        fact_cas_addr(fact, &ir1->arg.f_decode_insn3221);
        fact_use(fact, ir1->arg.f_decode_insn3221.rs,
                 ir1->arg.f_decode_insn3221.sz == 3);
        fact_use(fact, ir1->arg.f_decode_insn3221.rt,
                 ir1->arg.f_decode_insn3221.sz == 3);
        fact_def(fact, ir1->arg.f_decode_insn3221.rs,
                 ir1->arg.f_decode_insn3221.sz != 3);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_CASP:
        if ((ir1->arg.f_decode_insn3221.rs & 1) ||
            (ir1->arg.f_decode_insn3221.rt & 1) ||
            ir1->arg.f_decode_insn3221.sz < 2) {
            fact_helper_boundary(fact);
            break;
        }
        fact_cas_addr(fact, &ir1->arg.f_decode_insn3221);
        exclusive_state = ir1->arg.f_decode_insn3221.sz == 3;
        fact_use(fact, ir1->arg.f_decode_insn3221.rs, exclusive_state);
        fact_use(fact, ir1->arg.f_decode_insn3221.rs + 1, exclusive_state);
        fact_use(fact, ir1->arg.f_decode_insn3221.rt, exclusive_state);
        fact_use(fact, ir1->arg.f_decode_insn3221.rt + 1, exclusive_state);
        fact_def(fact, ir1->arg.f_decode_insn3221.rs, !exclusive_state);
        fact_def(fact, ir1->arg.f_decode_insn3221.rs + 1, !exclusive_state);
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_CLREX:
    case AARCH64_A64_DSB_DMB:
    case AARCH64_A64_ISB:
    case AARCH64_A64_SB:
    case AARCH64_A64_WFI:
    case AARCH64_A64_WFE:
    case AARCH64_A64_YIELD:
        fact_state_boundary(fact);
        break;
    case AARCH64_A64_ADDG_i:
    case AARCH64_A64_SUBG_i:
    case AARCH64_A64_BRA:
    case AARCH64_A64_BRAZ:
    case AARCH64_A64_BLRA:
    case AARCH64_A64_BLRAZ:
    case AARCH64_A64_RETA:
    case AARCH64_A64_ERET:
    case AARCH64_A64_ERETA:
    case AARCH64_A64_HVC:
    case AARCH64_A64_SMC:
    case AARCH64_A64_HLT:
    case AARCH64_A64_LDRA:
    case AARCH64_A64_STGP:
    case AARCH64_A64_LDG:
    case AARCH64_A64_LDGM:
    case AARCH64_A64_STG:
    case AARCH64_A64_STZG:
    case AARCH64_A64_ST2G:
    case AARCH64_A64_STZ2G:
    case AARCH64_A64_STGM:
    case AARCH64_A64_STZGM:
    case AARCH64_A64_MSR_i_DAIFCLEAR:
    case AARCH64_A64_MSR_i_DAIFSET:
    case AARCH64_A64_MSR_i_DIT:
    case AARCH64_A64_MSR_i_PAN:
    case AARCH64_A64_MSR_i_SBSS:
    case AARCH64_A64_MSR_i_SPSEL:
    case AARCH64_A64_MSR_i_SVCR:
    case AARCH64_A64_MSR_i_TCO:
    case AARCH64_A64_MSR_i_UAO:
        fact_helper_boundary(fact);
        break;
    default:
        break;
    }

    if (!table_handled && ir1->insn_type == AARCH64_A64_NULL &&
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

    if (!table_handled && ir1->insn_type == AARCH64_A64_NULL &&
        ((insn & 0x1f000000) == 0x11000000 ||
         (insn & 0x1f000000) == 0x12000000)) {
        unsigned rd = extract32(insn, 0, 5);
        unsigned rn = extract32(insn, 5, 5);

        fact_use(fact, rn, sf);
        fact_def(fact, rd, !sf);
    }

    if (!table_handled && ir1->insn_type == AARCH64_A64_NULL &&
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
    uint32_t vec_high_live[LATA_VEC_HIGH_CLASSES] = { 0 };
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
    uint32_t vec_high_up_use[LATA_VEC_HIGH_CLASSES] = { 0 };
    uint32_t vec_high_def[LATA_VEC_HIGH_CLASSES] = { 0 };
    uint8_t nzcv_up_use = 0;
    uint8_t nzcv_def = 0;

    for (int i = tb->icount - 1; i >= 0; i--) {
        LataIR1Facts *fact = &df[i].fact;

        df[i].gpr_live_after = live;
        df[i].gpr_x_live_after = x_live;
        df[i].vec_live_after = vec_live;
        for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
            df[i].vec_high_live_after[j] = vec_high_live[j];
            df[i].vec_high_local_live_after[j] = vec_high_live[j];
        }
        df[i].nzcv_live_after = nzcv_live;
        live = fact->gpr_use | (live & ~fact->gpr_def);
        x_live = fact->gpr_x_use | (x_live & ~fact->gpr_def);
        vec_live = fact->vec_use | (vec_live & ~fact->vec_def);
        for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
            vec_high_live[j] = fact->vec_high_use[j] |
                               (vec_high_live[j] & ~fact->vec_high_def[j]);
        }
        nzcv_live = fact->nzcv_use | (nzcv_live & ~fact->nzcv_def);
        helper_boundary |= fact->helper_boundary;
        state_boundary |= fact->state_boundary;
        gpr_up_use = fact->gpr_use | (gpr_up_use & ~fact->gpr_def);
        gpr_up_x_use = fact->gpr_x_use | (gpr_up_x_use & ~fact->gpr_def);
        vec_up_use = fact->vec_use | (vec_up_use & ~fact->vec_def);
        for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
            vec_high_up_use[j] = fact->vec_high_use[j] |
                                 (vec_high_up_use[j] &
                                  ~fact->vec_high_def[j]);
        }
        nzcv_up_use = fact->nzcv_use | (nzcv_up_use & ~fact->nzcv_def);
        gpr_def |= fact->gpr_def;
        gpr_wdef |= fact->gpr_wdef;
        gpr_all_use |= fact->gpr_use;
        gpr_all_x_use |= fact->gpr_x_use;
        vec_def |= fact->vec_def;
        for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
            vec_high_def[j] |= fact->vec_high_def[j];
        }
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
    for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
        tb->lata_df_vec_high_use[j] = vec_high_up_use[j];
        tb->lata_df_vec_high_def[j] = vec_high_def[j];
        tb->lata_df_vec_high_live_in[j] = vec_high_live[j];
        tb->lata_df_vec_high_live_out[j] = UINT32_MAX;
    }
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
    uint32_t vec_high_live[LATA_VEC_HIGH_CLASSES];
    uint8_t nzcv_live;

    if (!tb || !df || !tb->icount) {
        return;
    }

    live = tb->lata_df_gpr_live_out;
    x_live = tb->lata_df_gpr_x_live_out;
    vec_live = tb->lata_df_vec_live_out;
    for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
        vec_high_live[j] = tb->lata_df_vec_high_live_out[j];
    }
    nzcv_live = tb->lata_df_nzcv_live_out_mask;

    for (int i = tb->icount - 1; i >= 0; i--) {
        LataIR1Facts *fact = &df[i].fact;

        df[i].gpr_live_after = live;
        df[i].gpr_x_live_after = x_live;
        df[i].vec_live_after = vec_live;
        for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
            df[i].vec_high_live_after[j] = vec_high_live[j];
        }
        df[i].nzcv_live_after = nzcv_live;
        live = fact->gpr_use | (live & ~fact->gpr_def);
        x_live = fact->gpr_x_use | (x_live & ~fact->gpr_def);
        vec_live = fact->vec_use | (vec_live & ~fact->vec_def);
        for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
            vec_high_live[j] = fact->vec_high_use[j] |
                               (vec_high_live[j] & ~fact->vec_high_def[j]);
        }
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
            uint32_t old_vec_high_live_out[LATA_VEC_HIGH_CLASSES];
            uint8_t old_nzcv_live_out = tb->lata_df_nzcv_live_out_mask;
            bool has_external_exit = false;

            for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
                old_vec_high_live_out[j] = tb->lata_df_vec_high_live_out[j];
            }
            tb->lata_df_gpr_live_out = 0;
            tb->lata_df_gpr_x_live_out = 0;
            tb->lata_df_vec_live_out = 0;
            for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
                tb->lata_df_vec_high_live_out[j] = 0;
            }
            tb->lata_df_nzcv_live_out_mask = 0;
            lata_df_get_successors(tb, succ, &succ_count);

            for (unsigned j = 0; j < succ_count; j++) {
                tb->lata_df_gpr_live_out |= succ[j]->lata_df_gpr_live_in;
                tb->lata_df_gpr_x_live_out |= succ[j]->lata_df_gpr_x_live_in;
                tb->lata_df_vec_live_out |= succ[j]->lata_df_vec_live_in;
                for (unsigned k = 0; k < LATA_VEC_HIGH_CLASSES; k++) {
                    tb->lata_df_vec_high_live_out[k] |=
                        succ[j]->lata_df_vec_high_live_in[k];
                }
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
                for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
                    tb->lata_df_vec_high_live_out[j] = UINT32_MAX;
                }
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
            for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
                tb->lata_df_vec_high_live_in[j] =
                    tb->lata_df_vec_high_use[j] |
                    (tb->lata_df_vec_high_live_out[j] &
                     ~tb->lata_df_vec_high_def[j]);
            }
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
            for (unsigned j = 0; j < LATA_VEC_HIGH_CLASSES; j++) {
                changed |= old_vec_high_live_out[j] !=
                           tb->lata_df_vec_high_live_out[j];
            }
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

bool lata_df_vec_high_live_after_write(unsigned reg, unsigned size)
{
    TranslationBlock *tb = active_df.tb;
    uint32_t index = active_df.next_index;
    LataIR1DF *df;
    unsigned class;

    if (!option_lata_dataflow_opt || !tb || reg >= 32 || size >= 4) {
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
    class = size == 0 ? LATA_VEC_GT_B :
            size == 1 ? LATA_VEC_GT_H :
            size == 2 ? LATA_VEC_GT_S : LATA_VEC_GT_D;
    return (df[index].vec_high_live_after[class] & (1u << reg)) != 0;
}

bool lata_df_vec_high_local_live_after_write(unsigned reg, unsigned size)
{
    TranslationBlock *tb = active_df.tb;
    uint32_t index = active_df.next_index;
    LataIR1DF *df;
    unsigned class;

    if (!option_lata_dataflow_opt || !tb || reg >= 32 || size >= 4) {
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
    class = size == 0 ? LATA_VEC_GT_B :
            size == 1 ? LATA_VEC_GT_H :
            size == 2 ? LATA_VEC_GT_S : LATA_VEC_GT_D;
    return (df[index].vec_high_local_live_after[class] & (1u << reg)) != 0;
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
             " vec_high_use={%08x,%08x,%08x,%08x}"
             " vec_high_def={%08x,%08x,%08x,%08x}"
             " live_after=0x%08x x_live_after=0x%08x"
             " vec_live_after=0x%08x"
             " vec_high_after={%08x,%08x,%08x,%08x}"
             " vec_high_local_after={%08x,%08x,%08x,%08x}"
             " nzcv(use=0x%x def=0x%x after=0x%x) helper=%d state=%d\n",
             index, (uint64_t)ir1->pc_curr, ir1->insn, ir1->insn_type,
             fact->gpr_use, fact->gpr_def, fact->gpr_wdef,
             fact->gpr_x_use, fact->vec_use, fact->vec_def,
             fact->vec_high_use[0], fact->vec_high_use[1],
             fact->vec_high_use[2], fact->vec_high_use[3],
             fact->vec_high_def[0], fact->vec_high_def[1],
             fact->vec_high_def[2], fact->vec_high_def[3],
             df->gpr_live_after, df->gpr_x_live_after, df->vec_live_after,
             df->vec_high_live_after[0], df->vec_high_live_after[1],
             df->vec_high_live_after[2], df->vec_high_live_after[3],
             df->vec_high_local_live_after[0],
             df->vec_high_local_live_after[1],
             df->vec_high_local_live_after[2],
             df->vec_high_local_live_after[3],
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
             " vec_high(use={%08x,%08x,%08x,%08x}"
             " def={%08x,%08x,%08x,%08x}"
             " in={%08x,%08x,%08x,%08x}"
             " out={%08x,%08x,%08x,%08x})"
             " nzcv(use=0x%x def=0x%x in=0x%x out=0x%x)"
             " helper=%d state=%d\n",
             (uint64_t)tb->pc, tb->lata_df_gpr_use, tb->lata_df_gpr_def,
             tb->lata_df_gpr_wdef, tb->lata_df_gpr_x_use,
             tb->lata_df_gpr_all_use, tb->lata_df_gpr_all_x_use,
             tb->lata_df_gpr_live_in,
             tb->lata_df_gpr_live_out, tb->lata_df_gpr_x_live_in,
             tb->lata_df_gpr_x_live_out, tb->lata_df_vec_use,
             tb->lata_df_vec_def, tb->lata_df_vec_live_in,
             tb->lata_df_vec_live_out,
             tb->lata_df_vec_high_use[0], tb->lata_df_vec_high_use[1],
             tb->lata_df_vec_high_use[2], tb->lata_df_vec_high_use[3],
             tb->lata_df_vec_high_def[0], tb->lata_df_vec_high_def[1],
             tb->lata_df_vec_high_def[2], tb->lata_df_vec_high_def[3],
             tb->lata_df_vec_high_live_in[0],
             tb->lata_df_vec_high_live_in[1],
             tb->lata_df_vec_high_live_in[2],
             tb->lata_df_vec_high_live_in[3],
             tb->lata_df_vec_high_live_out[0],
             tb->lata_df_vec_high_live_out[1],
             tb->lata_df_vec_high_live_out[2],
             tb->lata_df_vec_high_live_out[3],
             tb->lata_df_nzcv_use_mask,
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
