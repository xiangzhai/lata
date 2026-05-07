/*
 *  AArch64 translation
 *
 *  Copyright (c) 2013 Alexander Graf <agraf@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"

#ifdef CONFIG_LATA
#include "target/arm/lata/include/translate.h"
#include "target/arm/lata/include/arm_ldst.h"
#include "target/arm/lata/include/insts-pattern.h"
#include "ir1.h"
#include "ir1-arg.h"
#include "translate-a64.h"
#include "lata-debug.h"
#include "tu.h"
#include "clear-high.h"
#include "dataflow.h"
#endif

#include "qemu/log.h"
#include "disas/disas.h"
#include "semihosting/semihost.h"
#include "cpregs.h"
#include "exec/cpu-all.h"
#include "exec/translation-block.h"
#include "hw/core/cpu.h"

enum a64_shift_type {
    A64_SHIFT_TYPE_LSL = 0,
    A64_SHIFT_TYPE_LSR = 1,
    A64_SHIFT_TYPE_ASR = 2,
    A64_SHIFT_TYPE_ROR = 3
};

/*
 * Helpers for extracting complex instruction fields
 */

/*
 * For load/store with an unsigned 12 bit immediate scaled by the element
 * size. The input has the immediate field in bits [14:3] and the element
 * size in [2:0].
 */
static int uimm_scaled(DisasContext* s, int x)
{
    unsigned imm = x >> 3;
    unsigned scale = extract32(x, 0, 3);
    return imm << scale;
}

/* For load/store memory tags: scale offset by LOG2_TAG_GRANULE */
static int scale_by_log2_tag_granule(DisasContext* s, int x)
{
    return x << LOG2_TAG_GRANULE;
}

static void set_base_isjump(DisasContext* s);

/*
 * Include the generated decoders.
 */

// #include "decode-sme-fa64.c.inc"
#ifdef CONFIG_LATA
#include "../ir1/decode_ir1_a64.c.inc"
#endif
/* Table based decoder typedefs - used when the relevant bits for decode
 * are too awkwardly scattered across the instruction (eg SIMD).
 */
typedef void AArch64DecodeFn(DisasContext* s, uint32_t insn);

typedef struct AArch64DecodeTable {
    uint32_t pattern;
    uint32_t mask;
    AArch64DecodeFn* disas_fn;
} AArch64DecodeTable;

uint64_t asimd_imm_const(uint32_t imm, int cmode, int op)
{
    /* Expand the encoded constant as per AdvSIMDExpandImm pseudocode */
    switch (cmode) {
        case 0:
        case 1:
            /* no-op */
            break;
        case 2:
        case 3:
            imm <<= 8;
            break;
        case 4:
        case 5:
            imm <<= 16;
            break;
        case 6:
        case 7:
            imm <<= 24;
            break;
        case 8:
        case 9:
            imm |= imm << 16;
            break;
        case 10:
        case 11:
            imm = (imm << 8) | (imm << 24);
            break;
        case 12:
            imm = (imm << 8) | 0xff;
            break;
        case 13:
            imm = (imm << 16) | 0xffff;
            break;
        case 14:
            if (op) {
                /*
                 * This and cmode == 15 op == 1 are the only cases where
                 * the top and bottom 32 bits of the encoded constant differ.
                 */
                uint64_t imm64 = 0;
                int n;

                for (n = 0; n < 8; n++) {
                    if (imm & (1 << n)) {
                        imm64 |= (0xffULL << (n * 8));
                    }
                }
                return imm64;
            }
            imm |= (imm << 8) | (imm << 16) | (imm << 24);
            break;
        case 15:
            if (op) {
                /* Reserved encoding for AArch32; valid for AArch64 */
                uint64_t imm64 = (uint64_t)(imm & 0x3f) << 48;
                if (imm & 0x80) {
                    imm64 |= 0x8000000000000000ULL;
                }
                if (imm & 0x40) {
                    imm64 |= 0x3fc0000000000000ULL;
                } else {
                    imm64 |= 0x4000000000000000ULL;
                }
                return imm64;
            }
            imm = ((imm & 0x80) << 24) | ((imm & 0x3f) << 19) | ((imm & 0x40) ? (0x1f << 25) : (1 << 30));
            break;
    }
    if (op) {
        imm = ~imm;
    }
    return dup_const(MO_32, imm);
}

/*
 * The imm8 encodes the sign bit, enough bits to represent an exponent in
 * the range 01....1xx to 10....0xx, and the most significant 4 bits of
 * the mantissa; see VFPExpandImm() in the v8 ARM ARM.
 */
uint64_t vfp_expand_imm(int size, uint8_t imm8)
{
    uint64_t imm;

    switch (size) {
        case MO_64:
            imm = (extract32(imm8, 7, 1) ? 0x8000 : 0) | (extract32(imm8, 6, 1) ? 0x3fc0 : 0x4000) | extract32(imm8, 0, 6);
            imm <<= 48;
            break;
        case MO_32:
            imm = (extract32(imm8, 7, 1) ? 0x8000 : 0) | (extract32(imm8, 6, 1) ? 0x3e00 : 0x4000) | (extract32(imm8, 0, 6) << 3);
            imm <<= 16;
            break;
        case MO_16:
            imm = (extract32(imm8, 7, 1) ? 0x8000 : 0) | (extract32(imm8, 6, 1) ? 0x3000 : 0x4000) | (extract32(imm8, 0, 6) << 6);
            break;
        default:
            g_assert_not_reached();
    }
    return imm;
}

void lata_gen_exit_tb_ret_0(DisasContext* s)
{
    IR2_OPND ir2_opnd_addr;

    lata_vec_materialize_all_dirty();

    int64_t curr_ins_pos = (unsigned long)s->base->tb->tc.ptr + (lsenv->tr_data->real_ir2_inst_num << 2);
    int64_t exit_offset = context_switch_native_to_bt_ret_0 - curr_ins_pos;

    ir2_opnd_build(&ir2_opnd_addr, IR2_OPND_IMM, exit_offset >> 2);
    la_b(ir2_opnd_addr);
    s->base->is_jmp = DISAS_NORETURN;
}

static void lata_gen_a64_update_pc_value(target_ulong dest)
{
    li_d(a0_ir2_opnd, dest);
    la_st_d(a0_ir2_opnd, env_ir2_opnd, env_offset_pc());
}

void lata_gen_a64_update_pc(DisasContext* s, target_long diff)
{
    target_ulong dest = s->pc_curr + diff;

    lata_gen_a64_update_pc_value(dest);
}

static void lata_gen_exception_with_syndrome(DisasContext *s, uint32_t excp,
                                             uint32_t syndrome)
{
    IR2_OPND temp;

    if (clearGprHigh) {
        for (int i = 0; i < 32; ++i) {
            if (arm_la_map[i] >= 0) {
                clear_gpr_high_for_boundary(i);
            }
        }
    }

    temp = ra_alloc_itemp();
    li_d(temp, s->pc_curr);
    la_st_d(temp, env_ir2_opnd, env_offset_pc());
    lata_gen_call_helper_prologue(tcg_ctx);

    // CPUARMState *env, uint32_t excp, uint32_t syndrome
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    li_d(a1_ir2_opnd, excp);
    li_d(a2_ir2_opnd, syndrome);

    li_d(temp, (uint64_t)helper_exception_with_syndrome);
    la_jirl(ra_ir2_opnd, temp, 0);

    s->base->is_jmp = DISAS_NORETURN;

    free_alloc_gpr(temp);
    return;
}

static void lata_unallocated_encoding(DisasContext* s)
{
    lata_gen_exception_with_syndrome(s, EXCP_UDEF, syn_uncategorized());
}

static bool trans_EXCP_ILLEGAL(DisasContext *s)
{
    lata_gen_exception_with_syndrome(s, EXCP_UDEF, syn_illegalstate());
    return true;
}

static bool trans_EXCP_BTI(DisasContext *s)
{
    lata_gen_exception_with_syndrome(s, EXCP_UDEF, syn_btitrap(s->btype));
    return true;
}

#ifdef CONFIG_LATA_TU
void lata_emit_tu_unlink_stub(uint64_t guest_pc)
{
    IR2_OPND ir2_opnd_addr;
    TranslationBlock *tb = lsenv->tr_data->curr_tb;

    lata_vec_materialize_all_dirty();
    lata_gen_a64_update_pc_value(guest_pc);
    li_d(a0_ir2_opnd, 0);

    int64_t curr_ins_pos =
        (unsigned long)tb->tc.ptr +
        (lsenv->tr_data->real_ir2_inst_num << 2);
    int64_t exit_offset = context_switch_native_to_bt - curr_ins_pos;

    ir2_opnd_build(&ir2_opnd_addr, IR2_OPND_IMM, exit_offset >> 2);
    la_b(ir2_opnd_addr);
}
#endif

static void lata_gen_runtime_trace(DisasContext *s)
{
#ifdef CONFIG_LATA_DEBUG
    IR2_OPND helper = ra_alloc_itemp();

    lata_gen_call_helper_prologue_no_flags(tcg_ctx);
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    li_d(a1_ir2_opnd, s->pc_curr);
    li_d(a2_ir2_opnd, s->insn);
    li_d(a3_ir2_opnd, s->insn_type);
    li_d(helper, (uint64_t)lata_debug_runtime_trace);
    la_jirl(ra_ir2_opnd, helper, 0);
    lata_gen_call_helper_epilogue_no_flags(tcg_ctx);

    free_alloc_gpr(helper);
#endif
}

static void lata_gen_trace_mem_store(DisasContext *s, IR2_OPND addr,
                                     uint32_t size, bool is_vector)
{
#ifdef CONFIG_LATA_DEBUG
    IR2_OPND helper;

    if (!lata_trace_mem) {
        return;
    }

    helper = ra_alloc_itemp();
    lata_gen_call_helper_prologue_no_flags(tcg_ctx);
    li_d(a0_ir2_opnd, s->pc_curr);
    la_mov64(a1_ir2_opnd, addr);
    li_d(a2_ir2_opnd, size);
    li_d(a3_ir2_opnd, is_vector);
    li_d(helper, (uint64_t)lata_debug_trace_mem_store);
    la_jirl(ra_ir2_opnd, helper, 0);
    lata_gen_call_helper_epilogue_no_flags(tcg_ctx);
    free_alloc_gpr(helper);
#endif
}

static void lata_clean_data_tbi(DisasContext* s, IR2_OPND* dst, IR2_OPND* src, int tbi)
{
    if (tbi == 0) {
        /* Load unmodified address */
    } else {
        /* lata only support user-mode, we don't need Sign-extend */
        la_bstrpick_d(*dst, *src, 56, 0);
    }
}

static void lata_clean_pc_tbi(DisasContext *s, IR2_OPND dst, IR2_OPND src)
{
    int tbi = s->tbii;

    if (tbi == 0) {
        la_mov64(dst, src);
    } else if (!regime_has_2_ranges(s->mmu_idx)) {
        la_bstrpick_d(dst, src, 55, 0);
    } else {
        IR2_OPND clean = ra_alloc_itemp();

        /* Match QEMU gen_top_byte_ignore(): EL0/EL1 PC tags are selected
         * by bit 55, and the cleaned address is sign-extended from bit 55. */
        la_slli_d(clean, src, 8);
        la_srai_d(clean, clean, 8);

        switch (tbi) {
        case 1:
            la_and(dst, clean, src);
            break;
        case 2:
            la_or(dst, clean, src);
            break;
        case 3:
            la_mov64(dst, clean);
            break;
        default:
            g_assert_not_reached();
        }
        free_alloc_gpr(clean);
    }
}

static void lata_compute_reg_offset_addr(IR2_OPND dst, IR2_OPND base,
                                         IR2_OPND offset)
{
    la_add_d(dst, base, offset);
    la_bstrpick_d(dst, dst, 47, 0);
}

static void store_gpr_dst_w_dirty(int reg, IR2_OPND opnd)
{
    if (reg == 31) {
        return;
    }

    if (arm_la_map[reg] >= 0) {
        if (clearGprHigh) {
            set_w_write_flag(reg, false);
        } else {
            la_bstrpick_d(opnd, opnd, 31, 0);
        }
        return;
    }

    if (clearGprHigh && !lata_df_reg_high_live_after_write(reg)) {
        store_gpr_dst(reg, opnd);
        lata_gpr_cache_adopt_clean(reg, opnd);
        return;
    }

    la_bstrpick_d(opnd, opnd, 31, 0);
    store_gpr_dst(reg, opnd);
    lata_gpr_cache_adopt_clean(reg, opnd);
}

static void store_gpr_dst_reg_width(int reg, IR2_OPND opnd, bool is_64bit)
{
    if (is_64bit) {
        if (reg != 31 && arm_la_map[reg] >= 0 && clearGprHigh) {
            set_w_write_flag(reg, true);
        }
        store_gpr_dst(reg, opnd);
        lata_gpr_cache_adopt_clean(reg, opnd);
        return;
    }

    store_gpr_dst_w_dirty(reg, opnd);
}

static unsigned fp_type_to_vec_size(unsigned type)
{
    return type == 3 ? 1 : type == 0 ? 2 : 3;
}

static bool simm_fits(int64_t value, unsigned bits)
{
    int64_t min = -(1LL << (bits - 1));
    int64_t max = (1LL << (bits - 1)) - 1;

    return value >= min && value <= max;
}

static int elem_shift_from_bytes(unsigned bytes)
{
    switch (bytes) {
    case 1:
        return 0;
    case 2:
        return 1;
    case 4:
        return 2;
    case 8:
        return 3;
    default:
        g_assert_not_reached();
    }
}

static bool scaled_elem_offset(int64_t byte_offset, unsigned bytes,
                               unsigned bits, int *scaled)
{
    int shift = elem_shift_from_bytes(bytes);

    if (byte_offset & ((1 << shift) - 1)) {
        return false;
    }
    byte_offset >>= shift;
    if (!simm_fits(byte_offset, bits)) {
        return false;
    }
    *scaled = byte_offset;
    return true;
}

static IR2_OPND addr_with_const_offset(IR2_OPND base, int64_t byte_offset,
                                       IR2_OPND scratch)
{
    if (byte_offset == 0) {
        return base;
    }
    li_d(scratch, byte_offset);
    la_add_d(scratch, base, scratch);
    return scratch;
}

static bool vec_high_live_after_write(unsigned reg, unsigned size)
{
    return lata_df_vec_high_local_live_after_write(reg, size);
}

static void fpr_clear_high_d(IR2_OPND vreg)
{
    la_vinsgr2vr_d(vreg, zero_ir2_opnd, 1);
}

static void fpr_clear_high_small(IR2_OPND vreg, unsigned bytes)
{
    IR2_OPND vtmp = ra_alloc_ftemp();

    la_vori_b(vtmp, vreg, 0);
    la_vxor_v(vreg, vreg, vreg);
    if (bytes == 1) {
        la_vextrins_b(vreg, vtmp, 0);
    } else if (bytes == 2) {
        la_vextrins_h(vreg, vtmp, 0);
    } else {
        lsassert(bytes == 4);
        la_vextrins_w(vreg, vtmp, 0);
    }
    free_alloc_fpr(vtmp);
}

static void fpr_clear_high(IR2_OPND vreg, unsigned size)
{
    switch (size) {
    case 0:
        fpr_clear_high_small(vreg, 1);
        break;
    case 1:
        fpr_clear_high_small(vreg, 2);
        break;
    case 2:
        fpr_clear_high_small(vreg, 4);
        break;
    case 3:
        fpr_clear_high_d(vreg);
        break;
    default:
        break;
    }
}

static bool fpr_clear_high_if_live(IR2_OPND vreg, unsigned reg, unsigned size)
{
    if (vec_high_live_after_write(reg, size)) {
        fpr_clear_high(vreg, size);
        return true;
    }
    return false;
}

static void store_scalar_fpr_dst(unsigned reg, IR2_OPND opnd, unsigned size,
                                 bool high_clean)
{
    store_fpr_dst(reg, opnd);
    if (!high_clean) {
        lata_vec_mark_dirty(reg, size);
    }
}

static void vldrepl_elem(IR2_OPND dst, IR2_OPND base, int64_t byte_offset,
                         unsigned bytes, IR2_OPND scratch)
{
    static const unsigned bits_by_shift[] = { 12, 11, 10, 9 };
    int scaled;
    int shift = elem_shift_from_bytes(bytes);

    if (!scaled_elem_offset(byte_offset, bytes, bits_by_shift[shift], &scaled)) {
        base = addr_with_const_offset(base, byte_offset, scratch);
        scaled = 0;
    }
    switch (bytes) {
    case 1:
        la_vldrepl_b(dst, base, scaled);
        break;
    case 2:
        la_vldrepl_h(dst, base, scaled);
        break;
    case 4:
        la_vldrepl_w(dst, base, scaled);
        break;
    case 8:
        la_vldrepl_d(dst, base, scaled);
        break;
    default:
        g_assert_not_reached();
    }
}

static void vstelm_elem(IR2_OPND src, IR2_OPND base, int64_t byte_offset,
                        unsigned bytes, unsigned lane, IR2_OPND scratch)
{
    int scaled;

    lsassert(lane < (16 / bytes));
    if (!scaled_elem_offset(byte_offset, bytes, 8, &scaled)) {
        base = addr_with_const_offset(base, byte_offset, scratch);
        scaled = 0;
    }
    switch (bytes) {
    case 1:
        la_vstelm_b(src, base, scaled, lane);
        break;
    case 2:
        la_vstelm_h(src, base, scaled, lane);
        break;
    case 4:
        la_vstelm_w(src, base, scaled, lane);
        break;
    case 8:
        la_vstelm_d(src, base, scaled, lane);
        break;
    default:
        g_assert_not_reached();
    }
}

static void fpu_load(IR2_OPND dst, IR2_OPND base, int64_t byte_offset,
                     unsigned size, IR2_OPND scratch)
{
    IR2_OPND addr = base;
    int64_t imm = byte_offset;

    if (!simm_fits(byte_offset, 12)) {
        addr = addr_with_const_offset(base, byte_offset, scratch);
        imm = 0;
    }
    if (size == 2) {
        la_fld_s(dst, addr, imm);
    } else {
        lsassert(size == 3);
        la_fld_d(dst, addr, imm);
    }
}

static void fpu_store(IR2_OPND src, IR2_OPND base, int64_t byte_offset,
                      unsigned size, IR2_OPND scratch)
{
    IR2_OPND addr = base;
    int64_t imm = byte_offset;

    if (!simm_fits(byte_offset, 12)) {
        addr = addr_with_const_offset(base, byte_offset, scratch);
        imm = 0;
    }
    if (size == 2) {
        la_fst_s(src, addr, imm);
    } else {
        lsassert(size == 3);
        la_fst_d(src, addr, imm);
    }
}

static void vector_load(IR2_OPND dst, IR2_OPND base, int64_t byte_offset,
                        IR2_OPND scratch)
{
    IR2_OPND addr = base;
    int64_t imm = byte_offset;

    if (!simm_fits(byte_offset, 12)) {
        addr = addr_with_const_offset(base, byte_offset, scratch);
        imm = 0;
    }
    la_vld(dst, addr, imm);
}

static void vector_store(IR2_OPND src, IR2_OPND base, int64_t byte_offset,
                         IR2_OPND scratch)
{
    IR2_OPND addr = base;
    int64_t imm = byte_offset;

    if (!simm_fits(byte_offset, 12)) {
        addr = addr_with_const_offset(base, byte_offset, scratch);
        imm = 0;
    }
    la_vst(src, addr, imm);
}

static void vector_store_to_env(unsigned reg, IR2_OPND src)
{
    IR2_OPND scratch = ra_alloc_itemp();

    vector_store(src, env_ir2_opnd, env_offset_fpr(reg), scratch);
    free_alloc_gpr(scratch);
}

static bool scalar_elem_load(IR2_OPND dst, IR2_OPND base, int64_t byte_offset,
                             unsigned size, unsigned guest_reg)
{
    unsigned bytes = 1u << size;
    bool high_clean = vec_high_live_after_write(guest_reg, size);

    if (!high_clean) {
        if (size == 2) {
            IR2_OPND scratch = ra_alloc_itemp();
            fpu_load(dst, base, byte_offset, size, scratch);
            free_alloc_gpr(scratch);
        } else if (size == 3) {
            IR2_OPND scratch = ra_alloc_itemp();
            fpu_load(dst, base, byte_offset, size, scratch);
            free_alloc_gpr(scratch);
        } else {
            IR2_OPND scratch = ra_alloc_itemp();
            vldrepl_elem(dst, base, byte_offset, bytes, scratch);
            free_alloc_gpr(scratch);
        }
        return false;
    }

    if (size == 2) {
        IR2_OPND vtmp = ra_alloc_ftemp();
        IR2_OPND scratch = ra_alloc_itemp();

        la_vxor_v(dst, dst, dst);
        fpu_load(vtmp, base, byte_offset, size, scratch);
        la_vextrins_w(dst, vtmp, 0);
        free_alloc_gpr(scratch);
        free_alloc_fpr(vtmp);
    } else if (size == 3) {
        IR2_OPND scratch = ra_alloc_itemp();

        fpu_load(dst, base, byte_offset, size, scratch);
        fpr_clear_high_d(dst);
        free_alloc_gpr(scratch);
    } else {
        IR2_OPND vtmp = ra_alloc_ftemp();
        IR2_OPND scratch = ra_alloc_itemp();

        la_vxor_v(dst, dst, dst);
        vldrepl_elem(vtmp, base, byte_offset, bytes, scratch);
        if (size == 0) {
            la_vextrins_b(dst, vtmp, 0);
        } else {
            la_vextrins_h(dst, vtmp, 0);
        }
        free_alloc_gpr(scratch);
        free_alloc_fpr(vtmp);
    }
    return true;
}


// check saturate
static inline void gen_sat_q(IR2_OPND vreg, int size, int is_u)
{
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND set_qc = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND exit = ir2_opnd_new_type(IR2_OPND_LABEL);

    uint64_t* upper;
    uint64_t* lower;

    static uint64_t s_upper[] = { INT8_MAX, INT16_MAX, INT32_MAX, INT64_MAX };
    static uint64_t s_lower[] = { INT8_MIN, INT16_MIN, INT32_MIN, INT64_MIN };

    static uint64_t u_upper[] = { UINT8_MAX, UINT16_MAX, UINT32_MAX,
        UINT64_MAX };
    static uint64_t u_lower[] = { 0, 0, 0, 0 };

    if (!is_u)
        upper = s_upper, lower = s_lower;
    else
        upper = u_upper, lower = u_lower;

    li_d(temp, upper[size]);
    la_vinsgr2vr_d(vtemp, temp, 0);

    switch (size) {
        case 0:
            la_vreplvei_b(vtemp, vtemp, 0);
            la_vseq_b(vtemp, vtemp, vreg);
            break;
        case 1:
            la_vreplvei_h(vtemp, vtemp, 0);
            la_vseq_h(vtemp, vtemp, vreg);
            break;
        case 2:
            la_vreplvei_w(vtemp, vtemp, 0);
            la_vseq_w(vtemp, vtemp, vreg);
            break;
        case 3:
            la_vreplvei_d(vtemp, vtemp, 0);
            la_vseq_d(vtemp, vtemp, vreg);
            break;
        default:
            assert(0);
    }

    la_vsetanyeqz_b(fcc1_ir2_opnd, vtemp);
    la_bcnez(fcc1_ir2_opnd, set_qc);

    li_d(temp, lower[size]);
    la_vinsgr2vr_d(vtemp, temp, 0);

    switch (size) {
        case 0:
            la_vreplvei_b(vtemp, vtemp, 0);
            la_vseq_b(vtemp, vtemp, vreg);
            break;
        case 1:
            la_vreplvei_h(vtemp, vtemp, 0);
            la_vseq_h(vtemp, vtemp, vreg);
            break;
        case 2:
            la_vreplvei_w(vtemp, vtemp, 0);
            la_vseq_w(vtemp, vtemp, vreg);
            break;
        case 3:
            la_vreplvei_d(vtemp, vtemp, 0);
            la_vseq_d(vtemp, vtemp, vreg);
            break;
        default:
            assert(0);
    }

    la_vsetanyeqz_b(fcc1_ir2_opnd, vtemp);
    la_bcnez(fcc1_ir2_opnd, set_qc);

    la_b(exit);

    la_label(set_qc);

    li_d(temp, 1);
    la_st_w(temp, env_ir2_opnd, env_offset_QC());

    la_label(exit);

    free_alloc_gpr(temp);
    free_alloc_fpr(vtemp);
}

static void lata_helper_addl_saturate_s64(DisasContext* ctx, IR2_OPND vreg_d, IR2_OPND vreg1,
    IR2_OPND vreg2, int rd)
{
    IR2_OPND temp = ra_alloc_itemp();

    // li_d(temp, ctx->base->pc_next);
    // la_st_d(temp, env_ir2_opnd, env_offset_pc());

    lata_gen_call_helper_prologue(tcg_ctx);

    li_d(temp, (uint64_t)helper_neon_addl_saturate_s64);
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    la_vpickve2gr_d(a1_ir2_opnd, vreg1, 0);
    la_vpickve2gr_d(a2_ir2_opnd, vreg2, 0);
    la_jirl(ra_ir2_opnd, temp, 0);
    la_vinsgr2vr_d(vreg_d, a0_ir2_opnd, 0);

    li_d(temp, (uint64_t)helper_neon_addl_saturate_s64);
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    la_vpickve2gr_d(a1_ir2_opnd, vreg1, 1);
    la_vpickve2gr_d(a2_ir2_opnd, vreg2, 1);
    la_jirl(ra_ir2_opnd, temp, 0);
    la_vinsgr2vr_d(vreg_d, a0_ir2_opnd, 1);

    if (rd != -1)
        vector_store_to_env(rd, vreg_d);

    lata_gen_call_helper_epilogue(tcg_ctx);

    free_alloc_gpr(temp);
}

static void lata_helper_addl_saturate_s32(DisasContext* ctx, IR2_OPND vreg_d, IR2_OPND vreg1,
    IR2_OPND vreg2, int rd)
{
    IR2_OPND temp = ra_alloc_itemp();

    // li_d(temp, ctx->base->pc_next);
    // la_st_d(temp, env_ir2_opnd, env_offset_pc());

    lata_gen_call_helper_prologue(tcg_ctx);

    li_d(temp, (uint64_t)helper_neon_addl_saturate_s32);
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    la_vpickve2gr_w(a1_ir2_opnd, vreg1, 0);
    la_vpickve2gr_w(a2_ir2_opnd, vreg2, 0);
    la_jirl(ra_ir2_opnd, temp, 0);
    la_vinsgr2vr_w(vreg_d, a0_ir2_opnd, 0);

    li_d(temp, (uint64_t)helper_neon_addl_saturate_s32);
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    la_vpickve2gr_w(a1_ir2_opnd, vreg1, 1);
    la_vpickve2gr_w(a2_ir2_opnd, vreg2, 1);
    la_jirl(ra_ir2_opnd, temp, 0);
    la_vinsgr2vr_w(vreg_d, a0_ir2_opnd, 1);

    li_d(temp, (uint64_t)helper_neon_addl_saturate_s32);
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    la_vpickve2gr_w(a1_ir2_opnd, vreg1, 2);
    la_vpickve2gr_w(a2_ir2_opnd, vreg2, 2);
    la_jirl(ra_ir2_opnd, temp, 0);
    la_vinsgr2vr_w(vreg_d, a0_ir2_opnd, 2);

    li_d(temp, (uint64_t)helper_neon_addl_saturate_s32);
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    la_vpickve2gr_w(a1_ir2_opnd, vreg1, 3);
    la_vpickve2gr_w(a2_ir2_opnd, vreg2, 3);
    la_jirl(ra_ir2_opnd, temp, 0);
    la_vinsgr2vr_w(vreg_d, a0_ir2_opnd, 3);
    if (rd != -1)
        vector_store_to_env(rd, vreg_d);

    lata_gen_call_helper_epilogue(tcg_ctx);
    free_alloc_gpr(temp);
}

#ifdef CONFIG_LATA_PROFILE
#define LATA_FAM_COUNTER_ENABLED() \
    (option_lata_fam_stats || indirect_jmp_opt_profile)
#else
#define LATA_FAM_COUNTER_ENABLED() (option_lata_fam_stats)
#endif
#define LATA_FAM_PROFILE_INC_INDEXED(tmp, kind, base_offset) do {         \
    if (LATA_FAM_COUNTER_ENABLED()) {                                     \
        la_ld_d((tmp), env_ir2_opnd,                                      \
                (base_offset) + sizeof(uint64_t) * (kind));               \
        la_addi_d((tmp), (tmp), 1);                                       \
        la_st_d((tmp), env_ir2_opnd,                                      \
                (base_offset) + sizeof(uint64_t) * (kind));               \
    }                                                                     \
} while (0)
#define LATA_FAM_PROFILE_INC_SCALAR(tmp, base_offset) do {                \
    if (LATA_FAM_COUNTER_ENABLED()) {                                     \
        la_ld_d((tmp), env_ir2_opnd, (base_offset));                      \
        la_addi_d((tmp), (tmp), 1);                                       \
        la_st_d((tmp), env_ir2_opnd, (base_offset));                      \
    }                                                                     \
} while (0)
#define LATA_FAM_PROFILE_LOOKUP(tmp, kind) do {                           \
    LATA_FAM_PROFILE_INC_INDEXED((tmp), (kind),                           \
                                 env_offset(fam_lookup_count));           \
    LATA_FAM_PROFILE_INC_SCALAR((tmp), env_offset(jr_cnt));               \
} while (0)
#define LATA_FAM_PROFILE_HIT(tmp, kind) do {                              \
    LATA_FAM_PROFILE_INC_INDEXED((tmp), (kind),                           \
                                 env_offset(fam_hit_count));              \
    LATA_FAM_PROFILE_INC_SCALAR((tmp), env_offset(jr_hit));               \
} while (0)
#define LATA_FAM_PROFILE_MISS(tmp, kind)                                  \
    LATA_FAM_PROFILE_INC_INDEXED((tmp), (kind), env_offset(fam_miss_count))
#define LATA_FAM_PROFILE_RANGE_MISS(tmp, kind)                            \
    LATA_FAM_PROFILE_INC_INDEXED((tmp), (kind),                           \
                                 env_offset(fam_range_miss_count))
#define LATA_FAM_PROFILE_MISS_REASON(tmp, kind, base_offset)              \
    LATA_FAM_PROFILE_INC_INDEXED((tmp), (kind), (base_offset))

static bool lata_fam_cflags_supported(uint32_t cflags)
{
    return !(cflags & (CF_COUNT_MASK | CF_INVALID | CF_NO_GOTO_TB |
                       CF_NO_GOTO_PTR | CF_SINGLE_STEP | CF_LAST_IO |
                       CF_MEMI_ONLY | CF_USE_ICOUNT | CF_NOIRQ | CF_PCREL));
}

static uint64_t lata_fam_cs_base_with_btype(TranslationBlock *tb, int btype)
{
    CPUARMTBFlags flags = arm_tbflags_from_tb(tb);

    DP_TBFLAG_A64(flags, BTYPE, btype);
    return flags.flags2;
}

static uint64_t lata_fam_expected_indirect_cs_base(DisasContext *s,
                                                  LataFAMKind fam_kind,
                                                  uint32_t rn)
{
    TranslationBlock *tb = s->base->tb;

    switch (fam_kind) {
    case LATA_FAM_KIND_BR:
        if (dc_isar_feature(aa64_bti, s)) {
            int btype = rn == 16 || rn == 17 || !s->guarded_page ? 1 : 3;

            return lata_fam_cs_base_with_btype(tb, btype);
        }
        return lata_fam_cs_base_with_btype(tb, 0);
    case LATA_FAM_KIND_BLR:
        return dc_isar_feature(aa64_bti, s) ?
            lata_fam_cs_base_with_btype(tb, 2) :
            lata_fam_cs_base_with_btype(tb, 0);
    case LATA_FAM_KIND_RET_X30:
    case LATA_FAM_KIND_RET_XN:
        /*
         * RET does not set BTYPE.  If this is not the first instruction in a
         * BTYPE-entered TB, earlier non-branch instructions have already reset
         * it to zero.
         */
        return s->pc_curr == tb->pc ? tb->cs_base :
            lata_fam_cs_base_with_btype(tb, 0);
    default:
        return tb->cs_base;
    }
}

static TranslationBlock *lata_lookup_direct_branch_tb(DisasContext *s,
                                                      int64_t diff)
{
#ifdef CONFIG_LATA_INDIRECT_JMP
    TranslationBlock *tb = s->base->tb;
    target_ulong guest_dest = s->pc_curr + diff;
    uint64_t cs_base = lata_fam_cs_base_with_btype(tb, 0);

    if (!tb || option_fam_jmp_cache < 0 ||
        !lata_fam_cflags_supported(tb_cflags(tb)) ||
        qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
        return NULL;
    }

    return lata_fam_lookup_tb(current_cpu->env_ptr, guest_dest, cs_base,
                              tb->flags, tb_cflags(tb));
#else
    return NULL;
#endif
}

static void lata_emit_fam_keyed_lookup(DisasContext *s, IR2_OPND target_pc,
                                       LataFAMKind fam_kind,
                                       uint64_t expected_cs_base)
{
#ifdef CONFIG_LATA_INDIRECT_JMP
    TranslationBlock *tb = s->base->tb;
    IR2_OPND miss = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND unsupported_miss = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND empty_miss = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND key_miss = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND invalid_miss = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND cache = ra_alloc_itemp();
    IR2_OPND entry = ra_alloc_itemp();
    IR2_OPND tb_ptr = ra_alloc_itemp();
    IR2_OPND scratch = ra_alloc_itemp();
    IR2_OPND cpu_ptr = ra_alloc_itemp();

    LATA_FAM_PROFILE_LOOKUP(scratch, fam_kind);

    if (option_fam_jmp_cache < 0 ||
        !lata_fam_cflags_supported(tb_cflags(tb))) {
        la_b(unsupported_miss);
    } else {
        li_d(cpu_ptr, env_offset(lata_cpu_state));
        la_ldx_d(cpu_ptr, env_ir2_opnd, cpu_ptr);
        la_ld_wu(scratch, cpu_ptr, offsetof(CPUState, cflags_next_tb));
        li_d(entry, UINT32_MAX);
        la_bne(scratch, entry, unsupported_miss);

        li_d(cache, env_offset(lata_fam_cache));
        la_ldx_d(cache, env_ir2_opnd, cache);
        la_beqz(cache, empty_miss);

        la_srli_d(entry, target_pc, TB_JMP_CACHE_BITS);
        la_xor(entry, target_pc, entry);
        la_bstrpick_d(entry, entry, TB_JMP_CACHE_BITS - 1, 0);
        la_slli_d(entry, entry, 5);
        la_add_d(entry, entry, cache);
        la_addi_d(entry, entry, offsetof(LataFAMCache, entries));

        la_ld_d(scratch, entry, offsetof(LataFAMEntry, pc));
        la_bne(scratch, target_pc, key_miss);
        li_d(scratch, expected_cs_base);
        la_ld_d(cache, entry, offsetof(LataFAMEntry, cs_base));
        la_bne(cache, scratch, key_miss);
        li_d(scratch, tb->flags);
        la_ld_wu(cache, entry, offsetof(LataFAMEntry, flags));
        la_bne(cache, scratch, key_miss);
        li_d(scratch, tb_cflags(tb) & ~CF_INVALID);
        la_ld_wu(cache, entry, offsetof(LataFAMEntry, cflags));
        la_bne(cache, scratch, key_miss);

        la_ld_d(tb_ptr, entry, offsetof(LataFAMEntry, tb));
        la_beqz(tb_ptr, empty_miss);

        la_ld_d(scratch, tb_ptr, offsetof(TranslationBlock, pc));
        la_bne(scratch, target_pc, key_miss);
        li_d(scratch, expected_cs_base);
        la_ld_d(cache, tb_ptr, offsetof(TranslationBlock, cs_base));
        la_bne(cache, scratch, key_miss);
        li_d(scratch, tb->flags);
        la_ld_wu(cache, tb_ptr, offsetof(TranslationBlock, flags));
        la_bne(cache, scratch, key_miss);
        la_ld_wu(cache, tb_ptr, offsetof(TranslationBlock, cflags));
        la_bstrpick_w(scratch, cache, 18, 18);
        la_bnez(scratch, invalid_miss);
        la_bstrins_d(cache, zero_ir2_opnd, 18, 18);
        li_d(scratch, tb_cflags(tb) & ~CF_INVALID);
        la_bne(cache, scratch, key_miss);

        la_st_d(target_pc, env_ir2_opnd, env_offset_pc());
        la_ld_d(tb_ptr, tb_ptr,
                offsetof(TranslationBlock, tc) + offsetof(struct tb_tc, ptr));
        la_beqz(tb_ptr, invalid_miss);
        LATA_FAM_PROFILE_HIT(scratch, fam_kind);
        la_jirl(zero_ir2_opnd, tb_ptr, 0);
    }

    la_label(unsupported_miss);
    LATA_FAM_PROFILE_MISS_REASON(
        scratch, fam_kind, env_offset(fam_unsupported_miss_count));
    la_b(miss);

    la_label(empty_miss);
    LATA_FAM_PROFILE_MISS_REASON(
        scratch, fam_kind, env_offset(fam_empty_miss_count));
    la_b(miss);

    la_label(key_miss);
    LATA_FAM_PROFILE_MISS_REASON(
        scratch, fam_kind, env_offset(fam_key_miss_count));
    la_b(miss);

    la_label(invalid_miss);
    LATA_FAM_PROFILE_MISS_REASON(
        scratch, fam_kind, env_offset(fam_invalid_miss_count));
    la_b(miss);

    la_label(miss);
    LATA_FAM_PROFILE_MISS(scratch, fam_kind);

    free_alloc_gpr(cpu_ptr);
    free_alloc_gpr(scratch);
    free_alloc_gpr(tb_ptr);
    free_alloc_gpr(entry);
    free_alloc_gpr(cache);
#endif
}

static void lata_emit_fam_fast_lookup(DisasContext *s, IR2_OPND target_pc,
                                      LataFAMKind fam_kind,
                                      uint64_t expected_cs_base)
{
#ifdef CONFIG_LATA_INDIRECT_JMP
    TranslationBlock *tb = s->base->tb;
    IR2_OPND miss = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND unsupported_miss = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND empty_miss = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND key_miss = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND invalid_miss = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND entry = ra_alloc_itemp();
    IR2_OPND host_ptr = ra_alloc_itemp();
    IR2_OPND scratch = ra_alloc_itemp();

    LATA_FAM_PROFILE_LOOKUP(scratch, fam_kind);

    if (option_fam_jmp_cache <= 0 ||
        !lata_fam_cflags_supported(tb_cflags(tb))) {
        la_b(unsupported_miss);
    } else {
        li_d(entry, env_offset(lata_cpu_state));
        la_ldx_d(entry, env_ir2_opnd, entry);
        la_ld_wu(scratch, entry, offsetof(CPUState, cflags_next_tb));
        li_d(entry, UINT32_MAX);
        la_bne(scratch, entry, unsupported_miss);

        li_d(entry, env_offset(lata_fam_cache));
        la_ldx_d(entry, env_ir2_opnd, entry);
        la_beqz(entry, empty_miss);

        /*
         * Fast FAM keeps the LATX-style cheap hit path: one fixed-size hash
         * probe, a complete AArch64 TB-key comparison, then a direct jump to
         * the cached host entry.  The saved TB pointer is used by invalidation,
         * not by the hot generated-code hit path.
         */
        la_srli_d(scratch, target_pc, TB_JMP_CACHE_BITS);
        la_xor(scratch, target_pc, scratch);
        la_bstrpick_d(scratch, scratch, TB_JMP_CACHE_BITS - 1, 0);
        la_slli_d(scratch, scratch, 5);
        la_add_d(entry, entry, scratch);
        la_addi_d(entry, entry, offsetof(LataFAMCache, entries));

        la_ld_d(host_ptr, entry, offsetof(LataFAMEntry, pc));
        la_bne(host_ptr, target_pc, key_miss);

        li_d(scratch, expected_cs_base);
        la_ld_d(host_ptr, entry, offsetof(LataFAMEntry, cs_base));
        la_bne(host_ptr, scratch, key_miss);

        li_d(scratch, (((uint64_t)(tb_cflags(tb) & ~CF_INVALID)) << 32) |
              tb->flags);
        la_ld_d(host_ptr, entry, offsetof(LataFAMEntry, flags_cflags));
        la_bne(host_ptr, scratch, key_miss);

        la_ld_d(host_ptr, entry, offsetof(LataFAMEntry, host_ptr));
        la_beqz(host_ptr, invalid_miss);
        LATA_FAM_PROFILE_HIT(scratch, fam_kind);
        la_jirl(zero_ir2_opnd, host_ptr, 0);
    }

    la_label(unsupported_miss);
    LATA_FAM_PROFILE_MISS_REASON(
        scratch, fam_kind, env_offset(fam_unsupported_miss_count));
    la_b(miss);

    la_label(empty_miss);
    LATA_FAM_PROFILE_MISS_REASON(
        scratch, fam_kind, env_offset(fam_empty_miss_count));
    la_b(miss);

    la_label(key_miss);
    LATA_FAM_PROFILE_MISS_REASON(
        scratch, fam_kind, env_offset(fam_key_miss_count));
    la_b(miss);

    la_label(invalid_miss);
    LATA_FAM_PROFILE_MISS_REASON(
        scratch, fam_kind, env_offset(fam_invalid_miss_count));
    la_b(miss);

    la_label(miss);
    LATA_FAM_PROFILE_MISS(scratch, fam_kind);

    free_alloc_gpr(scratch);
    free_alloc_gpr(host_ptr);
    free_alloc_gpr(entry);
#endif
}

static void lata_emit_fam_lookup(DisasContext *s, IR2_OPND target_pc,
                                 LataFAMKind fam_kind,
                                 uint64_t expected_cs_base)
{
#ifdef CONFIG_LATA_INDIRECT_JMP
    if (option_fam_jmp_cache > 0) {
        lata_emit_fam_fast_lookup(s, target_pc, fam_kind, expected_cs_base);
    } else {
        lata_emit_fam_keyed_lookup(s, target_pc, fam_kind, expected_cs_base);
    }
#endif
}

static void gen_goto_tb_indirect_kind(DisasContext* s, uint32_t rn,
                                      LataFAMKind fam_kind)
{
    IR2_OPND reg_n = alloc_gpr_src(rn);
    IR2_OPND target_pc = ra_alloc_itemp();
    uint64_t expected_cs_base =
        lata_fam_expected_indirect_cs_base(s, fam_kind, rn);

    lata_clean_pc_tbi(s, target_pc, reg_n);
    lata_gpr_cache_flush_all();
    lata_emit_fam_lookup(s, target_pc, fam_kind, expected_cs_base);

    la_st_d(target_pc, env_ir2_opnd, env_offset_pc());
    lata_gen_exit_tb_ret_0(s);

    free_alloc_gpr(target_pc);
    free_alloc_gpr(reg_n);
}

static void gen_goto_tb_indirect_boundary(DisasContext *s, uint32_t rn,
                                          LataTUBoundaryKind kind)
{
    LataFAMKind fam_kind = LATA_FAM_KIND_BR;

    lata_debug_note_tu_boundary(kind);
    if (kind == LATA_TU_BOUNDARY_RET) {
        fam_kind = rn == 30 ? LATA_FAM_KIND_RET_X30 : LATA_FAM_KIND_RET_XN;
    }
    gen_goto_tb_indirect_kind(s, rn, fam_kind);
}

static void gen_goto_tb_indirect_blr(DisasContext* s, IR2_OPND reg_n,
                                     LataFAMKind fam_kind)
{
    IR2_OPND target_pc = ra_alloc_itemp();
    uint64_t expected_cs_base =
        lata_fam_expected_indirect_cs_base(s, fam_kind, 0);

    lata_clean_pc_tbi(s, target_pc, reg_n);
    lata_gpr_cache_flush_all();
    lata_emit_fam_lookup(s, target_pc, fam_kind, expected_cs_base);

    la_st_d(target_pc, env_ir2_opnd, env_offset_pc());
    lata_gen_exit_tb_ret_0(s);

    free_alloc_gpr(target_pc);
    free_alloc_gpr(reg_n);
}

static void gen_goto_tb_indirect_blr_boundary(DisasContext *s,
                                              IR2_OPND reg_n)
{
    lata_debug_note_tu_boundary(LATA_TU_BOUNDARY_BLR);
    gen_goto_tb_indirect_blr(s, reg_n, LATA_FAM_KIND_BLR);
}

#undef LATA_FAM_PROFILE_INC_INDEXED
#undef LATA_FAM_PROFILE_INC_SCALAR
#undef LATA_FAM_COUNTER_ENABLED
#undef LATA_FAM_PROFILE_LOOKUP
#undef LATA_FAM_PROFILE_HIT
#undef LATA_FAM_PROFILE_MISS
#undef LATA_FAM_PROFILE_RANGE_MISS
#undef LATA_FAM_PROFILE_MISS_REASON

static void lata_set_btype(DisasContext *s, int val)
{
    if (s->btype == val) {
        return;
    }
    li_d(a0_ir2_opnd, val);
    la_st_w(a0_ir2_opnd, env_ir2_opnd, env_offset(btype));
    s->btype = -1;
}

static void lata_reset_btype(DisasContext *s)
{
    if (s->btype != 0) {
        li_d(a0_ir2_opnd, 0);
        la_st_w(a0_ir2_opnd, env_ir2_opnd, env_offset(btype));
        s->btype = 0;
    }
}

static void lata_set_btype_for_br(DisasContext *s, int rn)
{
    if (dc_isar_feature(aa64_bti, s)) {
        lata_set_btype(s, rn == 16 || rn == 17 || !s->guarded_page ? 1 : 3);
    }
}

static void lata_set_btype_for_blr(DisasContext *s)
{
    if (dc_isar_feature(aa64_bti, s)) {
        lata_set_btype(s, 2);
    }
}

static bool lata_is_guarded_page(CPUARMState *env, DisasContext *s)
{
#ifdef CONFIG_USER_ONLY
    return (page_get_flags(s->base->pc_first) & PAGE_BTI) != 0;
#else
    (void)env;
    (void)s;
    return false;
#endif
}

static bool lata_btype_destination_ok(uint32_t insn, bool bt, int btype)
{
    if ((insn & 0xfffff01fu) == 0xd503201fu) {
        switch (extract32(insn, 5, 7)) {
        case 0x19: /* PACIASP */
        case 0x1b: /* PACIBSP */
            return !bt || btype != 3;
        case 0x20: /* BTI */
            return false;
        case 0x22: /* BTI c */
            return btype != 3;
        case 0x24: /* BTI j */
            return btype != 2;
        case 0x26: /* BTI jc */
            return true;
        }
    } else {
        switch (insn & 0xffe0001fu) {
        case 0xd4200000u: /* BRK */
        case 0xd4400000u: /* HLT */
            return true;
        }
    }
    return false;
}

static inline void li_arm_addr(IR2_OPND opnd2, int64_t value)
{

    uint32_t /* hi32 ,*/ lo32;

    lo32 = value & 0xffffffff;
    // hi32 = value >> 32;

    la_lu12i_w(opnd2, lo32 >> 12);
    la_ori(opnd2, opnd2, lo32 & 0xfff);
};

static inline void li_tb(IR2_OPND opnd2, int64_t value)
{

    uint32_t hi32, lo32;

    lo32 = value & 0xffffffff;
    hi32 = value >> 32;

    la_lu12i_w(opnd2, lo32 >> 12);
    la_ori(opnd2, opnd2, lo32 & 0xfff);
    la_lu32i_d(opnd2, hi32 & 0xfffff);
};

static void gen_goto_tb(DisasContext* s, int n, int64_t diff)
{
    IR2_OPND goto_label = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND ir2_opnd_addr;
    TranslationBlock* tb = lsenv->tr_data->curr_tb;

    lata_vec_materialize_all_dirty();

#ifdef CONFIG_LATA_TU
    if (tb && tb->next_tb[n] != NULL) {
        la_label(goto_label);
        lata_tu_edge_emit_branch(tb, n, ir2_opnd_label_id(&goto_label),
                                 s->pc_curr + diff);
        ir2_opnd_build(&ir2_opnd_addr, IR2_OPND_IMM, 1);
        la_b(ir2_opnd_addr);
        set_base_isjump(s);
        return;
    }
#endif

    tb->lata_prelink_tb[n] = lata_lookup_direct_branch_tb(s, diff);

    la_label(goto_label);
    tb->jmp_reset_offset[n] = ir2_opnd_label_id(&goto_label);
    ir2_opnd_build(&ir2_opnd_addr, IR2_OPND_IMM, B_STUB_SIZE >> 2);
    la_b(ir2_opnd_addr); // nop
    la_ld_d(a0_ir2_opnd, a0_ir2_opnd, 0);
    la_jirl(zero_ir2_opnd, a0_ir2_opnd, 0);

    lata_gen_a64_update_pc(s, diff);

    if (qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
        li_d(a0_ir2_opnd, 0); // do not link
    } else {
        li_tb(a0_ir2_opnd, (uint64_t)tb | n);
    }

    int64_t curr_ins_pos = (unsigned long)tb->tc.ptr + (lsenv->tr_data->real_ir2_inst_num << 2);
    int64_t exit_offset = context_switch_native_to_bt - curr_ins_pos;

    ir2_opnd_build(&ir2_opnd_addr, IR2_OPND_IMM, exit_offset >> 2);
    la_b(ir2_opnd_addr);
    set_base_isjump(s);
}

#ifdef CONFIG_LATA_TU
static void gen_goto_tb_nochain(DisasContext* s, int64_t diff)
{
    IR2_OPND ir2_opnd_addr;
    TranslationBlock* tb = lsenv->tr_data->curr_tb;

    lata_vec_materialize_all_dirty();
    lata_gen_a64_update_pc(s, diff);
    li_d(a0_ir2_opnd, 0);

    int64_t curr_ins_pos = (unsigned long)tb->tc.ptr +
        (lsenv->tr_data->real_ir2_inst_num << 2);
    int64_t exit_offset = context_switch_native_to_bt - curr_ins_pos;

    ir2_opnd_build(&ir2_opnd_addr, IR2_OPND_IMM, exit_offset >> 2);
    la_b(ir2_opnd_addr);
}

static bool tu_has_both_cond_edges(TranslationBlock *tb)
{
    return tb &&
           tb->next_tb[TU_TB_INDEX_NEXT] &&
           tb->next_tb[TU_TB_INDEX_TARGET] &&
           tb->next_tb[TU_TB_INDEX_NEXT]->pc == tb->next_pc &&
           tb->next_tb[TU_TB_INDEX_TARGET]->pc == tb->target_pc;
}

static void gen_tu_b_edge(DisasContext *s, int n, int64_t diff)
{
    IR2_OPND goto_label = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND ir2_opnd_addr;
    TranslationBlock *tb = lsenv->tr_data->curr_tb;

    lata_vec_materialize_all_dirty();
    la_label(goto_label);
    lata_tu_edge_emit_branch(tb, n, ir2_opnd_label_id(&goto_label),
                             s->pc_curr + diff);
    ir2_opnd_build(&ir2_opnd_addr, IR2_OPND_IMM, 1);
    la_b(ir2_opnd_addr);
}

static void gen_tu_cond_edge_setup(DisasContext *s, int64_t target_diff)
{
    TranslationBlock *tb = lsenv->tr_data->curr_tb;

    tb->tu_edges[TU_TB_INDEX_TARGET].fallback_guest_pc =
        s->pc_curr + target_diff;
    tb->tu_edges[TU_TB_INDEX_NEXT].fallback_guest_pc = s->pc_curr + 4;
    tb->tu_has_edges = true;
}

static void gen_tu_shared_unlink_label(TranslationBlock *tb, IR2_OPND label)
{
    lata_tu_edge_set_unlink_stub(tb, TU_TB_INDEX_TARGET,
                                 ir2_opnd_label_id(&label));
    lata_tu_edge_set_unlink_stub(tb, TU_TB_INDEX_NEXT,
                                 ir2_opnd_label_id(&label));
}

static void gen_tu_unlink_stubs(TranslationBlock *tb)
{
    if (!tb || !tu_use_jmp(tb)) {
        return;
    }

    for (int n = 0; n < 2; n++) {
        LataTUEdge *edge = &tb->tu_edges[n];
        if (edge->branch_offset == LATA_TU_EDGE_OFFSET_INVALID) {
            continue;
        }
        if (edge->unlink_stub_offset != TU_UNLINK_STUB_INVALID) {
            continue;
        }

        IR2_OPND unlink_label = ir2_opnd_new_type(IR2_OPND_LABEL);

        la_label(unlink_label);
        lata_tu_edge_set_unlink_stub(tb, n, ir2_opnd_label_id(&unlink_label));
        edge->local_unlink_stub_offset = ir2_opnd_label_id(&unlink_label);
        lata_emit_tu_unlink_stub(edge->fallback_guest_pc);
    }
}
#endif

/* dest = T0 - T1; compute C, N, V and Z flags */

static void gen_add_CC(IR2_OPND* src1, IR2_OPND* src2, int sf)
{
    if (sf) {
        la_x86add_d(*src1, *src2);
    } else {
        la_x86add_w(*src1, *src2);
    }
}

static void gen_sub_CC(IR2_OPND* src1, IR2_OPND* src2, int sf)
{
    if (sf) {
        /*  bits(datasize) operand1 = *src1;
            bits(datasize) operand2 = NOT(*src2);
            (-, nzcv) = AddWithCarry(operand1, operand2, '1');
        */
        IR2_OPND temp = ra_alloc_itemp();
        la_lu12i_w(temp, 0x20000);
        la_armmtflag(temp, 0x39);           // pstate.c = 1
        la_orn(temp, zero_ir2_opnd, *src2); // NOT(*src2)
        la_x86adc_d(*src1, temp);
        free_alloc_gpr(temp);
    } else {
        /*  bits(datasize) operand1 = *src1;
            bits(datasize) operand2 = NOT(*src2);
            (-, nzcv) = AddWithCarry(operand1, operand2, '1');
        */
        IR2_OPND temp = ra_alloc_itemp();
        la_lu12i_w(temp, 0x20000);
        la_armmtflag(temp, 0x39);           // pstate.c = 1
        la_orn(temp, zero_ir2_opnd, *src2); // NOT(*src2)
        la_x86adc_w(*src1, temp);
        free_alloc_gpr(temp);
    }
}

static void gen_add(IR2_OPND* dst, IR2_OPND* src1, IR2_OPND* src2, int sf)
{
    if (sf) {
        la_add_d(*dst, *src1, *src2);
    } else {
        la_add_w(*dst, *src1, *src2);
    }
}

static void gen_sub(IR2_OPND* dst, IR2_OPND* src1, IR2_OPND* src2, int sf)
{
    if (sf) {
        la_sub_d(*dst, *src1, *src2);
    } else {
        la_sub_w(*dst, *src1, *src2);
    }
}

/* Check that FP/Neon access is enabled. If it is, return
 * true. If not, emit code to generate an appropriate exception,
 * and return false; the caller should not emit any code for
 * the instruction. Note that this check must happen after all
 * unallocated-encoding checks (otherwise the syndrome information
 * for the resulting exception will be incorrect).
 */
static bool fp_access_check_only(DisasContext* s)
{
    if (s->fp_excp_el) {
        assert(!s->fp_access_checked);
        s->fp_access_checked = true;

        lata_unallocated_encoding(s);
        return true;
        return false;
    }
    s->fp_access_checked = true;
    return true;
}

static bool fp_access_check(DisasContext* s)
{
    if (!fp_access_check_only(s)) {
        return false;
    }
    if (s->sme_trap_nonstreaming && s->is_nonstreaming) {
        lata_unallocated_encoding(s);
        return true;
        return false;
    }
    return true;
}

/*
 * Check that SME access is enabled, raise an exception if not.
 * Note that this function corresponds to CheckSMEAccess and is
 * only used directly for cpregs.
 */
static bool sme_access_check(DisasContext* s)
{
    if (s->sme_excp_el) {
        lata_unallocated_encoding(s);
        return true;
        return false;
    }
    return true;
}

/*
 * Check that SVE access is enabled.  If it is, return true.
 * If not, emit code to generate an appropriate exception and return false.
 * This function corresponds to CheckSVEEnabled().
 */
bool sve_access_check(DisasContext* s)
{
    if (s->pstate_sm || !dc_isar_feature(aa64_sve, s)) {
        lata_unallocated_encoding(s);
        return false;
    } else if (s->sve_excp_el) {
        lata_unallocated_encoding(s);
        return false;
    }
    s->sve_access_checked = true;
    return fp_access_check(s);
}

static inline void gen_check_sp_alignment(DisasContext* s)
{
    /* The AArch64 architecture mandates that (if enabled via PSTATE
     * or SCTLR bits) there is a check that SP is 16-aligned on every
     * SP-relative load or store (with an exception generated if it is not).
     * In line with general QEMU practice regarding misaligned accesses,
     * we omit these checks for the sake of guest program performance.
     * This function is provided as a hook so we can more easily add these
     * checks in future (possibly as a "favour catching guest program bugs
     * over speed" user selectable option).
     */
}

/*
 * This provides a simple table based table lookup decoder. It is
 * intended to be used when the relevant bits for decode are too
 * awkwardly placed and switch/if based logic would be confusing and
 * deeply nested. Since it's a linear search through the table, tables
 * should be kept small.
 *
 * It returns the first handler where insn & mask == pattern, or
 * NULL if there is no match.
 * The table is terminated by an empty mask (i.e. 0)
 */
static inline AArch64DecodeFn* lookup_disas_fn(const AArch64DecodeTable* table,
    uint32_t insn)
{
    const AArch64DecodeTable* tptr = table;

    while (tptr->mask) {
        if ((insn & tptr->mask) == tptr->pattern) {
            return tptr->disas_fn;
        }
        tptr++;
    }
    return NULL;
}

/*
 * The instruction disassembly implemented here matches
 * the instruction encoding classifications in chapter C4
 * of the ARM Architecture Reference Manual (DDI0487B_a);
 * classification names and decode diagrams here should generally
 * match up with those in the manual.
 */

static bool trans_B(DisasContext* s)
{
    arg_i* a = &(s->arg.f_i);
    if (clearGprHigh) {
        for (int i = 0; i < 32; ++i) {
            if (arm_la_map[i] >= 0) {
                clear_gpr_high_for_boundary(i);
            }
        }
    }

    lata_reset_btype(s);
    gen_goto_tb(s, 1, a->imm);
    // s->base->is_jmp = DISAS_NORETURN;

    return true;
}

static bool trans_BL(DisasContext* s)
{
    arg_i* a = &(s->arg.f_i);
    if (clearGprHigh) {
        for (int i = 0; i < 32; ++i) {
            if (arm_la_map[i] >= 0) {
                clear_gpr_high_for_boundary(i);
            }
        }
    }

    IR2_OPND x30 = alloc_gpr_dst(30);
    li_d(x30, s->base->pc_next); /* BL setting X30 to PC+4 */
    store_gpr_dst(30, x30);

    lata_reset_btype(s);
    gen_goto_tb(s, 1, a->imm);
    // s->base->is_jmp = DISAS_NORETURN;

    return true;
}

static bool trans_CBZ(DisasContext* s)
{
    arg_cbz* a = &(s->arg.f_cbz);
    if (clearGprHigh) {
        for (int i = 0; i < 32; ++i) {
            if (arm_la_map[i] >= 0) {
                clear_gpr_high_for_boundary(i);
            }
        }
    }

    IR2_OPND reg_t = alloc_gpr_src_ro(a->rt);
    IR2_OPND label = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND temp;

    lata_reset_btype(s);

    lata_vec_materialize_all_dirty();
    if (a->sf) {
        if (a->nz) { // CBNZ
            la_bnez(reg_t, label);
        } else { // CBZ
            la_beqz(reg_t, label);
        }
    } else {
        temp = ra_alloc_itemp();
        la_bstrpick_d(temp, reg_t, 31, 0);
        if (a->nz) { // CBNZ
            la_bnez(temp, label);
        } else { // CBZ
            la_beqz(temp, label);
        }
        free_alloc_gpr(temp);
    }

    gen_goto_tb(s, 0, 4);
    la_label(label);
    gen_goto_tb(s, 1, a->imm);
    // s->base->is_jmp = DISAS_NORETURN;

    free_alloc_gpr(reg_t);
    return true;
}

static bool trans_TBZ(DisasContext* s)
{
    arg_tbz* a = &(s->arg.f_tbz);
    if (clearGprHigh) {
        for (int i = 0; i < 32; ++i) {
            if (arm_la_map[i] >= 0) {
                clear_gpr_high_for_boundary(i);
            }
        }
    }

    IR2_OPND reg_t = alloc_gpr_src_ro(a->rt);
    IR2_OPND label = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND temp = ra_alloc_itemp();

    lata_reset_btype(s);

    la_bstrpick_d(temp, reg_t, a->bitpos, a->bitpos);
    lata_vec_materialize_all_dirty();
    if (a->nz) { // TBNZ
        la_bnez(temp, label);
    } else { // TBZ
        la_beqz(temp, label);
    }
    gen_goto_tb(s, 0, 4);
    la_label(label);
    gen_goto_tb(s, 1, a->imm);
    // s->base->is_jmp = DISAS_NORETURN;

    free_alloc_gpr(reg_t);
    free_alloc_gpr(temp);
    return true;
}

static bool trans_B_cond(DisasContext* s)
{
    arg_B_cond* a = &(s->arg.f_decode_insn3211);
    if (clearGprHigh) {
        for (int i = 0; i < 32; ++i) {
            if (arm_la_map[i] >= 0) {
                clear_gpr_high_for_boundary(i);
            }
        }
    }

    lata_reset_btype(s);

    if (a->cond < 0x0e) {
        /* genuinely conditional branches */
        IR2_OPND label = ir2_opnd_new_type(IR2_OPND_LABEL);
        IR2_OPND reg_t = ra_alloc_itemp();
        la_setarmj(reg_t, a->cond);
        lata_vec_materialize_all_dirty();
#ifdef CONFIG_LATA_TU
        TranslationBlock *tb = lsenv->tr_data->curr_tb;
        if (tu_has_both_cond_edges(tb)) {
            gen_tu_cond_edge_setup(s, a->imm);
            la_label(label);
            lata_tu_edge_emit_cond_branch(tb, TU_TB_INDEX_TARGET,
                                          ir2_opnd_label_id(&label),
                                          s->pc_curr + a->imm,
                                          LATA_TU_BRANCH_BCC20);
            la_bnez(reg_t, label);
            gen_tu_b_edge(s, TU_TB_INDEX_NEXT, 4);

            IR2_OPND unlink_label = ir2_opnd_new_type(IR2_OPND_LABEL);
            IR2_OPND target_label = ir2_opnd_new_type(IR2_OPND_LABEL);
            IR2_OPND fallback_cond = ra_alloc_itemp();

            la_label(unlink_label);
            gen_tu_shared_unlink_label(tb, unlink_label);
            la_setarmj(fallback_cond, a->cond);
            la_bnez(fallback_cond, target_label);
            gen_goto_tb_nochain(s, 4);
            la_label(target_label);
            gen_goto_tb_nochain(s, a->imm);

            free_alloc_gpr(fallback_cond);
            free_alloc_gpr(reg_t);
            set_base_isjump(s);
            return true;
        }
#endif
        la_bnez(reg_t, label);
        gen_goto_tb(s, 0, 4);
        la_label(label);
        gen_goto_tb(s, 1, a->imm);
        free_alloc_gpr(reg_t);
    } else {
        /* 0xe and 0xf are both "always" conditions */
        gen_goto_tb(s, 0, a->imm);
    }
    // s->base->is_jmp = DISAS_NORETURN;
    return true;
}

static bool trans_BR(DisasContext* s)
{
    arg_r* a = &(s->arg.f_r);
    if (clearGprHigh) {
        for (int i = 0; i < 32; ++i) {
            if (arm_la_map[i] >= 0) {
                clear_gpr_high_for_boundary(i);
            }
        }
    }
    lata_set_btype_for_br(s, a->rn);
    gen_goto_tb_indirect_boundary(s, a->rn, LATA_TU_BOUNDARY_BR);
    // s->base->is_jmp = DISAS_NORETURN;

    return true;
}

static bool trans_BLR(DisasContext* s)
{
    arg_r* a = &(s->arg.f_r);

    IR2_OPND reg_n;
    IR2_OPND x30 = alloc_gpr_dst(30);

    if (clearGprHigh) {
        for (int i = 0; i < 32; ++i) {
            if (arm_la_map[i] >= 0) {
                clear_gpr_high_for_boundary(i);
            }
        }
    }

    if (a->rn != 30) {
        reg_n = alloc_gpr_src(a->rn);
    } else {
        reg_n = ra_alloc_itemp();
        la_ori(reg_n, x30, 0);
    }

    li_d(x30, s->base->pc_next); /* BL setting X30 to PC+4 */
    store_gpr_dst(30, x30);

    lata_set_btype_for_blr(s);
    gen_goto_tb_indirect_blr_boundary(s, reg_n);
    // s->base->is_jmp = DISAS_NORETURN;

    return true;
}

static bool trans_RET(DisasContext* s)
{
    arg_r* a = &(s->arg.f_r);
    if (clearGprHigh) {
        for (int i = 0; i < 32; ++i) {
            if (arm_la_map[i] >= 0) {
                clear_gpr_high_for_boundary(i);
            }
        }
    }
    gen_goto_tb_indirect_boundary(s, a->rn, LATA_TU_BOUNDARY_RET);
    // s->base->is_jmp = DISAS_NORETURN;

    return true;
}

static bool trans_BRAZ(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_BLRAZ(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_RETA(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_BRA(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_BLRA(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_ERET(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_ERETA(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_NOP(DisasContext* s)
{
    return true;
}

static bool trans_YIELD(DisasContext* s)
{
    /*
     * When running in MTTCG we don't generate jumps to the yield and
     * WFE helpers as it won't affect the scheduling of other vCPUs.
     * If we wanted to more completely model WFE/SEV so we don't busy
     * spin unnecessarily we would need to do something more involved.
     */
    if (!(tb_cflags(s->base->tb) & CF_PARALLEL)) {
        // s->base->is_jmp = DISAS_YIELD;
    }
    return true;
}

static bool trans_WFI(DisasContext* s)
{
    s->base->is_jmp = DISAS_WFI;
    return true;
}

static bool trans_WFE(DisasContext* s)
{
    /*
     * When running in MTTCG we don't generate jumps to the yield and
     * WFE helpers as it won't affect the scheduling of other vCPUs.
     * If we wanted to more completely model WFE/SEV so we don't busy
     * spin unnecessarily we would need to do something more involved.
     */
    if (!(tb_cflags(s->base->tb) & CF_PARALLEL)) {
        s->base->is_jmp = DISAS_WFE;
    }
    return true;
}

static bool trans_XPACLRI(DisasContext* s)
{
    return true;
}

static bool trans_PACIA1716(DisasContext* s)
{
    return true;
}

static bool trans_PACIB1716(DisasContext* s)
{
    return true;
}

static bool trans_AUTIA1716(DisasContext* s)
{
    return true;
}

static bool trans_AUTIB1716(DisasContext* s)
{
    return true;
}

static bool trans_ESB(DisasContext* s)
{
    return true;
}

static bool trans_PACIAZ(DisasContext* s)
{
    return true;
}

static bool trans_PACIASP(DisasContext* s)
{
    return true;
}

static bool trans_PACIBZ(DisasContext* s)
{
    return true;
}

static bool trans_PACIBSP(DisasContext* s)
{
    return true;
}

static bool trans_AUTIAZ(DisasContext* s)
{
    return true;
}

static bool trans_AUTIASP(DisasContext* s)
{
    return true;
}

static bool trans_AUTIBZ(DisasContext* s)
{
    return true;
}

static bool trans_AUTIBSP(DisasContext* s)
{
    return true;
}

static bool trans_CLREX(DisasContext* s)
{
    /* Clear exclusive monitor by consuming LLbit with a dummy SC.
     * LoongArch has no explicit CLREX instruction.
     * SC to exclusive_memdata field: read old value, then SC it back.
     * This is a safe no-op in memory – doesn't change any data. */
    IR2_OPND addr = ra_alloc_itemp();
    IR2_OPND val = ra_alloc_itemp();

    li_d(addr, env_offset(exclusive_memdata));
    la_add_d(addr, env_ir2_opnd, addr);

    la_ll_d(val, addr, 0); /* LL.D to overwrite lladdr with env field address */
    la_sc_d(val, addr, 0); /* SC.D consumes LLbit — clears exclusive monitor */

    free_alloc_gpr(addr);
    free_alloc_gpr(val);
    return true;
}

static void lata_gen_mb(void)
{
    bool parallel = tcg_ctx->gen_tb->cflags & CF_PARALLEL;
    if (parallel) {
        la_dbar(0);
    }
}

static bool trans_DSB_DMB(DisasContext* s)
{
    lata_gen_mb();
    return true;
}

static bool trans_ISB(DisasContext* s)
{
    lata_reset_btype(s);
    gen_goto_tb(s, 0, 4);
    return true;
}

static bool trans_SB(DisasContext* s)
{
    if (!dc_isar_feature(aa64_sb, s)) {
        return false;
    }
    /*
     * TODO: There is no speculation barrier opcode for TCG;
     * MB and end the TB instead.
     */
    la_dbar(0);
    gen_goto_tb(s, 0, 4);
    return true;
}

static bool trans_CFINV(DisasContext* s)
{
    IR2_OPND t1 = ra_alloc_itemp(), t2 = ra_alloc_itemp();
    la_armmfflag(t1, 0x01);
    li_d(t2, 0x20000000);
    la_xor(t1, t1, t2);
    la_armmtflag(t1, 0x01);
    free_alloc_gpr(t1);
    free_alloc_gpr(t2);
    return true;
}

static bool trans_XAFLAG(DisasContext* s)
{
    /* Convert x86-style flags → ARM NZCV */
    IR2_OPND f = ra_alloc_itemp(), z = ra_alloc_itemp(), c = ra_alloc_itemp();
    IR2_OPND t1 = ra_alloc_itemp(), t2 = ra_alloc_itemp();
    la_armmfflag(f, 0x39);
    la_bstrpick_d(f, f, 31, 0);
    li_d(t1, 0x40000000);
    la_and(z, f, t1); /* z = f & Z */
    li_d(t1, 0x20000000);
    la_and(c, f, t1); /* c = f & C */
    /* new_n = (not_c << 2) & (not_z << 1) */
    li_d(t2, 0x20000000);
    la_andn(t2, t2, c);
    la_slli_d(t2, t2, 2); /* not_c << 2 */
    li_d(t1, 0x40000000);
    la_andn(t1, t1, z);
    la_slli_d(t1, t1, 1); /* not_z << 1 */
    la_and(t1, t2, t1);   /* t1 = new_n */
    /* new_z = z & (c << 1) */
    la_slli_d(t2, c, 1);
    la_and(t2, z, t2); /* t2 = new_z */
    la_or(f, t1, t2);  /* f = new_n | new_z */
    /* new_c = c | (z >> 1) */
    la_srli_d(t1, z, 1);
    la_or(t1, c, t1);
    la_or(f, f, t1); /* f |= new_c */
    /* new_v = (not_c >> 1) & (z >> 2) */
    li_d(t2, 0x20000000);
    la_andn(t2, t2, c);
    la_srli_d(t2, t2, 1); /* not_c >> 1 */
    la_srli_d(t1, z, 2);
    la_and(t1, t2, t1);
    la_or(f, f, t1); /* f |= new_v */
    la_armmtflag(f, 0x39);
    free_alloc_gpr(f);
    free_alloc_gpr(z);
    free_alloc_gpr(c);
    free_alloc_gpr(t1);
    free_alloc_gpr(t2);
    return true;
}

static bool trans_AXFLAG(DisasContext* s)
{
    /* Convert ARM NZCV → x86-style flags */
    IR2_OPND f = ra_alloc_itemp(), z = ra_alloc_itemp(), c = ra_alloc_itemp();
    IR2_OPND v = ra_alloc_itemp();
    la_armmfflag(f, 0x39);
    la_bstrpick_d(f, f, 31, 0);
    li_d(z, 0x40000000);
    la_and(z, f, z); /* z */
    li_d(v, 0x10000000);
    la_and(v, f, v); /* v */
    la_slli_d(c, v, 2);
    la_or(z, z, c); /* new_z = z | (v << 2) */
    li_d(c, 0x20000000);
    la_and(c, f, c);    /* c */
    la_slli_d(v, v, 1); /* v <<= 1 */
    la_andn(c, c, v);   /* c & ~(v<<1) */
    li_d(v, 0x20000000);
    la_and(c, c, v); /* mask to C bit */
    la_or(f, z, c);  /* result = new_z | new_c */
    la_armmtflag(f, 0x39);
    free_alloc_gpr(f);
    free_alloc_gpr(z);
    free_alloc_gpr(c);
    free_alloc_gpr(v);
    return true;
}

static bool trans_RMIF(DisasContext* s)
{
    /* RMIF Xn, #shift, #mask: rotate Xn right by shift, extract bits[3:0],
     * update NZCV flags per mask (bit3=N, bit2=Z, bit1=C, bit0=V). */
    uint32_t insn = s->insn;
    int rn = extract32(insn, 5, 5);
    int shift = extract32(insn, 15, 6);
    int mask = extract32(insn, 0, 4);

    IR2_OPND reg_n = alloc_gpr_src(rn);
    IR2_OPND rotated = ra_alloc_itemp();
    IR2_OPND flags = ra_alloc_itemp();
    IR2_OPND current = ra_alloc_itemp();
    IR2_OPND tmp = ra_alloc_itemp();

    /* rotated = ROR(Xn, shift) */
    la_rotri_d(rotated, reg_n, shift);

    /* flags = rotated & 0xF */
    la_andi(flags, rotated, 0xF);

    /* Read current NZCV */
    la_armmfflag(current, 0x39);
    /* Clear upper 32 bits (matches XAFLAG pattern) */
    la_bstrpick_d(current, current, 31, 0);

    /* Keep only flags NOT being updated: current & ~(mask << 28) */
    li_d(tmp, mask);
    la_slli_d(tmp, tmp, 28);
    la_andn(current, current, tmp);

    /* Shift new flags to NZCV position, mask them: (flags & mask) << 28 */
    la_andi(flags, flags, mask);
    la_slli_d(flags, flags, 28);

    /* Combine: new_nzcv = kept_old | new_flags */
    la_or(current, current, flags);

    /* Write back NZCV */
    la_armmtflag(current, 0x39);

    free_alloc_gpr(reg_n);
    free_alloc_gpr(rotated);
    free_alloc_gpr(flags);
    free_alloc_gpr(current);
    free_alloc_gpr(tmp);
    return true;
}

static bool trans_CRYPTO(DisasContext* s)
{
    uint32_t insn = s->insn;
    uint8_t top = insn >> 24;
    int size = extract32(insn, 22, 2);

    if (top == 0x4E) {
        int opcode = extract32(insn, 12, 5);
        int rn = extract32(insn, 5, 5);
        int rd = extract32(insn, 0, 5);
        if (!dc_isar_feature(aa64_aes, s) || size != 0) {
            lata_unallocated_encoding(s);
            return true;
        }
        if (!fp_access_check(s)) return true;
        void* helper_func;
        bool is_2reg = false;
        switch (opcode) {
            case 4: helper_func = helper_crypto_aese; break;
            case 5: helper_func = helper_crypto_aesd; break;
            case 6:
                helper_func = helper_crypto_aesmc;
                is_2reg = true;
                break;
            case 7:
                helper_func = helper_crypto_aesimc;
                is_2reg = true;
                break;
            default: lata_unallocated_encoding(s); return true;
        }
        IR2_OPND temp = ra_alloc_itemp();
        lata_gen_call_helper_prologue(tcg_ctx);
        if (is_2reg) {
            li_d(temp, env_offset_fpr(rd));
            la_add_d(a0_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, env_offset_fpr(rn));
            la_add_d(a1_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, 0x101);
            la_mov64(a2_ir2_opnd, temp);
        } else {
            /* AESE/AESD are destructive two-source operations:
             * helper(rd, rd, rn), matching QEMU's gen_gvec_op3_ool use.
             * The encoding has no Rm field; bits[20:16] are fixed pattern bits.
             */
            li_d(temp, env_offset_fpr(rd));
            la_add_d(a0_ir2_opnd, env_ir2_opnd, temp);
            la_mov64(a1_ir2_opnd, a0_ir2_opnd);
            li_d(temp, env_offset_fpr(rn));
            la_add_d(a2_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, 0x101);
            la_mov64(a3_ir2_opnd, temp);
        }
        li_d(temp, (uint64_t)helper_func);
        la_jirl(ra_ir2_opnd, temp, 0);
        lata_gen_call_helper_epilogue(tcg_ctx);
        free_alloc_gpr(temp);
        return true;
    }

    if (top == 0x5E) {
        bool is_three_reg = (insn & 0xFF208C00) == 0x5E000000;
        bool is_two_reg = (insn & 0xFF3E0C00) == 0x5E280800;
        int rn = extract32(insn, 5, 5);
        int rd = extract32(insn, 0, 5);
        if (size != 0) {
            lata_unallocated_encoding(s);
            return true;
        }
        if (!is_three_reg && !is_two_reg) {
            goto crypto_undef;
        }
        if (!fp_access_check(s)) return true;
        void* helper_func = NULL;
        int rm_sh = 0;
        if (is_two_reg) {
            int opcode = extract32(insn, 12, 5);
            switch (opcode) {
                case 0:
                    if (!dc_isar_feature(aa64_sha1, s)) goto crypto_undef;
                    helper_func = helper_crypto_sha1h;
                    break;
                case 1:
                    if (!dc_isar_feature(aa64_sha1, s)) goto crypto_undef;
                    helper_func = helper_crypto_sha1su1;
                    break;
                case 2:
                    if (!dc_isar_feature(aa64_sha256, s)) goto crypto_undef;
                    helper_func = helper_crypto_sha256su0;
                    break;
                default: goto crypto_undef;
            }
        } else {
            int opcode = extract32(insn, 12, 3);
            rm_sh = extract32(insn, 16, 5);
            switch (opcode) {
                case 0:
                    if (!dc_isar_feature(aa64_sha1, s)) goto crypto_undef;
                    helper_func = helper_crypto_sha1c;
                    break;
                case 1:
                    if (!dc_isar_feature(aa64_sha1, s)) goto crypto_undef;
                    helper_func = helper_crypto_sha1p;
                    break;
                case 2:
                    if (!dc_isar_feature(aa64_sha1, s)) goto crypto_undef;
                    helper_func = helper_crypto_sha1m;
                    break;
                case 3:
                    if (!dc_isar_feature(aa64_sha1, s)) goto crypto_undef;
                    helper_func = helper_crypto_sha1su0;
                    break;
                case 4:
                    if (!dc_isar_feature(aa64_sha256, s)) goto crypto_undef;
                    helper_func = helper_crypto_sha256h;
                    break;
                case 5:
                    if (!dc_isar_feature(aa64_sha256, s)) goto crypto_undef;
                    helper_func = helper_crypto_sha256h2;
                    break;
                case 6:
                    if (!dc_isar_feature(aa64_sha256, s)) goto crypto_undef;
                    helper_func = helper_crypto_sha256su1;
                    break;
                default: goto crypto_undef;
            }
        }
        IR2_OPND temp = ra_alloc_itemp();
        lata_gen_call_helper_prologue(tcg_ctx);
        if (is_two_reg) {
            li_d(temp, env_offset_fpr(rd));
            la_add_d(a0_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, env_offset_fpr(rn));
            la_add_d(a1_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, 0x101);
            la_mov64(a2_ir2_opnd, temp);
        } else {
            li_d(temp, env_offset_fpr(rd));
            la_add_d(a0_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, env_offset_fpr(rn));
            la_add_d(a1_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, env_offset_fpr(rm_sh));
            la_add_d(a2_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, 0x101);
            la_mov64(a3_ir2_opnd, temp);
        }
        li_d(temp, (uint64_t)helper_func);
        la_jirl(ra_ir2_opnd, temp, 0);
        lata_gen_call_helper_epilogue(tcg_ctx);
        free_alloc_gpr(temp);
        return true;
    }

    if (top == 0xCE) {
        int rn = extract32(insn, 5, 5);
        int rd = extract32(insn, 0, 5);
        int rm = extract32(insn, 16, 5);
        IR2_OPND temp;
        if (!fp_access_check(s)) return true;

        /* EOR3/BCAX/SM3SS1: 4-reg */
        if ((insn & 0xFF808000) == 0xCE000000) {
            int op0 = extract32(insn, 21, 2);
            int ra = extract32(insn, 10, 5);
            IR2_OPND vreg_d = alloc_fpr_dst(rd);
            IR2_OPND vreg_n = alloc_fpr_src(rn);
            IR2_OPND vreg_m = alloc_fpr_src(rm);
            IR2_OPND vreg_k = alloc_fpr_src(ra);
            if (op0 == 0) {
                IR2_OPND vtemp2 = ra_alloc_ftemp();
                la_vxor_v(vtemp2, vreg_n, vreg_m);
                la_vxor_v(vreg_d, vtemp2, vreg_k);
                free_alloc_fpr(vtemp2);
            } else if (op0 == 1) {
                IR2_OPND vtemp2 = ra_alloc_ftemp();
                la_vandn_v(vtemp2, vreg_k, vreg_m);
                la_vxor_v(vreg_d, vreg_n, vtemp2);
                free_alloc_fpr(vtemp2);
            } else {
                /* SM3SS1 */
                IR2_OPND gn = ra_alloc_itemp(), gm = ra_alloc_itemp(), gk = ra_alloc_itemp();
                la_vpickve2gr_wu(gn, vreg_n, 3);
                la_vpickve2gr_wu(gm, vreg_m, 3);
                la_vpickve2gr_wu(gk, vreg_k, 3);
                la_rotri_w(gn, gn, 20);
                la_add_w(gn, gn, gm);
                la_add_w(gn, gn, gk);
                la_rotri_w(gn, gn, 25);
                la_vinsgr2vr_d(vreg_d, gn, 0);
                la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
                free_alloc_gpr(gn);
                free_alloc_gpr(gm);
                free_alloc_gpr(gk);
            }
            store_fpr_dst(rd, vreg_d);
            free_alloc_fpr(vreg_d);
            free_alloc_fpr(vreg_n);
            free_alloc_fpr(vreg_m);
            free_alloc_fpr(vreg_k);
            return true;
        }

        /* XAR */
        if ((insn & 0xFFE00000) == 0xCE800000) {
            int imm6 = extract32(insn, 10, 6);
            IR2_OPND vreg_d = alloc_fpr_dst(rd);
            IR2_OPND vreg_n = alloc_fpr_src(rn);
            IR2_OPND vreg_m = alloc_fpr_src(rm);
            IR2_OPND vtemp2 = ra_alloc_ftemp();
            la_vrotri_d(vtemp2, vreg_m, imm6);
            la_vxor_v(vreg_d, vreg_n, vtemp2);
            store_fpr_dst(rd, vreg_d);
            free_alloc_fpr(vreg_d);
            free_alloc_fpr(vreg_n);
            free_alloc_fpr(vreg_m);
            free_alloc_fpr(vtemp2);
            return true;
        }

        /* SM3TT imm2 */
        if ((insn & 0xFFE0C000) == 0xCE408000) {
            int opcode_tt = extract32(insn, 12, 2);
            int imm2 = extract32(insn, 10, 2);
            uint32_t desc_val = 0x101 | (imm2 << 10);
            void* tt_func = NULL;
            switch (opcode_tt) {
                case 0: tt_func = helper_crypto_sm3tt1a; break;
                case 1: tt_func = helper_crypto_sm3tt1b; break;
                case 2: tt_func = helper_crypto_sm3tt2a; break;
                case 3: tt_func = helper_crypto_sm3tt2b; break;
                default: goto crypto_undef;
            }
            if (!dc_isar_feature(aa64_sm3, s)) goto crypto_undef;
            temp = ra_alloc_itemp();
            lata_gen_call_helper_prologue(tcg_ctx);
            li_d(temp, env_offset_fpr(rd));
            la_add_d(a0_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, env_offset_fpr(rn));
            la_add_d(a1_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, env_offset_fpr(rm));
            la_add_d(a2_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, desc_val);
            la_mov64(a3_ir2_opnd, temp);
            li_d(temp, (uint64_t)tt_func);
            la_jirl(ra_ir2_opnd, temp, 0);
            lata_gen_call_helper_epilogue(tcg_ctx);
            free_alloc_gpr(temp);
            return true;
        }

        /* SHA512SU0 (2-reg) or SM4E (3-reg vd=vn) */
        if ((insn & 0xFFFFF000) == 0xCEC08000) {
            int opcode_2r = extract32(insn, 10, 2);
            temp = ra_alloc_itemp();
            lata_gen_call_helper_prologue(tcg_ctx);
            if (opcode_2r == 0) {
                if (!dc_isar_feature(aa64_sha512, s)) {
                    lata_gen_call_helper_epilogue(tcg_ctx);
                    free_alloc_gpr(temp);
                    goto crypto_undef;
                }
                li_d(temp, env_offset_fpr(rd));
                la_add_d(a0_ir2_opnd, env_ir2_opnd, temp);
                li_d(temp, env_offset_fpr(rn));
                la_add_d(a1_ir2_opnd, env_ir2_opnd, temp);
                li_d(temp, 0x101);
                la_mov64(a2_ir2_opnd, temp);
                li_d(temp, (uint64_t)helper_crypto_sha512su0);
                la_jirl(ra_ir2_opnd, temp, 0);
            } else if (opcode_2r == 1) {
                if (!dc_isar_feature(aa64_sm4, s)) {
                    lata_gen_call_helper_epilogue(tcg_ctx);
                    free_alloc_gpr(temp);
                    goto crypto_undef;
                }
                li_d(temp, env_offset_fpr(rd));
                la_add_d(a0_ir2_opnd, env_ir2_opnd, temp);
                la_mov64(a1_ir2_opnd, a0_ir2_opnd);
                li_d(temp, env_offset_fpr(rn));
                la_add_d(a2_ir2_opnd, env_ir2_opnd, temp);
                li_d(temp, 0x101);
                la_mov64(a3_ir2_opnd, temp);
                li_d(temp, (uint64_t)helper_crypto_sm4e);
                la_jirl(ra_ir2_opnd, temp, 0);
            } else {
                lata_gen_call_helper_epilogue(tcg_ctx);
                free_alloc_gpr(temp);
                goto crypto_undef;
            }
            lata_gen_call_helper_epilogue(tcg_ctx);
            free_alloc_gpr(temp);
            return true;
        }

        /* SHA512/SM3/SM4 3-reg */
        if ((insn & 0xFFE0B000) == 0xCE608000) {
            void* func3 = NULL;
            int sub_o = extract32(insn, 10, 1);
            int sub_opcode;
            if (sub_o == 0) {
                sub_opcode = extract32(insn, 12, 2);
                switch (sub_opcode) {
                    case 0:
                        if (!dc_isar_feature(aa64_sha512, s)) goto crypto_undef;
                        func3 = helper_crypto_sha512h;
                        break;
                    case 1:
                        if (!dc_isar_feature(aa64_sha512, s)) goto crypto_undef;
                        func3 = helper_crypto_sha512h2;
                        break;
                    case 2:
                        if (!dc_isar_feature(aa64_sha512, s)) goto crypto_undef;
                        func3 = helper_crypto_sha512su1;
                        break;
                    case 3:
                        if (!dc_isar_feature(aa64_sha3, s)) goto crypto_undef;
                        func3 = helper_crypto_rax1;
                        break;
                    default: goto crypto_undef;
                }
            } else {
                sub_opcode = extract32(insn, 12, 2);
                switch (sub_opcode) {
                    case 0:
                        if (!dc_isar_feature(aa64_sm3, s)) goto crypto_undef;
                        func3 = helper_crypto_sm3partw1;
                        break;
                    case 1:
                        if (!dc_isar_feature(aa64_sm3, s)) goto crypto_undef;
                        func3 = helper_crypto_sm3partw2;
                        break;
                    case 2:
                        if (!dc_isar_feature(aa64_sm4, s)) goto crypto_undef;
                        func3 = helper_crypto_sm4ekey;
                        break;
                    default: goto crypto_undef;
                }
            }
            temp = ra_alloc_itemp();
            lata_gen_call_helper_prologue(tcg_ctx);
            li_d(temp, env_offset_fpr(rd));
            la_add_d(a0_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, env_offset_fpr(rn));
            la_add_d(a1_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, env_offset_fpr(rm));
            la_add_d(a2_ir2_opnd, env_ir2_opnd, temp);
            li_d(temp, 0x101);
            la_mov64(a3_ir2_opnd, temp);
            li_d(temp, (uint64_t)func3);
            la_jirl(ra_ir2_opnd, temp, 0);
            lata_gen_call_helper_epilogue(tcg_ctx);
            free_alloc_gpr(temp);
            return true;
        }
    }

crypto_undef:
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_FCADD(DisasContext* s)
{
    /* FCADD vector complex add: opcode in bits[15:11], 0x1c=#90, 0x1e=#270 */
    uint32_t insn = s->insn;
    int is_q = extract32(insn, 30, 1);
    int size = extract32(insn, 22, 2);
    int opcode = extract32(insn, 11, 5);
    int rm = extract32(insn, 16, 5);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);
    bool is270 = (opcode == 0x1e);

    /* FCADD uses size=3 for f64 — skip the generic size==3 check */
    if (!fp_access_check(s)) return true;

    IR2_OPND vd = alloc_fpr_dst(rd);
    IR2_OPND vn_re = alloc_fpr_src(rn);
    IR2_OPND vm_im = alloc_fpr_src(rm);
    IR2_OPND ve = ra_alloc_ftemp();
    IR2_OPND vo = ra_alloc_ftemp();
    IR2_OPND te = ra_alloc_ftemp();
    IR2_OPND to2 = ra_alloc_ftemp();

    if (size == 0) { /* f32: encoded size=0 for FCADD */
        IR2_OPND vn_e = ra_alloc_ftemp(), vn_o = ra_alloc_ftemp();
        IR2_OPND vm_e = ra_alloc_ftemp(), vm_o = ra_alloc_ftemp();
        IR2_OPND r1 = ra_alloc_ftemp(), r2 = ra_alloc_ftemp();
        la_vilvl_w(ve, vn_re, vm_im);
        la_vilvh_w(vo, vn_re, vm_im);
        la_vilvl_w(vn_e, ve, vo);
        la_vilvh_w(vm_e, ve, vo);
        la_vilvh_w(vn_o, vn_e, vn_e);
        la_vilvh_w(vm_o, vm_e, vm_e);
        if (is270) {
            la_vfadd_s(r1, vn_e, vm_o);
            la_vfsub_s(r2, vn_o, vm_e);
        } else {
            la_vfsub_s(r1, vn_e, vm_o);
            la_vfadd_s(r2, vn_o, vm_e);
        }
        la_vilvl_w(vd, r1, r2);
        free_alloc_fpr(vn_e);
        free_alloc_fpr(vn_o);
        free_alloc_fpr(vm_e);
        free_alloc_fpr(vm_o);
        free_alloc_fpr(r1);
        free_alloc_fpr(r2);
    } else { /* f64: reuse pre-allocated ftemps to stay within pool limit */
        /* Free unused ve/vo/te/to2, reuse as temp FPRs */
        free_alloc_fpr(te);
        free_alloc_fpr(to2);
        /* ve, vo reused as temp FPRs for fp ops */
        IR2_OPND g0 = ra_alloc_itemp(), g1 = ra_alloc_itemp();
        IR2_OPND g2 = ra_alloc_itemp(), g3 = ra_alloc_itemp();
        la_vpickve2gr_d(g0, vn_re, 0);
        la_vpickve2gr_d(g1, vn_re, 1);
        la_vpickve2gr_d(g2, vm_im, 0);
        la_vpickve2gr_d(g3, vm_im, 1);
        /* ve, vo = va, vb; allocate 2 more FPRs for vc, vd2 → total 4 new, 6 peak */
        la_movgr2fr_d(ve, g0);
        la_movgr2fr_d(vo, g1); /* ve=va, vo=vb */
        IR2_OPND vc = ra_alloc_ftemp(), vd22 = ra_alloc_ftemp();
        la_movgr2fr_d(vc, g2);
        la_movgr2fr_d(vd22, g3);
        if (is270) {
            la_fadd_d(ve, ve, vd22);
            la_fsub_d(vo, vo, vc);
        } else {
            la_fsub_d(ve, ve, vd22);
            la_fadd_d(vo, vo, vc);
        }
        la_movfr2gr_d(g0, ve);
        la_movfr2gr_d(g1, vo);
        la_vinsgr2vr_d(vd, g0, 0);
        la_vinsgr2vr_d(vd, g1, 1);
        free_alloc_fpr(vc);
        free_alloc_fpr(vd22);
        free_alloc_fpr(ve);
        free_alloc_fpr(vo);
        free_alloc_gpr(g0);
        free_alloc_gpr(g1);
        free_alloc_gpr(g2);
        free_alloc_gpr(g3);
    }
    if (!is_q) la_vinsgr2vr_d(vd, zero_ir2_opnd, 1);
    store_fpr_dst(rd, vd);
    free_alloc_fpr(vd);
    free_alloc_fpr(vn_re);
    free_alloc_fpr(vm_im);
    if (size == 0) {
        free_alloc_fpr(ve);
        free_alloc_fpr(vo);
        free_alloc_fpr(te);
        free_alloc_fpr(to2);
    }
    return true;
}

static bool trans_MSR_i_UAO(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_MSR_i_PAN(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_MSR_i_SPSEL(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_MSR_i_SBSS(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_MSR_i_DIT(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_MSR_i_TCO(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_MSR_i_DAIFSET(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_MSR_i_DAIFCLEAR(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_MSR_i_SVCR(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static void lata_helper_access_check_sysReg(DisasContext* ctx, void* la_ri, uint32_t key, uint32_t syndrome, uint32_t isread)
{
    IR2_OPND temp = ra_alloc_itemp();
    li_d(temp, ctx->base->pc_next);
    la_st_d(temp, env_ir2_opnd, env_offset_pc());
    lata_gen_call_helper_prologue(tcg_ctx);

    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    li_d(a1_ir2_opnd, key);
    li_d(a2_ir2_opnd, syndrome);
    li_d(a3_ir2_opnd, isread);
    li_d(temp, (uint64_t)helper_access_check_cp_reg);
    la_jirl(ra_ir2_opnd, temp, 0);

    li_d(temp, (uint64_t)&la_ri);
    la_st_d(a0_ir2_opnd, temp, 0);

    lata_gen_call_helper_epilogue(tcg_ctx);
    free_alloc_gpr(temp);

    return;
}

static void lata_helper_get_sysReg(DisasContext* ctx, uint32_t key, int rt, void* la_ri)
{
    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND no_lookup = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND set_reg = ir2_opnd_new_type(IR2_OPND_LABEL);
    li_d(temp, ctx->base->pc_next);
    la_st_d(temp, env_ir2_opnd, env_offset_pc());
    lata_gen_call_helper_prologue(tcg_ctx);

    IR2_OPND ri_isnull = ra_alloc_itemp();
    li_d(ri_isnull, (uint64_t)la_ri);
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    la_bnez(ri_isnull, no_lookup);

    /* la_ri == NULL, helper_lookup_cp_reg */
    li_d(a1_ir2_opnd, key);
    li_d(temp, (uint64_t)helper_lookup_cp_reg);
    la_jirl(ra_ir2_opnd, temp, 0);
    la_mov64(a1_ir2_opnd, a0_ir2_opnd);
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    la_b(set_reg);

    /* la_ri != NULL */
    la_label(no_lookup);
    la_mov64(a1_ir2_opnd, ri_isnull);

    /* helper_get_cp_reg64 */
    la_label(set_reg);
    li_d(temp, (uint64_t)helper_get_cp_reg64);
    la_jirl(ra_ir2_opnd, temp, 0);

    la_st_d(a0_ir2_opnd, env_ir2_opnd, env_offset_gpr(rt));

    lata_gen_call_helper_epilogue(tcg_ctx);
    free_alloc_gpr(temp);
    free_alloc_gpr(ri_isnull);

    return;
}

static void lata_helper_set_sysReg(DisasContext* ctx, uint32_t key, int rt, void* la_ri)
{
    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND no_lookup = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND set_reg = ir2_opnd_new_type(IR2_OPND_LABEL);
    li_d(temp, ctx->base->pc_next);
    la_st_d(temp, env_ir2_opnd, env_offset_pc());
    lata_gen_call_helper_prologue(tcg_ctx);

    IR2_OPND ri_isnull = ra_alloc_itemp();
    li_d(ri_isnull, (uint64_t)la_ri);
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    la_bnez(ri_isnull, no_lookup);

    /* la_ri == NULL, helper_lookup_cp_reg */
    li_d(a1_ir2_opnd, key);
    li_d(temp, (uint64_t)helper_lookup_cp_reg);
    la_jirl(ra_ir2_opnd, temp, 0);
    la_mov64(a1_ir2_opnd, a0_ir2_opnd);
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    la_b(set_reg);

    /* la_ri != NULL */
    la_label(no_lookup);
    la_mov64(a1_ir2_opnd, ri_isnull);

    la_label(set_reg);
    la_ld_d(a2_ir2_opnd, env_ir2_opnd, env_offset_gpr(rt));
    li_d(temp, (uint64_t)helper_set_cp_reg64);
    la_jirl(ra_ir2_opnd, temp, 0);

    lata_gen_call_helper_epilogue(tcg_ctx);
    free_alloc_gpr(temp);
    return;
}

static void lata_helper_dc_zva(DisasContext* s, int rt)
{
    IR2_OPND temp = ra_alloc_itemp();
    li_d(temp, s->base->pc_next);
    la_st_d(temp, env_ir2_opnd, env_offset_pc());
    lata_gen_call_helper_prologue(tcg_ctx);

    if (s->mte_active[0]) {
        lata_unallocated_encoding(s);
        return;
    } else {
        la_ld_d(temp, env_ir2_opnd, env_offset_gpr(rt));
        lata_clean_data_tbi(s, &temp, &temp, s->tbid);
    }

    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    la_mov64(a1_ir2_opnd, temp);
    li_d(temp, (uint64_t)helper_dc_zva);
    la_jirl(ra_ir2_opnd, temp, 0);

    lata_gen_call_helper_epilogue(tcg_ctx);
    free_alloc_gpr(temp);
    return;
}

static G_NORETURN void never_reach(const char* msg)
{
    lsassertm(0, "%s\n", msg);
}

static void gen_never_reach(DisasContext* ctx, const char* msg)
{
    IR2_OPND temp = ra_alloc_itemp();

    li_d(a0_ir2_opnd, (uint64_t)msg);
    li_d(temp, (uint64_t)never_reach);
    la_jirl(ra_ir2_opnd, temp, 0);

    free_alloc_gpr(temp);

    return;
}

/* MRS - move from system register
 * MSR (register) - move to system register
 * SYS
 * SYSL
 * These are all essentially the same insn in 'read' and 'write'
 * versions, with varying op0 fields.
 */
static void handle_sys(DisasContext* s, bool isread,
    unsigned int op0, unsigned int op1, unsigned int op2,
    unsigned int crn, unsigned int crm, unsigned int rt)
{
    uint32_t key = ENCODE_AA64_CP_REG(CP_REG_ARM64_SYSREG_CP,
        crn, crm, op0, op1, op2);
    const ARMCPRegInfo* ri = get_arm_cp_reginfo(s->cp_regs, key);
    bool need_exit_tb = false;
    void* la_ri = NULL;

    if (!ri) {
        /* Unknown register; this might be a guest error or a QEMU
         * unimplemented feature.
         */
        gen_never_reach(s, "Unknown register");
        return;
    }

    /* Check access permissions */
    if (!cp_access_ok(s->current_el, ri, isread)) {
        lata_unallocated_encoding(s);
        return;
    }

    if (ri->accessfn || (ri->fgt && s->fgt_active)) {
        /* Emit code to perform further access permissions checks at
         * runtime; this may result in an exception.
         */
        uint32_t syndrome;
        syndrome = syn_aa64_sysregtrap(op0, op1, op2, crn, crm, rt, isread);
        lata_gen_a64_update_pc(s, 0);
        lata_helper_access_check_sysReg(s, la_ri, key, syndrome, isread);
    } else if (ri->type & ARM_CP_RAISES_EXC) {
        /*
         * The readfn or writefn might raise an exception;
         * synchronize the CPU state in case it does.
         */
        lata_unallocated_encoding(s);
        return;
    }

    IR2_OPND reg_t;
    if (clearGprHigh && !isread && arm_la_map[rt] >= 0 && rt != 31) {
        clear_gpr_high(rt);
    }
    /* Handle special cases first */
    switch (ri->type & ARM_CP_SPECIAL_MASK) {
        case 0:
            break;
        case ARM_CP_NOP:
            return;
        case ARM_CP_NZCV:
            // tcg_rt = cpu_reg(s, rt);
            if (isread) {
                // gen_get_nzcv(tcg_rt);
                reg_t = alloc_gpr_dst(rt);
                la_armmfflag(reg_t, 0x39);
                la_bstrpick_d(reg_t, reg_t, 31, 0);

                store_gpr_dst(rt, reg_t);
            } else {
                reg_t = alloc_gpr_src(rt);
                la_armmtflag(reg_t, 0x39);
            }
            free_alloc_gpr(reg_t);
            return;
        case ARM_CP_CURRENTEL:
            lata_unallocated_encoding(s);
            return;
            /* Reads as current EL value from pstate, which is
             * guaranteed to be constant by the tb flags.
             */
            return;
        case ARM_CP_DC_ZVA:
            lata_helper_dc_zva(s, rt);
            return;
        case ARM_CP_DC_GVA: {
            lata_unallocated_encoding(s);
            return;
        }
            return;
        case ARM_CP_DC_GZVA: {
            lata_unallocated_encoding(s);
            return;
        }
            return;
        default:
            g_assert_not_reached();
    }
    if ((ri->type & ARM_CP_FPU) && !fp_access_check_only(s)) {
        lata_unallocated_encoding(s);
        return;
        return;
    } else if ((ri->type & ARM_CP_SVE) && !sve_access_check(s)) {
        assert(0);
        return;
    } else if ((ri->type & ARM_CP_SME) && !sme_access_check(s)) {
        assert(0);
        return;
    }

    if (ri->type & ARM_CP_IO) {
        assert(0);
        /* I/O operations must end the TB here (whether read or write) */
    }

    if (isread) {
        reg_t = alloc_gpr_dst(rt);
        if (ri->type & ARM_CP_CONST) {
            li_d(reg_t, ri->resetvalue);
            store_gpr_dst(rt, reg_t);
        } else if (ri->readfn) {
            lata_helper_get_sysReg(s, key, rt, la_ri);
        } else {
            if (ri->fieldoffset > 0x7ff) {
                IR2_OPND temp = ra_alloc_itemp();
                li_d(temp, ri->fieldoffset);
                la_add_d(temp, env_ir2_opnd, temp);
                la_ld_d(reg_t, temp, 0);
                free_alloc_gpr(temp);
            } else {
                la_ld_d(reg_t, env_ir2_opnd, ri->fieldoffset);
            }
            store_gpr_dst(rt, reg_t);
        }
        free_alloc_gpr(reg_t);
    } else {
        reg_t = alloc_gpr_src(rt);
        if (ri->type & ARM_CP_CONST) {
            assert(0); /* 需要释放reg_t */
            return;
        } else if (ri->writefn) {
            lata_helper_set_sysReg(s, key, rt, la_ri);
        } else {
            if (ri->fieldoffset > 0x7ff) {
                IR2_OPND temp = ra_alloc_itemp();
                li_d(temp, ri->fieldoffset);
                la_add_d(temp, env_ir2_opnd, temp);
                la_st_d(reg_t, temp, 0);
                free_alloc_gpr(temp);
            } else {
                la_st_d(reg_t, env_ir2_opnd, ri->fieldoffset);
            }
        }

        free_alloc_gpr(reg_t);
    }

    if (isread && arm_la_map[rt] >= 0 && rt != 31 && clearGprHigh) {
        set_w_write_flag(rt, TRUE);
    }

    if (!isread && !(ri->type & ARM_CP_SUPPRESS_TB_END)) {
        /*
         * A write to any coprocessor register that ends a TB
         * must rebuild the hflags for the next TB.
         */
        // gen_rebuild_hflags(s);

        /*
         * We default to ending the TB on a coprocessor register write,
         * but allow this to be suppressed by the register definition
         * (usually only necessary to work around guest bugs).
         */
        need_exit_tb = true;
    }
    if (need_exit_tb) {
        s->base->is_jmp = DISAS_UPDATE_EXIT;
    }
}

static bool trans_SYS(DisasContext* s)
{
    arg_SYS* a = &(s->arg.f_decode_insn3218);
    handle_sys(s, a->l, a->op0, a->op1, a->op2, a->crn, a->crm, a->rt);
    return true;
}

static bool trans_SVC(DisasContext* s)
{
    arg_i* a = &(s->arg.f_i);
    lata_debug_note_tu_boundary(LATA_TU_BOUNDARY_SVC);

    if (clearGprHigh) {
        for (int i = 0; i < 32; ++i) {
            if (arm_la_map[i] >= 0) {
                clear_gpr_high_for_boundary(i);
            }
        }
    }

    /*
     * For SVC, HVC and SMC we advance the single-step state
     * machine before taking the exception. This is architecturally
     * mandated, to ensure that single-stepping a system call
     * instruction works properly.
     */
    IR2_OPND temp = ra_alloc_itemp();

    li_d(temp, s->base->pc_next);
    la_st_d(temp, env_ir2_opnd, env_offset_pc());
    lata_gen_call_helper_prologue(tcg_ctx);

    // CPUARMState *env, uint32_t excp, uint32_t syndrome
    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    li_d(a1_ir2_opnd, EXCP_SWI);
    li_d(a2_ir2_opnd, syn_aa64_svc(a->imm));

    li_d(temp, (uint64_t)helper_exception_with_syndrome);
    la_jirl(ra_ir2_opnd, temp, 0);

    s->base->is_jmp = DISAS_NORETURN;
    free_alloc_gpr(temp);
    return true;
}

static bool trans_HVC(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_SMC(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_BRK(DisasContext* s)
{
    arg_i* a = &(s->arg.f_i);
    if (clearGprHigh) {
        for (int i = 0; i < 32; ++i) {
            if (arm_la_map[i] >= 0) {
                clear_gpr_high_for_boundary(i);
            }
        }
    }

    IR2_OPND temp = ra_alloc_itemp();

    li_d(temp, s->base->pc_next);
    la_st_d(temp, env_ir2_opnd, env_offset_pc());
    lata_gen_call_helper_prologue(tcg_ctx);

    la_mov64(a0_ir2_opnd, env_ir2_opnd);
    li_d(a1_ir2_opnd, EXCP_BKPT);
    li_d(a2_ir2_opnd, syn_aa64_bkpt(a->imm));

    li_d(temp, (uint64_t)helper_exception_with_syndrome);
    la_jirl(ra_ir2_opnd, temp, 0);

    free_alloc_gpr(temp);
    return true;
}

static bool trans_HLT(DisasContext* s)
{
    /*
     * HLT. This has two purposes.
     * Architecturally, it is an external halting debug instruction.
     * Since QEMU doesn't implement external debug, we treat this as
     * it is required for halting debug disabled: it will UNDEF.
     * Secondly, "HLT 0xf000" is the A64 semihosting syscall instruction.
     */
    lata_unallocated_encoding(s);
    return true;
}
/*
 * Compute the ISS.SF bit for syndrome information if an exception
 * is taken on a load or store. This indicates whether the instruction
 * is accessing a 32-bit or 64-bit register. This logic is derived
 * from the ARMv8 specs for LDR (Shared decode for all encodings).
 */
static bool ldst_iss_sf(int size, bool sign, bool ext)
{

    if (sign) {
        /*
         * Signed loads are 64 bit results if we are not going to
         * do a zero-extend from 32 to 64 after the load.
         * (For a store, sign and ext are always false.)
         */
        return !ext;
    } else {
        /* Unsigned loads/stores work at the specified size */
        return size == MO_64;
    }
}

static void lata_load_gpr_by_size(IR2_OPND* reg_t, IR2_OPND* reg_n, int64_t offset,
                                  uint64_t sz, uint64_t sign)
{
    switch (sz) {
        case 0:
            if (sign) {
                la_ld_b(*reg_t, *reg_n, offset);
            } else {
                la_ld_bu(*reg_t, *reg_n, offset);
            }
            break;
        case 1:
            if (sign) {
                la_ld_h(*reg_t, *reg_n, offset);
            } else {
                la_ld_hu(*reg_t, *reg_n, offset);
            }
            break;
        case 2:
            if (sign) {
                la_ld_w(*reg_t, *reg_n, offset);
            } else {
                la_ld_wu(*reg_t, *reg_n, offset);
            }
            break;
        case 3:
            la_ld_d(*reg_t, *reg_n, offset);
            break;
        default:
            assert(0);
    }
}

static void lata_store_gpr_by_size(IR2_OPND* reg_t, IR2_OPND* reg_n, int64_t offset, uint64_t sz)
{
    switch (sz) {
        case 0:
            la_st_b(*reg_t, *reg_n, offset);
            break;
        case 1:
            la_st_h(*reg_t, *reg_n, offset);
            break;
        case 2:
            la_st_w(*reg_t, *reg_n, offset);
            break;
        case 3:
            la_st_d(*reg_t, *reg_n, offset);
            break;
        default:
            assert(0);
    }
}

static void lata_load_exclusive(DisasContext* s, int rt, int rt2, int rn,
    int size, bool is_pair)
{
    s->is_ldex = true;
    IR2_OPND reg_n = alloc_gpr_src_sp(rn);
    IR2_OPND reg_t = alloc_gpr_dst(rt);
    IR2_OPND reg_t2;

    if (clearGprHigh && arm_la_map[rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(rn);
    }

    g_assert(size <= 3);
    if (is_pair) {
        g_assert(size >= 2);
        reg_t2 = alloc_gpr_dst(rt2);
        if (size == 2) {
            if (s->be_data == MO_LE) {
                la_ll_d(reg_t, reg_n, 0);
                la_bstrpick_d(reg_t2, reg_t, 63, 32);
                la_bstrpick_d(reg_t, reg_t, 31, 0);
            } else {
                la_ll_d(reg_t2, reg_n, 0);
                la_bstrpick_d(reg_t, reg_t2, 63, 32);
                la_bstrpick_d(reg_t2, reg_t2, 31, 0);
            }
        } else {
            /* size==3 (64-bit pair): LL.D for first value + LD.D for second.
             * LLbit is set for the first 8 bytes; SC.Q later checks it for 128-bit store. */
            if (s->be_data == MO_LE) {
                la_ll_d(reg_t, reg_n, 0);
                la_ld_d(reg_t2, reg_n, 8);
            } else {
                la_ll_d(reg_t2, reg_n, 0);
                la_ld_d(reg_t, reg_n, 8);
            }
        }
        store_fpr_dst(rt2, reg_t2);
        free_alloc_gpr(reg_t2);
    } else {
        // if(size == 2){
        //     la_ll_w(reg_t, reg_n, 0);
        // }else{
        //     la_ll_d(reg_t, reg_n, 0);
        // }
        /*  LL支持4字节和8字节，1字节和2字节使用普通的访存指令
            在单线程下不会出现问题。
            */
        IR2_OPND aligned_mem = ra_alloc_itemp();
        IR2_OPND offset = ra_alloc_itemp();
        switch (size) {
            case 0: // deal with the situation when memory is not aligned
                la_bstrpick_d(offset, reg_n, 2, 0);
                la_or(aligned_mem, reg_n, zero_ir2_opnd);
                la_bstrins_d(aligned_mem, zero_ir2_opnd, 2, 0);
                la_ll_d(reg_t, aligned_mem, 0);
                la_st_d(reg_t, env_ir2_opnd, env_offset(exclusive_memdata));
                la_slli_d(offset, offset, 3);
                la_srl_d(reg_t, reg_t, offset);
                la_bstrpick_d(reg_t, reg_t, 7, 0);
                break;
            case 1:
                la_bstrpick_d(offset, reg_n, 2, 0);
                la_or(aligned_mem, reg_n, zero_ir2_opnd);
                la_bstrins_d(aligned_mem, zero_ir2_opnd, 2, 0);
                la_ll_d(reg_t, aligned_mem, 0);
                la_st_d(reg_t, env_ir2_opnd, env_offset(exclusive_memdata));
                la_slli_d(offset, offset, 3);
                la_srl_d(reg_t, reg_t, offset);
                la_bstrpick_d(reg_t, reg_t, 15, 0);
                break;
            case 2:
                la_ll_w(reg_t, reg_n, 0);
                la_bstrpick_d(reg_t, reg_t, 31, 0);
                break;
            case 3:
                la_ll_d(reg_t, reg_n, 0);
                break;
        }
        free_alloc_gpr(aligned_mem);
        free_alloc_gpr(offset);
    }

    if (arm_la_map[rt] >= 0 && rt != 31 && clearGprHigh) {
        set_w_write_flag(rt, TRUE);
    }

    store_gpr_dst(rt, reg_t);
    free_alloc_gpr(reg_t);
    free_alloc_gpr(reg_n);
}

static void lata_store_exclusive(DisasContext* s, int rs, int rt, int rt2,
    int rn, int size, int is_pair)
{
    assert(!(rs == rn && rn != 31));

    IR2_OPND reg_s = alloc_gpr_dst(rs);
    IR2_OPND reg_n = alloc_gpr_src_sp(rn);
    IR2_OPND reg_t = alloc_gpr_src(rt);
    IR2_OPND reg_t2;

    if (clearGprHigh && arm_la_map[rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(rn);
    }

    if (clearGprHigh && size == 3 && rt != 31 && arm_la_map[rt] >= 0) {
        clear_gpr_high(rt);
    }

    if (is_pair) {
        assert(rs != rt && rs != rt2);
        reg_t2 = alloc_gpr_src(rt2);
        if (size == 2) {
            if (s->be_data == MO_LE) {
                la_bstrpick_d(reg_s, reg_t, 31, 0);
                la_bstrins_d(reg_s, reg_t2, 63, 32);
                la_sc_d(reg_s, reg_n, 0);
            } else {
                la_bstrpick_d(reg_s, reg_t2, 31, 0);
                la_bstrins_d(reg_s, reg_t, 63, 32);
                la_sc_d(reg_s, reg_n, 0);
            }
        } else {
            /* size==3 (64-bit pair): use LL->SC per element.
             * Re-establish LLbit before each SC since SC consumes it. */
            IR2_OPND tmp = ra_alloc_itemp();
            IR2_OPND tmp2 = ra_alloc_itemp();
            if (s->be_data == MO_LE) {
                la_or(reg_s, reg_t, zero_ir2_opnd);
                la_sc_d(reg_s, reg_n, 0);
                la_xori(reg_s, reg_s, 1); /* invert LoongArch SC result to ARM convention */

                la_or(tmp, reg_t2, zero_ir2_opnd);
                la_ll_d(tmp2, reg_n, 8);
                la_sc_d(tmp, reg_n, 8);
                la_xori(tmp, tmp, 1);
                la_or(reg_s, reg_s, tmp); /* OR: fail if either element fails */
            } else {
                la_or(reg_s, reg_t2, zero_ir2_opnd);
                la_sc_d(reg_s, reg_n, 0);
                la_xori(reg_s, reg_s, 1);

                la_or(tmp, reg_t, zero_ir2_opnd);
                la_ll_d(tmp2, reg_n, 8);
                la_sc_d(tmp, reg_n, 8);
                la_xori(tmp, tmp, 1);
                la_or(reg_s, reg_s, tmp);
            }
            free_alloc_gpr(tmp);
            free_alloc_gpr(tmp2);
        }
        free_alloc_gpr(reg_t2);
    } else {
        assert(rs != rt);
        /*  LL/SC支持4字节和8字节，1字节和2字节使用普通的访存指令
            在单线程下不会出现问题。
        */
        IR2_OPND offset = ra_alloc_itemp();
        IR2_OPND aligned_mem = ra_alloc_itemp();
        IR2_OPND mem_data = ra_alloc_itemp();
        switch (size) {
            case 0:
                /* get aligned memory*/
                la_bstrpick_d(offset, reg_n, 2, 0);
                la_slli_d(offset, offset, 3);
                la_or(aligned_mem, reg_n, zero_ir2_opnd);
                la_bstrins_d(aligned_mem, zero_ir2_opnd, 2, 0);

                /*merge data*/
                la_bstrpick_d(reg_s, reg_t, 7, 0);
                la_sll_d(reg_s, reg_s, offset);

                li_d(mem_data, 0xff);
                la_sll_d(offset, mem_data, offset);
                la_ld_d(mem_data, env_ir2_opnd, env_offset(exclusive_memdata));
                la_andn(mem_data, mem_data, offset);

                la_or(reg_s, reg_s, mem_data);

                la_sc_d(reg_s, aligned_mem, 0);
                la_xori(reg_s, reg_s, 1);
                break;
            case 1:
                /* get aligned memory*/
                la_bstrpick_d(offset, reg_n, 2, 0);
                la_slli_d(offset, offset, 3);
                la_or(aligned_mem, reg_n, zero_ir2_opnd);
                la_bstrins_d(aligned_mem, zero_ir2_opnd, 2, 0);

                /*merge data*/
                la_bstrpick_d(reg_s, reg_t, 15, 0);
                la_sll_d(reg_s, reg_s, offset);

                li_d(mem_data, 0xffff);
                la_sll_d(offset, mem_data, offset);
                la_ld_d(mem_data, env_ir2_opnd, env_offset(exclusive_memdata));
                la_andn(mem_data, mem_data, offset);

                la_or(reg_s, reg_s, mem_data);

                la_sc_d(reg_s, aligned_mem, 0);
                la_xori(reg_s, reg_s, 1);
                break;
            case 2:
                la_or(reg_s, reg_t, zero_ir2_opnd);
                la_sc_w(reg_s, reg_n, 0);
                la_xori(reg_s, reg_s, 1); /* 龙芯的SC返回值和arm相反 */
                break;
            case 3:
                la_or(reg_s, reg_t, zero_ir2_opnd);
                la_sc_d(reg_s, reg_n, 0);
                la_xori(reg_s, reg_s, 1); /* 龙芯的SC返回值和arm相反 */
                break;
        }
        free_alloc_gpr(aligned_mem);
        free_alloc_gpr(offset);
        free_alloc_gpr(mem_data);
    }

    /*  the value of reg_s must be 0 or 1,
        it's no need to clear high bits.
    */
    if (arm_la_map[rs] >= 0 && rs != 31 && clearGprHigh) {
        set_w_write_flag(rs, TRUE);
    }

    store_gpr_dst(rs, reg_s);
    free_alloc_gpr(reg_s);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_t);
}

static bool trans_STXR(DisasContext* s)
{
    arg_stxr* a = &(s->arg.f_stxr);
    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }
    if (a->lasr) {
        lata_gen_mb();
    }
    lata_store_exclusive(s, a->rs, a->rt, a->rt2, a->rn, a->sz, false);
    return true;
}

static bool trans_LDXR(DisasContext* s)
{
    arg_stxr* a = &(s->arg.f_stxr);
    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }
    lata_load_exclusive(s, a->rt, a->rt2, a->rn, a->sz, false);
    if (a->lasr) {
        lata_gen_mb();
    }
    return true;
}

static bool trans_STLR(DisasContext* s)
{
    arg_stlr* a = &(s->arg.f_stlr);
    bool iss_sf = ldst_iss_sf(a->sz, false, false);
    int offset;
    /*
     * StoreLORelease is the same as Store-Release for QEMU, but
     * needs the feature-test.
     */
    if (!a->lasr && !dc_isar_feature(aa64_lor, s)) {
        return false;
    }
    /* Generate ISS for non-exclusive accesses including LASR.  */
    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }
    lata_gen_mb();
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND reg_t = alloc_gpr_src(a->rt);

    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (clearGprHigh && a->sz == 3 && arm_la_map[a->rt] >= 0 && a->rt != 31) {
        clear_gpr_high(a->rt);
    }

    if (a->lasr) { /* no offset */
        offset = 0;
        // if(iss_sf){
        //     la_st_d(reg_t, reg_n, offset);
        // }else{
        //     la_st_w(reg_t, reg_n, offset);
        // }
        switch (a->sz) {
            case 0:
                la_st_b(reg_t, reg_n, offset);
                break;
            case 1:
                la_st_h(reg_t, reg_n, offset);
                break;
            case 2:
                la_st_w(reg_t, reg_n, offset);
                break;
            case 3:
                la_st_d(reg_t, reg_n, offset);
                break;
            default:
                break;
        }
    } else { /* pre-index */
        lata_unallocated_encoding(s);
        return true;
        offset = -(1 << a->sz);
        la_addi_d(reg_n, reg_n, offset);
        if (iss_sf) {
            la_st_d(reg_t, reg_n, 0);
        } else {
            la_st_w(reg_t, reg_n, 0);
        }
        store_gpr_dst(a->rn, reg_n);
    }

    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_t);
    return true;
}

static bool trans_LDAR(DisasContext* s)
{
    arg_stlr* a = &(s->arg.f_stlr);
    IR2_OPND reg_t = alloc_gpr_dst(a->rt);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);

    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    /* LoadLOAcquire is the same as Load-Acquire for QEMU.  */
    if (!a->lasr && !dc_isar_feature(aa64_lor, s)) {
        return false;
    }
    /* Generate ISS for non-exclusive accesses including LASR.  */
    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    switch (a->sz) {
        case 0:
            la_ld_bu(reg_t, reg_n, 0);
            break;
        case 1:
            la_ld_hu(reg_t, reg_n, 0);
            break;
        case 2:
            la_ld_wu(reg_t, reg_n, 0);
            break;
        case 3:
            la_ld_d(reg_t, reg_n, 0);
            break;
    }

    lata_gen_mb();

    if (a->rt != 31 && arm_la_map[a->rt] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rt, TRUE);
    }

    store_gpr_dst(a->rt, reg_t);
    free_alloc_gpr(reg_t);
    free_alloc_gpr(reg_n);
    return true;
}

static bool trans_STXP(DisasContext* s)
{
    arg_stxr* a = &(s->arg.f_stxr);
    lata_store_exclusive(s, a->rs, a->rt, a->rt2, a->rn, a->sz, true);
    return true;
}

static bool trans_LDXP(DisasContext* s)
{
    arg_stxr* a = &(s->arg.f_stxr);
    lata_load_exclusive(s, a->rt, a->rt2, a->rn, a->sz, true);
    return true;
}

static bool trans_CASP(DisasContext* s)
{
    int acquire = extract32(s->insn, 22, 1);
    int release = extract32(s->insn, 15, 1);
    arg_CAS* a = &(s->arg.f_decode_insn3221);

    if (!dc_isar_feature(aa64_atomics, s)) {
        return false;
    }
    if ((a->rs & 1) || (a->rt & 1) || a->sz < 2) {
        lata_unallocated_encoding(s);
        return true;
    }

    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND cmp_lo_in = alloc_gpr_src(a->rs);
    IR2_OPND cmp_hi_in = alloc_gpr_src(a->rs + 1);
    IR2_OPND new_lo_in = alloc_gpr_src(a->rt);
    IR2_OPND new_hi_in = alloc_gpr_src(a->rt + 1);
    IR2_OPND cmp_lo = ra_alloc_itemp();
    IR2_OPND cmp_hi = ra_alloc_itemp();
    IR2_OPND new_lo = ra_alloc_itemp();
    IR2_OPND new_hi = ra_alloc_itemp();
    IR2_OPND old_lo = alloc_gpr_dst(a->rs);
    IR2_OPND old_hi = alloc_gpr_dst(a->rs + 1);
    IR2_OPND sc_lo = ra_alloc_itemp();
    IR2_OPND sc_hi = ra_alloc_itemp();
    IR2_OPND label_ll = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND label_exit = ir2_opnd_new_type(IR2_OPND_LABEL);

    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    la_or(cmp_lo, cmp_lo_in, zero_ir2_opnd);
    la_or(cmp_hi, cmp_hi_in, zero_ir2_opnd);
    la_or(new_lo, new_lo_in, zero_ir2_opnd);
    la_or(new_hi, new_hi_in, zero_ir2_opnd);

    if (release) {
        la_dbar(0);
    }

    if (a->sz == 3) {
        /*
         * CASP X uses one LL.D on the low half followed by SC.Q.  Per the
         * LoongArch SC.Q definition, rd/rk provide the low/high 64-bit store
         * data and rd is overwritten with the success flag, so both desired
         * values must be copied to temporaries before the store-conditional.
         * DBAR 0 around the LL/SC pair is conservative, but keeps the AArch64
         * atomic ordering model correct while we expose FEAT_LSE.
         */
        la_label(label_ll);
        la_dbar(0);
        la_ll_d(old_lo, reg_n, 0);
        la_ld_d(old_hi, reg_n, 8);
        la_bne(old_lo, cmp_lo, label_exit);
        la_bne(old_hi, cmp_hi, label_exit);
        la_or(sc_lo, new_lo, zero_ir2_opnd);
        la_or(sc_hi, new_hi, zero_ir2_opnd);
        la_sc_q(sc_lo, sc_hi, reg_n);
        la_beqz(sc_lo, label_ll);
        la_dbar(0);
    } else {
        /*
         * CASP W compares and replaces two adjacent 32-bit words atomically.
         * Pack them into one 64-bit LL/SC word in little-endian order:
         * low word at [addr], high word at [addr + 4].
         */
        la_bstrpick_d(cmp_lo, cmp_lo, 31, 0);
        la_bstrpick_d(cmp_hi, cmp_hi, 31, 0);
        la_slli_d(cmp_hi, cmp_hi, 32);
        la_or(cmp_lo, cmp_lo, cmp_hi);

        la_bstrpick_d(new_lo, new_lo, 31, 0);
        la_bstrpick_d(new_hi, new_hi, 31, 0);
        la_slli_d(new_hi, new_hi, 32);
        la_or(new_lo, new_lo, new_hi);

        la_label(label_ll);
        la_dbar(0);
        la_ll_d(old_lo, reg_n, 0);
        la_bne(old_lo, cmp_lo, label_exit);
        la_or(sc_lo, new_lo, zero_ir2_opnd);
        la_sc_d(sc_lo, reg_n, 0);
        la_beqz(sc_lo, label_ll);
        la_dbar(0);
        la_label(label_exit);
        la_bstrpick_d(old_hi, old_lo, 63, 32);
        la_bstrpick_d(old_lo, old_lo, 31, 0);
        goto casp_done;
    }

    la_label(label_exit);

casp_done:
    if (acquire) {
        la_dbar(0);
    }

    if (a->sz == 2) {
        la_bstrpick_d(old_lo, old_lo, 31, 0);
        la_bstrpick_d(old_hi, old_hi, 31, 0);
    }

    store_gpr_dst(a->rs, old_lo);
    store_gpr_dst(a->rs + 1, old_hi);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(cmp_lo_in);
    free_alloc_gpr(cmp_hi_in);
    free_alloc_gpr(new_lo_in);
    free_alloc_gpr(new_hi_in);
    free_alloc_gpr(cmp_lo);
    free_alloc_gpr(cmp_hi);
    free_alloc_gpr(new_lo);
    free_alloc_gpr(new_hi);
    free_alloc_gpr(old_lo);
    free_alloc_gpr(old_hi);
    free_alloc_gpr(sc_lo);
    free_alloc_gpr(sc_hi);
    return true;
}

static bool trans_CAS(DisasContext* s)
{
    int acquire = extract32(s->insn, 22, 1);
    int release = extract32(s->insn, 15, 1);

    if (!dc_isar_feature(aa64_atomics, s)) {
        return false;
    }

    arg_CAS* a = &(s->arg.f_decode_insn3221);
    IR2_OPND reg_s = alloc_gpr_src(a->rs);
    IR2_OPND reg_t = alloc_gpr_src(a->rt);
    IR2_OPND reg_n = alloc_gpr_src(a->rn);
    IR2_OPND src = ra_alloc_itemp();
    IR2_OPND dest = ra_alloc_itemp();
    IR2_OPND label_exit = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND label_ll = ir2_opnd_new_type(IR2_OPND_LABEL);

    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    if (release) {
        la_dbar(0);
    }

    if (a->sz == 3) {
        la_or(src, reg_s, zero_ir2_opnd);
        la_label(label_ll);
        la_ll_d(reg_s, reg_n, 0);
        la_bne(src, reg_s, label_exit);
        la_or(dest, reg_t, zero_ir2_opnd);
        la_sc_d(dest, reg_n, 0);
        la_beqz(dest, label_ll);
    } else if (a->sz == 2) {
        la_bstrpick_d(src, reg_s, 31, 0);
        la_label(label_ll);
        la_ll_w(reg_s, reg_n, 0);
        la_bstrpick_d(reg_s, reg_s, 31, 0);
        la_bne(src, reg_s, label_exit);
        la_or(dest, reg_t, zero_ir2_opnd);
        la_sc_w(dest, reg_n, 0);
        la_beqz(dest, label_ll);
    } else if (a->sz == 1) {
        IR2_OPND offset = ra_alloc_itemp();
        IR2_OPND aligned_mem = ra_alloc_itemp();
        /*  mov tmp1, ws
            1:
            ldxr ws, [xn]
            cmp  ws, tmp1
            b.ne 2
            stxr tmp2, wt, [xn]
            cbnz tmp2,1
            2:
            ret
        */
        // mov
        la_bstrpick_d(src, reg_s, 15, 0);

        // ldxr ws, [xn]
        la_label(label_ll);
        la_bstrpick_d(offset, reg_n, 2, 0);
        la_or(aligned_mem, reg_n, zero_ir2_opnd);
        la_bstrins_d(aligned_mem, zero_ir2_opnd, 2, 0);
        la_ll_d(dest, aligned_mem, 0);
        la_slli_d(offset, offset, 3);
        la_srl_d(reg_s, dest, offset);
        la_bstrpick_d(reg_s, reg_s, 15, 0);

        // cmp  ws, tmp1 + b.ne 2
        la_bne(reg_s, src, label_exit);

        // stxr tmp2, wt, [xn]
        li_d(src, 0xffff);
        la_sll_d(src, src, offset);
        la_andn(src, dest, src);
        la_bstrpick_d(dest, reg_t, 15, 0); // Being able to run here means [xn] == ws,even wt == ws,it won't be changed.
        la_sll_d(dest, dest, offset);
        la_or(dest, src, dest);

        // src recover
        la_or(src, reg_s, zero_ir2_opnd);
        la_sc_d(dest, aligned_mem, 0);

        // cbnz tmp2,1
        la_beqz(dest, label_ll);
        free_alloc_gpr(offset);
        free_alloc_gpr(aligned_mem);
    } else {
        IR2_OPND offset = ra_alloc_itemp();
        IR2_OPND aligned_mem = ra_alloc_itemp();
        // mov
        la_bstrpick_d(src, reg_s, 7, 0);

        // ldxr ws, [xn]
        la_label(label_ll);
        la_bstrpick_d(offset, reg_n, 2, 0);
        la_or(aligned_mem, reg_n, zero_ir2_opnd);
        la_bstrins_d(aligned_mem, zero_ir2_opnd, 2, 0);
        la_ll_d(dest, aligned_mem, 0);
        la_slli_d(offset, offset, 3);
        la_srl_d(reg_s, dest, offset);
        la_bstrpick_d(reg_s, reg_s, 7, 0);

        // cmp  ws, tmp1 + b.ne 2
        la_bne(reg_s, src, label_exit);

        // stxr tmp2, wt, [xn]
        li_d(src, 0xff);
        la_sll_d(src, src, offset);
        la_andn(src, dest, src);
        la_bstrpick_d(dest, reg_t, 7, 0); // Being able to run here means [xn] == ws,even wt == ws,it won't be changed.
        la_sll_d(dest, dest, offset);
        la_or(dest, src, dest);

        // src recover
        la_or(src, reg_s, zero_ir2_opnd);
        la_sc_d(dest, aligned_mem, 0);

        // cbnz tmp2,1
        la_beqz(dest, label_ll);
        free_alloc_gpr(offset);
        free_alloc_gpr(aligned_mem);
    }

    la_label(label_exit);
    if (acquire) {
        la_dbar(0);
    }

    store_gpr_dst(a->rs, reg_s);
    free_alloc_gpr(reg_s);
    free_alloc_gpr(reg_t);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(src);
    free_alloc_gpr(dest);
    return true;
}

static bool trans_LD_lit(DisasContext* s)
{
    arg_ldlit* a = &(s->arg.f_ldlit);
    IR2_OPND reg_d = alloc_gpr_dst(a->rt);
    MemOp memop = a->sz + a->sign * MO_SIGN;
    uint64_t addr = s->pc_curr + a->imm;
    switch (memop) {
        case MO_64:
            // ld_d只能处理si12
            la_lu12i_w(reg_d, addr >> 12);
            if (addr & 0x800) {
                la_ori(reg_d, reg_d, addr & 0xfff);
                la_ld_d(reg_d, reg_d, 0);
            } else {
                la_ld_d(reg_d, reg_d, addr & 0x7ff);
            }

            break;
        default:
            lata_unallocated_encoding(s);
            return true;
            break;
    }

    if (arm_la_map[a->rt] >= 0 && a->rt != 31 && clearGprHigh) {
        set_w_write_flag(a->rt, TRUE);
    }

    store_gpr_dst(a->rt, reg_d);
    free_alloc_gpr(reg_d);
    return true;
}

static bool trans_LD_lit_v(DisasContext* s)
{
    /* Load register (literal), vector version */
    lata_unallocated_encoding(s);
    return true;
    return true;
}

static bool trans_STP(DisasContext* s)
{

    /*3 classes: Post-index , Pre-index and Signed offset
     *
     *               Post-index      Pre-index       Signed offset
     * postindex     true            false           false
     *   wback       true            true            false
     */

    arg_ldstpair* a = &(s->arg.f_ldstpair);
    int64_t offset = (int64_t)a->imm << a->sz;
    int dbytes = (8 << a->sz) / 8;
    if (a->w && (a->rt == a->rn || a->rt2 == a->rn) && a->rn != 31) {
        lata_unallocated_encoding(s);
        return true;
        return true;
    }

    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND reg_t = alloc_gpr_src(a->rt);
    IR2_OPND reg_t2 = alloc_gpr_src(a->rt2);
    IR2_OPND temp = ra_alloc_itemp();

    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (clearGprHigh && a->sz == 3 && arm_la_map[a->rt] >= 0 && a->rt != 31) {
        clear_gpr_high(a->rt);
    }

    if (clearGprHigh && a->sz == 3 && arm_la_map[a->rt2] >= 0 && a->rt2 != 31) {
        clear_gpr_high(a->rt2);
    }

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);

    if (!a->w && offset) { // wback = false && offset!=0
        la_addi_d(temp, reg_n, offset);
        switch (dbytes) {
            case 4:
                la_st_w(reg_t, temp, 0);
                la_st_w(reg_t2, temp, dbytes);
                break;
            case 8:
                la_st_d(reg_t, temp, 0);
                la_st_d(reg_t2, temp, dbytes);
                break;
            default:
                lata_unallocated_encoding(s);
                return true;
        }
    } else { // Pre-index or post-index
        if (!a->p && offset) {
            la_addi_d(reg_n, reg_n, offset);
        }

        switch (dbytes) {
            case 4:
                la_st_w(reg_t, reg_n, 0);
                la_st_w(reg_t2, reg_n, dbytes);
                break;
            case 8:
                la_st_d(reg_t, reg_n, 0);
                la_st_d(reg_t2, reg_n, dbytes);
                break;
            default:
                lata_unallocated_encoding(s);
                return true;
        }

        if (a->p && offset) {
            la_addi_d(reg_n, reg_n, offset);
        }
        if (a->w)
            store_gpr_dst(a->rn, reg_n);
    }

    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_t);
    free_alloc_gpr(reg_t2);
    free_alloc_gpr(temp);
    return true;
}

static bool trans_LDP(DisasContext* s)
{

    /*3 classes: Post-index , Pre-index and Signed offset
     *
     *               Post-index      Pre-index       Signed offset
     * postindex     true            false           false
     *   wback       true            true            false
     */

    arg_ldstpair* a = &(s->arg.f_ldstpair);
    int64_t offset = (int64_t)a->imm << a->sz;
    int dbytes = (8 << a->sz) / 8; // dbytes = datasize / 8;
    if (a->w && (a->rt == a->rn || a->rt2 == a->rn) && a->rn != 31) {
        lata_unallocated_encoding(s);
        return true;
        return true;
    }

    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND reg_t = alloc_gpr_dst(a->rt);
    IR2_OPND reg_t2 = alloc_gpr_dst(a->rt2);
    IR2_OPND temp = ra_alloc_itemp();

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);

    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (!a->w && offset) { // wback = false && offset!=0
        la_addi_d(temp, reg_n, offset);
        switch (dbytes) {
            case 4:
                if (a->sign) {
                    la_ld_w(reg_t, temp, 0);
                    la_ld_w(reg_t2, temp, dbytes);
                } else {
                    la_ld_wu(reg_t, temp, 0);
                    la_ld_wu(reg_t2, temp, dbytes);
                }
                break;
            case 8:
                la_ld_d(reg_t, temp, 0);
                la_ld_d(reg_t2, temp, dbytes);
                break;
            default:
                lata_unallocated_encoding(s);
                return true;
        }
    } else { // Pre-index or post-index
        if (!a->p && offset) {
            la_addi_d(reg_n, reg_n, offset);
        }

        switch (dbytes) {
            case 4:
                if (a->sign) {
                    if (a->rn != a->rt && a->rn != a->rt2) {
                        la_ld_w(reg_t, reg_n, 0);
                        la_ld_w(reg_t2, reg_n, dbytes);
                    } else { // read vs write
                        la_or(temp, reg_n, zero_ir2_opnd);
                        la_ld_w(reg_t, temp, 0);
                        la_ld_w(reg_t2, temp, dbytes);
                    }
                } else {
                    if (a->rn != a->rt && a->rn != a->rt2) {
                        la_ld_wu(reg_t, reg_n, 0);
                        la_ld_wu(reg_t2, reg_n, dbytes);
                    } else {
                        la_or(temp, reg_n, zero_ir2_opnd);
                        la_ld_wu(reg_t, temp, 0);
                        la_ld_wu(reg_t2, temp, dbytes);
                    }
                }
                break;
            case 8:
                if (a->rn != a->rt && a->rn != a->rt2) {
                    la_ld_d(reg_t, reg_n, 0);
                    la_ld_d(reg_t2, reg_n, dbytes);
                } else {
                    la_or(temp, reg_n, zero_ir2_opnd);
                    la_ld_d(reg_t, temp, 0);
                    la_ld_d(reg_t2, temp, dbytes);
                }
                break;
            default:
                assert(0);
        }

        if (a->p && offset) {
            la_addi_d(reg_n, reg_n, offset);
        }
        if (a->w)
            store_gpr_dst(a->rn, reg_n);
    }

    if (a->rt != 31 && arm_la_map[a->rt] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rt, TRUE);
    }

    if (a->rt != 31 && arm_la_map[a->rt2] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rt2, TRUE);
    }

    store_gpr_dst(a->rt, reg_t);
    store_gpr_dst(a->rt2, reg_t2);

    /* Force-store x30 to env after LDP to prevent register conflict
     * with ra_alloc_itemp() in subsequent indirect branch (RET/BR). */
    if (a->rt == 30) {
        la_st_d(reg_t, env_ir2_opnd, env_offset_gpr(30));
    }
    if (a->rt2 == 30) {
        la_st_d(reg_t2, env_ir2_opnd, env_offset_gpr(30));
    }

    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_t);
    free_alloc_gpr(reg_t2);
    free_alloc_gpr(temp);
    return true;
}

static bool trans_STP_v(DisasContext* s)
{
    /*3 classes: Post-index , Pre-index and Signed offset
     *
     *               Post-index      Pre-index       Signed offset
     * postindex     true            false           false
     *   wback       true            true            false
     */

    arg_ldstpair* a = &(s->arg.f_ldstpair);
    int64_t offset = (int64_t)a->imm << a->sz;
    int dbytes = (8 << a->sz) / 8; // dbytes = datasize / 8;

    /* TODO: CheckFPAdvSIMDEnabled64(s) */

    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND vreg_t = alloc_fpr_src(a->rt);
    IR2_OPND vreg_t2 = alloc_fpr_src(a->rt2);
    IR2_OPND temp = ra_alloc_itemp();

    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);

    if (!a->w && offset) { // wback = false && offset!=0
        IR2_OPND addr = addr_with_const_offset(reg_n, offset, temp);
        switch (dbytes) {
            case 4:
                fpu_store(vreg_t, addr, 0, 2, temp);
                fpu_store(vreg_t2, addr, dbytes, 2, temp);
                break;
            case 8:
                fpu_store(vreg_t, addr, 0, 3, temp);
                fpu_store(vreg_t2, addr, dbytes, 3, temp);
                break;
            case 16:
                vector_store(vreg_t, addr, 0, temp);
                vector_store(vreg_t2, addr, dbytes, temp);
                break;
            default:
                lata_unallocated_encoding(s);
                return true;
        }
    } else { // Pre-index or post-index
        if (!a->p && offset) {
            la_addi_d(reg_n, reg_n, offset);
        }

        switch (dbytes) {
            case 4:
                fpu_store(vreg_t, reg_n, 0, 2, temp);
                fpu_store(vreg_t2, reg_n, dbytes, 2, temp);
                break;
            case 8:
                fpu_store(vreg_t, reg_n, 0, 3, temp);
                fpu_store(vreg_t2, reg_n, dbytes, 3, temp);
                break;
            case 16:
                vector_store(vreg_t, reg_n, 0, temp);
                vector_store(vreg_t2, reg_n, dbytes, temp);
                break;
            default:
                lata_unallocated_encoding(s);
                return true;
        }

        if (a->p && offset) {
            la_addi_d(reg_n, reg_n, offset);
        }
        if (a->w)
            store_gpr_dst(a->rn, reg_n);
    }

    free_alloc_gpr(reg_n);
    free_alloc_fpr(vreg_t);
    free_alloc_fpr(vreg_t2);
    free_alloc_gpr(temp);
    return true;
}

static bool trans_LDP_v(DisasContext* s)
{
    /*3 classes: Post-index , Pre-index and Signed offset
     *
     *               Post-index      Pre-index       Signed offset
     * postindex     true            false           false
     *   wback       true            true            false
     */

    arg_ldstpair* a = &(s->arg.f_ldstpair);
    int64_t offset = (int64_t)a->imm << a->sz;
    int dbytes = (8 << a->sz) / 8; // dbytes = datasize / 8;
    /* TODO: CheckFPAdvSIMDEnabled64(s) */

    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND vreg_t = alloc_fpr_dst(a->rt);
    IR2_OPND vreg_t2 = alloc_fpr_dst(a->rt2);
    IR2_OPND temp = ra_alloc_itemp();
    bool high_clean_t = true;
    bool high_clean_t2 = true;

    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (!a->w && offset) { // wback = false && offset!=0
        IR2_OPND addr = addr_with_const_offset(reg_n, offset, temp);
        switch (dbytes) {
            case 4:
                high_clean_t = scalar_elem_load(vreg_t, addr, 0, 2, a->rt);
                high_clean_t2 = scalar_elem_load(vreg_t2, addr, dbytes, 2,
                                                 a->rt2);
                break;
            case 8:
                high_clean_t = scalar_elem_load(vreg_t, addr, 0, 3, a->rt);
                high_clean_t2 = scalar_elem_load(vreg_t2, addr, dbytes, 3,
                                                 a->rt2);
                break;
            case 16:
                vector_load(vreg_t, addr, 0, temp);
                vector_load(vreg_t2, addr, dbytes, temp);
                break;
            default:
                lata_unallocated_encoding(s);
                return true;
        }
    } else { // Pre-index or post-index
        if (!a->p && offset) {
            la_addi_d(reg_n, reg_n, offset);
        }

        switch (dbytes) {
            case 4:
                if (a->rn != a->rt && a->rn != a->rt2) {
                    high_clean_t = scalar_elem_load(vreg_t, reg_n, 0, 2,
                                                    a->rt);
                    high_clean_t2 = scalar_elem_load(vreg_t2, reg_n, dbytes,
                                                     2, a->rt2);
                } else { // read vs write
                    la_or(temp, reg_n, zero_ir2_opnd);
                    high_clean_t = scalar_elem_load(vreg_t, temp, 0, 2,
                                                    a->rt);
                    high_clean_t2 = scalar_elem_load(vreg_t2, temp, dbytes,
                                                     2, a->rt2);
                }
                break;
            case 8:
                if (a->rn != a->rt && a->rn != a->rt2) {
                    high_clean_t = scalar_elem_load(vreg_t, reg_n, 0, 3,
                                                    a->rt);
                    high_clean_t2 = scalar_elem_load(vreg_t2, reg_n, dbytes,
                                                     3, a->rt2);
                } else { // read vs write
                    la_or(temp, reg_n, zero_ir2_opnd);
                    high_clean_t = scalar_elem_load(vreg_t, temp, 0, 3,
                                                    a->rt);
                    high_clean_t2 = scalar_elem_load(vreg_t2, temp, dbytes,
                                                     3, a->rt2);
                }
                break;
            case 16:
                if (a->rn != a->rt && a->rn != a->rt2) {
                    vector_load(vreg_t, reg_n, 0, temp);
                    vector_load(vreg_t2, reg_n, dbytes, temp);
                } else { // read vs write
                    la_or(temp, reg_n, zero_ir2_opnd);
                    vector_load(vreg_t, temp, 0, temp);
                    vector_load(vreg_t2, temp, dbytes, temp);
                }
                break;
            default:
                assert(0);
        }

        if (a->p && offset) {
            la_addi_d(reg_n, reg_n, offset);
        }
        if (a->w)
            store_gpr_dst(a->rn, reg_n);
    }

    if (dbytes == 4 || dbytes == 8) {
        store_scalar_fpr_dst(a->rt, vreg_t, dbytes == 4 ? 2 : 3,
                             high_clean_t);
        store_scalar_fpr_dst(a->rt2, vreg_t2, dbytes == 4 ? 2 : 3,
                             high_clean_t2);
    } else {
        store_fpr_dst(a->rt, vreg_t);
        store_fpr_dst(a->rt2, vreg_t2);
    }
    free_alloc_gpr(reg_n);
    free_alloc_fpr(vreg_t);
    free_alloc_fpr(vreg_t2);
    free_alloc_gpr(temp);
    return true;
}

static bool trans_STGP(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static void assist_trans_STR_i(DisasContext *s, IR2_OPND* reg_t,
                               IR2_OPND* reg_n, int64_t offset, uint64_t sz)
{
    IR2_OPND addr = *reg_n;

    if (offset) {
        addr = ra_alloc_itemp();
        li_d(addr, offset);
        la_add_d(addr, *reg_n, addr);
    }
    lata_gen_trace_mem_store(s, addr, 1u << sz, false);
    lata_store_gpr_by_size(reg_t, reg_n, offset, sz);
    if (offset) {
        free_alloc_gpr(addr);
    }
}

static bool trans_STR_i(DisasContext* s)
{
    /*3 classes: Post-index , Pre-index and Unsigned offset
     *
     *               Post-index      Pre-index       Unsigned offset
     * postindex     true            false           false
     *   wback       true            true            false
     */

    arg_ldst_imm* a = &(s->arg.f_ldst_imm);
    int64_t offset = a->imm;
    if (a->w && a->rt == a->rn && a->rn != 31) {
        lata_unallocated_encoding(s);
        return true;
        return true;
    }

    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND reg_t = alloc_gpr_src(a->rt);

    /*  # STR (immediate)
        ## Post-index                       ## Pre-index                         ## Unsigned offset
        32-bit (size == 10)                 32-bit (size == 10)                  32-bit (size == 10)
        STR <Wt>, [<Xn|SP>], #<simm>        STR <Wt>, [<Xn|SP>, #<simm>]!        STR <Wt>, [<Xn|SP>{, #<pimm>}]
        64-bit (size == 11)                 64-bit (size == 11)                  64-bit (size == 11)
        STR <Xt>, [<Xn|SP>], #<simm>        STR <Xt>, [<Xn|SP>, #<simm>]!        STR <Xt>, [<Xn|SP>{, #<pimm>}]

        # STRB (immediate)
        ## Post-index                       ## Pre-index                         ## Unsigned offset
        STRB <Wt>, [<Xn|SP>], #<simm>       STRB <Wt>, [<Xn|SP>, #<simm>]!       STRB <Wt>, [<Xn|SP>{, #<pimm>}]

        # STRH (immediate)
        ## Post-index                       ## Pre-index                         ## Unsigned offset
        STRH <Wt>, [<Xn|SP>], #<simm>       STRH <Wt>, [<Xn|SP>, #<simm>]!       STRH <Wt>, [<Xn|SP>{, #<pimm>}]
    */

    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (clearGprHigh && a->sz == 3 && arm_la_map[a->rt] >= 0 && a->rt != 31) {
        clear_gpr_high(a->rt);
    }

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);

    if (!a->w && offset) { // postindex = false
        /* Unsigned offset立即数是uimm12位，
        la_addi_d立即数是imm12，需要将立即数加载到寄存器
        而Post-index，Pre-index立即数是imm9满足la_addi_d的立即数规范
        */
        if (a->imm > 0x7ff) {
            IR2_OPND temp = ra_alloc_itemp();
            li_d(temp, a->imm);
            la_add_d(temp, reg_n, temp);
            assist_trans_STR_i(s, &reg_t, &temp, 0, a->sz);
            free_alloc_gpr(temp);
        } else {
            assist_trans_STR_i(s, &reg_t, &reg_n, offset, a->sz);
        }
    } else {
        if (!a->p && offset)
            la_addi_d(reg_n, reg_n, offset);
        assist_trans_STR_i(s, &reg_t, &reg_n, 0, a->sz);
        if (a->p && offset)
            la_addi_d(reg_n, reg_n, offset);
        if (a->w)
            store_gpr_dst(a->rn, reg_n);
    }

    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_t);
    return true;
}

static void assist_trans_LDR_i(IR2_OPND* reg_t, IR2_OPND* reg_n, int64_t offset, uint64_t sz, uint64_t sign, bool iss_sf)
{
    lata_load_gpr_by_size(reg_t, reg_n, offset, sz, sign);
}

static bool trans_LDR_i(DisasContext* s)
{
    /*3 classes: Post-index , Pre-index and Unsigned offset
     *
     *               Post-index      Pre-index       Unsigned offset
     * postindex     true            false           false
     *   wback       true            true            false
     */

    arg_ldst_imm* a = &(s->arg.f_ldst_imm);
    int64_t offset = a->imm;
    /* iss_sf ? regsize=64 : regsize=32 */
    bool iss_sf = ldst_iss_sf(a->sz, a->sign, a->ext);
    if (a->w && a->rt == a->rn && a->rn != 31) {
        lata_unallocated_encoding(s);
        return true;
        return true;
    }

    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND reg_t = alloc_gpr_dst(a->rt);

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);

    /*  # LDR (immediate)
        ## Post-index                       ## Pre-index                         ## Unsigned offset
        32-bit (size == 10)                 32-bit (size == 10)                  32-bit (size == 10)
        LDR <Wt>, [<Xn|SP>], #<simm>        LDR <Wt>, [<Xn|SP>, #<simm>]!        LDR <Wt>, [<Xn|SP>{, #<pimm>}]
        64-bit (size == 11)                 64-bit (size == 11)                  64-bit (size == 11)
        LDR <Xt>, [<Xn|SP>], #<simm>        LDR <Xt>, [<Xn|SP>, #<simm>]!        LDR <Xt>, [<Xn|SP>{, #<pimm>}]

        # LDRB (immediate)
        ## Post-index                       ## Pre-index                         ## Unsigned offset
        LDRB <Wt>, [<Xn|SP>], #<simm>       LDRB <Wt>, [<Xn|SP>, #<simm>]!       LDRB <Wt>, [<Xn|SP>{, #<pimm>}]

        # LDRH (immediate)
        ## Post-index                       ## Pre-index                         ## Unsigned offset
        LDRH <Wt>, [<Xn|SP>], #<simm>       LDRH <Wt>, [<Xn|SP>, #<simm>]!       LDRH <Wt>, [<Xn|SP>{, #<pimm>}]
    */

    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    if (!a->w && offset) { // wback = false && offset!=0
        /* Unsigned offset立即数是uimm12位，
        la_addi_d立即数是imm12，需要将立即数加载到寄存器
        而Post-index，Pre-index立即数是imm9满足la_addi_d的立即数规范
        */
        if (offset > 0x7ff) {
            IR2_OPND temp = ra_alloc_itemp();
            li_d(temp, offset);
            la_add_d(temp, reg_n, temp);
            assist_trans_LDR_i(&reg_t, &temp, 0, a->sz, a->sign, iss_sf);
            free_alloc_gpr(temp);
        } else {
            assist_trans_LDR_i(&reg_t, &reg_n, offset, a->sz, a->sign, iss_sf);
        }
    } else { // Post-index
        if (!a->p && offset) {
            la_addi_d(reg_n, reg_n, offset);
        }

        assist_trans_LDR_i(&reg_t, &reg_n, 0, a->sz, a->sign, iss_sf);

        if (a->p && offset) {
            la_addi_d(reg_n, reg_n, offset);
        }
        if (a->w)
            store_gpr_dst(a->rn, reg_n);
    }

    if (a->rt != 31 && arm_la_map[a->rt] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rt, !(a->sign && !iss_sf));
    } else {
        if (a->sign && !iss_sf) {
            la_bstrpick_d(reg_t, reg_t, 31, 0);
        }
    }

    store_gpr_dst(a->rt, reg_t);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_t);
    return true;
}

static void assist_trans_STR_v_i(DisasContext *s, IR2_OPND* vreg_t,
                                 IR2_OPND* reg_n, int64_t offset, uint64_t sz)
{
    IR2_OPND scratch = ra_alloc_itemp();
    uint32_t size = sz == 4 ? 16 : (1u << sz);

    if (lata_trace_mem) {
        IR2_OPND addr = offset ? addr_with_const_offset(*reg_n, offset,
                                                        scratch) : *reg_n;
        lata_gen_trace_mem_store(s, addr, size, true);
    }
    switch (sz) {
        case 0:
        case 1:
            vstelm_elem(*vreg_t, *reg_n, offset, size, 0, scratch);
            break;
        case 2:
        case 3:
            fpu_store(*vreg_t, *reg_n, offset, sz, scratch);
            break;
        case 4:
            vector_store(*vreg_t, *reg_n, offset, scratch);
            break;
        default:
            assert(0);
    }
    free_alloc_gpr(scratch);
}

static bool trans_STR_v_i(DisasContext* s)
{
    /*3 classes: Post-index , Pre-index and Unsigned offset
     *
     *               Post-index      Pre-index       Unsigned offset
     * postindex     true            false           false
     *   wback       true            true            false
     */

    arg_ldst_imm* a = &(s->arg.f_ldst_imm);
    int64_t offset = a->imm;

    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND vreg_t = alloc_fpr_src(a->rt);

    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);

    if (!a->w && offset) { // postindex = false
        /* Unsigned offset立即数是uimm12位，
        la_addi_d立即数是imm12，需要将立即数加载到寄存器
        而Post-index，Pre-index立即数是imm9满足la_addi_d的立即数规范
        */
        if (a->imm > 0x7ff) {
            IR2_OPND temp = ra_alloc_itemp();
            li_d(temp, a->imm);
            la_add_d(temp, reg_n, temp);
            assist_trans_STR_v_i(s, &vreg_t, &temp, 0, a->sz);
            free_alloc_gpr(temp);
        } else {
            // la_addi_d(temp, reg_n, a->imm);
            assist_trans_STR_v_i(s, &vreg_t, &reg_n, offset, a->sz);
        }
    } else {
        if (!a->p && offset)
            la_addi_d(reg_n, reg_n, offset);

        assist_trans_STR_v_i(s, &vreg_t, &reg_n, 0, a->sz);

        if (a->p && offset)
            la_addi_d(reg_n, reg_n, offset);
        if (a->w)
            store_gpr_dst(a->rn, reg_n);
    }

    free_alloc_gpr(reg_n);
    free_alloc_fpr(vreg_t);
    return true;
}

static bool assist_trans_LDR_v_i(IR2_OPND* vreg_t, IR2_OPND* reg_n,
                                 int64_t offset, uint64_t sz, unsigned rt)
{
    bool high_clean = true;

    switch (sz) {
        case 0:
        case 1:
        case 2:
        case 3:
            high_clean = scalar_elem_load(*vreg_t, *reg_n, offset, sz, rt);
            break;
        case 4:
        {
            IR2_OPND scratch = ra_alloc_itemp();
            vector_load(*vreg_t, *reg_n, offset, scratch);
            free_alloc_gpr(scratch);
            break;
        }
        default:
            assert(0);
    }
    return high_clean;
}

static bool trans_LDR_v_i(DisasContext* s)
{
    /*3 classes: Post-index , Pre-index and Unsigned offset
     *
     *               Post-index      Pre-index       Unsigned offset
     * postindex     true            false           false
     *   wback       true            true            false
     */

    arg_ldst_imm* a = &(s->arg.f_ldst_imm);
    int64_t offset = a->imm;
    bool high_clean = true;

    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND vreg_t = alloc_fpr_dst(a->rt);

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);

    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (!a->w && offset) { // wback = false && offset!=0
        /* Unsigned offset立即数是uimm12位，
        la_addi_d立即数是imm12，需要将立即数加载到寄存器
        而Post-index，Pre-index立即数是imm9满足la_addi_d的立即数规范
        */
        if (offset > 0x7ff) {
            IR2_OPND temp = ra_alloc_itemp();
            li_d(temp, offset);
            la_add_d(temp, reg_n, temp);
            high_clean = assist_trans_LDR_v_i(&vreg_t, &temp, 0, a->sz,
                                              a->rt);
            free_alloc_gpr(temp);
        } else {
            high_clean = assist_trans_LDR_v_i(&vreg_t, &reg_n, offset, a->sz,
                                              a->rt);
        }
    } else { // Post-index
        if (!a->p && offset) {
            la_addi_d(reg_n, reg_n, offset);
        }

        high_clean = assist_trans_LDR_v_i(&vreg_t, &reg_n, 0, a->sz, a->rt);

        if (a->p && offset) {
            la_addi_d(reg_n, reg_n, offset);
        }
        if (a->w)
            store_gpr_dst(a->rn, reg_n);
    }

    if (a->sz < 4) {
        store_scalar_fpr_dst(a->rt, vreg_t, a->sz, high_clean);
    } else {
        store_fpr_dst(a->rt, vreg_t);
    }
    free_alloc_gpr(reg_n);
    free_alloc_fpr(vreg_t);
    return true;
}

static bool trans_LDR(DisasContext* s)
{
    arg_ldst* a = &(s->arg.f_ldst);
    IR2_OPND reg_t = alloc_gpr_dst(a->rt);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND reg_m = alloc_gpr_src(a->rm);
    IR2_OPND temp = ra_alloc_itemp();

    /*  LDR (register)
        32-bit (size == 10)
        LDR <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
        64-bit (size == 11)
        LDR <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]

        LDRB (register)
        Extended register (option != 011)
        LDRB <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
        Shifted register (option == 011)
        LDRB <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}]

        LDRH (register)
        LDRH <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
    */
    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (clearGprHigh && a->sz == 3 && arm_la_map[a->rm] >= 0 && a->rm != 31) {
        clear_gpr_high(a->rm);
    }

    /* iss_sf ? regsize=64 : regsize=32 */
    bool iss_sf = ldst_iss_sf(a->sz, a->sign, a->ext);
    if (extract32(a->opt, 1, 1) == 0) {
        return false;
    }

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);

    int extsize = extract32(a->opt, 0, 2);
    bool is_signed = extract32(a->opt, 2, 1);
    unsigned int shift = a->s ? a->sz : 0;

    if (is_signed) {
        switch (extsize) {
            case 0:
                la_ext_w_b(temp, reg_m);
                break;
            case 1:
                la_ext_w_h(temp, reg_m);
                break;
            case 2:
                la_slli_w(temp, reg_m, 0);
                break;
            case 3:
                // to reduce instructions inflation,handle separately
                break;
        }
    } else {
        switch (extsize) {
            case 0:
                la_bstrpick_d(temp, reg_m, 7, 0);
                break;
            case 1:
                la_bstrpick_d(temp, reg_m, 15, 0);
                break;
            case 2:
                la_bstrpick_d(temp, reg_m, 31, 0);
                break;
            case 3:
                // to reduce instructions inflation,handle separately
                break;
        }
    }

    /* LDR(register), */
    if (extsize == 3 && !shift) {
        lata_compute_reg_offset_addr(temp, reg_n, reg_m);
        switch (a->sz) {
            case 0:
                if (a->sign) { // LDRSB
                    la_ld_b(reg_t, temp, 0);
                } else { // LDRB
                    la_ld_bu(reg_t, temp, 0);
                }
                break;
            case 1:
                if (a->sign) { // LDRSH
                    la_ld_h(reg_t, temp, 0);
                } else { // LDRH
                    la_ld_hu(reg_t, temp, 0);
                }
                break;
            case 2:
                if (a->sign) { // LDRSW
                    la_ld_w(reg_t, temp, 0);
                } else { // LDR
                    la_ld_wu(reg_t, temp, 0);
                }
                break;
            case 3: // LDR
                la_ld_d(reg_t, temp, 0);
                break;
            default:
                break;
        }
    } else {
        if (shift) {
            if (extsize == 3) {
                la_slli_d(temp, reg_m, shift);
            } else {
                la_slli_d(temp, temp, shift);
            }
        }

        lata_compute_reg_offset_addr(temp, reg_n, temp);
        switch (a->sz) {
            case 0:
                if (a->sign) { // LDRSB
                    la_ld_b(reg_t, temp, 0);
                } else { // LDRB
                    la_ld_bu(reg_t, temp, 0);
                }
                break;
            case 1:
                if (a->sign) { // LDRSH
                    la_ld_h(reg_t, temp, 0);
                } else { // LDRH
                    la_ld_hu(reg_t, temp, 0);
                }
                break;
            case 2:
                if (a->sign) { // LDRSW
                    la_ld_w(reg_t, temp, 0);
                } else { // LDR
                    la_ld_wu(reg_t, temp, 0);
                }
                break;
            case 3: // LDR
                la_ld_d(reg_t, temp, 0);
                break;
            default:
                break;
        }
    }

    if (a->rt != 31 && arm_la_map[a->rt] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rt, !(a->sign && !iss_sf));
    } else {
        if (a->sign && !iss_sf) {
            la_bstrpick_d(reg_t, reg_t, 31, 0);
        }
    }

    store_gpr_dst(a->rt, reg_t);
    free_alloc_gpr(reg_t);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_m);
    free_alloc_gpr(temp);
    return true;
}

static bool trans_STR(DisasContext* s)
{
    arg_ldst* a = &(s->arg.f_ldst);
    IR2_OPND reg_t = alloc_gpr_src(a->rt);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND reg_m = alloc_gpr_src(a->rm);
    IR2_OPND temp = ra_alloc_itemp();
    int extsize = extract32(a->opt, 0, 2);
    bool is_signed = extract32(a->opt, 2, 1);
    unsigned int shift = a->s ? a->sz : 0;

    /*  STR (register)
        32-bit (size == 10)
        STR <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
        64-bit (size == 11)
        STR <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]

        STRB (register)
        Extended register (option != 011)
        STRB <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
        Shifted register (option == 011)
        STRB <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}]

        STRH (register)
        STRH <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
    */
    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (clearGprHigh && a->sz == 3 && arm_la_map[a->rt] >= 0 && a->rt != 31) {
        clear_gpr_high(a->rt);
    }

    if (clearGprHigh && a->sz == 3 && arm_la_map[a->rm] >= 0 && a->rm != 31) {
        clear_gpr_high(a->rm);
    }

    if (extract32(a->opt, 1, 1) == 0) {
        return false;
    }

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);

    if (is_signed) {
        switch (extsize) {
            case 0:
                la_ext_w_b(temp, reg_m);
                break;
            case 1:
                la_ext_w_h(temp, reg_m);
                break;
            case 2:
                la_slli_w(temp, reg_m, 0);
                break;
            case 3:
                // to reduce instructions inflation,handle separately
                break;
        }
    } else {
        switch (extsize) {
            case 0:
                la_bstrpick_d(temp, reg_m, 7, 0);
                break;
            case 1:
                la_bstrpick_d(temp, reg_m, 15, 0);
                break;
            case 2:
                la_bstrpick_d(temp, reg_m, 31, 0);
                break;
            case 3:
                // to reduce instructions inflation,handle separately
                break;
        }
    }

    if (extsize == 3 && !shift) {
        lata_compute_reg_offset_addr(temp, reg_n, reg_m);
        switch (a->sz) {
            case 0:
                la_st_b(reg_t, temp, 0);
                break;
            case 1:
                la_st_h(reg_t, temp, 0);
                break;
            case 2:
                la_st_w(reg_t, temp, 0);
                break;
            case 3:
                la_st_d(reg_t, temp, 0);
                break;
            default:
                break;
        }
    } else {
        if (shift) {
            if (extsize == 3) {
                la_slli_d(temp, reg_m, shift);
            } else {
                la_slli_d(temp, temp, shift);
            }
        }

        lata_compute_reg_offset_addr(temp, reg_n, temp);
        switch (a->sz) {
            case 0:
                la_st_b(reg_t, temp, 0);
                break;
            case 1:
                la_st_h(reg_t, temp, 0);
                break;
            case 2:
                la_st_w(reg_t, temp, 0);
                break;
            case 3:
                la_st_d(reg_t, temp, 0);
                break;
            default:
                break;
        }
    }

    free_alloc_gpr(reg_t);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_m);
    free_alloc_gpr(temp);
    return true;
}

static bool trans_LDR_v(DisasContext* s)
{
    arg_ldst* a = &(s->arg.f_ldst);
    IR2_OPND vreg_t = alloc_fpr_dst(a->rt);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND reg_m = alloc_gpr_src(a->rm);
    IR2_OPND temp = ra_alloc_itemp();
    bool high_clean = true;

    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (clearGprHigh && extract32(a->opt, 0, 2) == 3 && arm_la_map[a->rm] >= 0 && a->rm != 31) {
        clear_gpr_high(a->rm);
    }

    if (extract32(a->opt, 1, 1) == 0) {
        return false;
    }

    if (!fp_access_check(s)) {
        return true;
    }

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);

    int extsize = extract32(a->opt, 0, 2);
    bool is_signed = extract32(a->opt, 2, 1);
    unsigned int shift = a->s ? a->sz : 0;

    if (is_signed) {
        switch (extsize) {
            case 0:
                la_ext_w_b(temp, reg_m);
                break;
            case 1:
                la_ext_w_h(temp, reg_m);
                break;
            case 2:
                la_slli_w(temp, reg_m, 0);
                break;
            case 3:
                // to reduce instructions inflation,handle separately
                break;
        }
    } else {
        switch (extsize) {
            case 0:
                la_bstrpick_d(temp, reg_m, 7, 0);
                break;
            case 1:
                la_bstrpick_d(temp, reg_m, 15, 0);
                break;
            case 2:
                la_bstrpick_d(temp, reg_m, 31, 0);
                break;
            case 3:
                // to reduce instructions inflation,handle separately
                break;
        }
    }

    /* LDR(register), */
    if (extsize == 3 && !shift) {
        lata_compute_reg_offset_addr(temp, reg_n, reg_m);
        switch (a->sz) {
            case 0:
            case 1:
            case 2:
            case 3:
                high_clean = scalar_elem_load(vreg_t, temp, 0, a->sz, a->rt);
                break;
            case 4:
                vector_load(vreg_t, temp, 0, temp);
                break;
            default:
                break;
        }
    } else {
        if (shift) {
            if (extsize == 3) {
                la_slli_d(temp, reg_m, shift);
            } else {
                la_slli_d(temp, temp, shift);
            }
        }

        /* LDR(register), */
        lata_compute_reg_offset_addr(temp, reg_n, temp);
        switch (a->sz) {
            case 0:
            case 1:
            case 2:
            case 3:
                high_clean = scalar_elem_load(vreg_t, temp, 0, a->sz, a->rt);
                break;
            case 4:
                vector_load(vreg_t, temp, 0, temp);
                break;
            default:
                break;
        }
    }

    if (a->sz < 4) {
        store_scalar_fpr_dst(a->rt, vreg_t, a->sz, high_clean);
    } else {
        store_fpr_dst(a->rt, vreg_t);
    }
    free_alloc_fpr(vreg_t);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_m);
    free_alloc_gpr(temp);
    return true;
}

static bool trans_STR_v(DisasContext* s)
{
    arg_ldst* a = &(s->arg.f_ldst);
    IR2_OPND vreg_t = alloc_fpr_src(a->rt);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND reg_m = alloc_gpr_src(a->rm);
    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND temp1 = ra_alloc_itemp();
    int extsize = extract32(a->opt, 0, 2);
    bool is_signed = extract32(a->opt, 2, 1);
    unsigned int shift = a->s ? a->sz : 0;

    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (clearGprHigh && extract32(a->opt, 0, 2) == 3 && arm_la_map[a->rm] >= 0 && a->rm != 31) {
        clear_gpr_high(a->rm);
    }

    if (extract32(a->opt, 1, 1) == 0) {
        return false;
    }

    if (!fp_access_check(s)) {
        return true;
    }

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);

    if (is_signed) {
        switch (extsize) {
            case 0:
                la_ext_w_b(temp, reg_m);
                break;
            case 1:
                la_ext_w_h(temp, reg_m);
                break;
            case 2:
                la_slli_w(temp, reg_m, 0);
                break;
            case 3:
                // to reduce instructions inflation,handle separately
                break;
        }
    } else {
        switch (extsize) {
            case 0:
                la_bstrpick_d(temp, reg_m, 7, 0);
                break;
            case 1:
                la_bstrpick_d(temp, reg_m, 15, 0);
                break;
            case 2:
                la_bstrpick_d(temp, reg_m, 31, 0);
                break;
            case 3:
                // to reduce instructions inflation,handle separately
                break;
        }
    }

    if (extsize == 3 && !shift) {
        lata_compute_reg_offset_addr(temp, reg_n, reg_m);
        switch (a->sz) {
            case 0:
            case 1:
                vstelm_elem(vreg_t, temp, 0, 1u << a->sz, 0, temp1);
                break;
            case 2:
            case 3:
                fpu_store(vreg_t, temp, 0, a->sz, temp1);
                break;
            case 4:
                vector_store(vreg_t, temp, 0, temp1);
                break;
            default:
                break;
        }
    } else {
        if (shift) {
            if (extsize == 3) {
                la_slli_d(temp, reg_m, shift);
            } else {
                la_slli_d(temp, temp, shift);
            }
        }

        lata_compute_reg_offset_addr(temp, reg_n, temp);
        switch (a->sz) {
            case 0:
            case 1:
                vstelm_elem(vreg_t, temp, 0, 1u << a->sz, 0, temp1);
                break;
            case 2:
            case 3:
                fpu_store(vreg_t, temp, 0, a->sz, temp1);
                break;
            case 4:
                vector_store(vreg_t, temp, 0, temp1);
                break;
            default:
                break;
        }
    }

    free_alloc_fpr(vreg_t);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_m);
    free_alloc_gpr(temp);
    free_alloc_gpr(temp1);
    return true;
}

typedef enum LATALseAtomicOp {
    LATA_LSE_ADD,
    LATA_LSE_CLR,
    LATA_LSE_EOR,
    LATA_LSE_SET,
    LATA_LSE_SMAX,
    LATA_LSE_SMIN,
    LATA_LSE_UMAX,
    LATA_LSE_UMIN,
    LATA_LSE_SWP,
} LATALseAtomicOp;

static void gen_lse_atomic_narrow_llsc(IR2_OPND old_field, IR2_OPND addr,
    IR2_OPND input, IR2_OPND input_field, IR2_OPND new_field, int sz,
    LATALseAtomicOp op)
{
    const int msb = sz == 1 ? 15 : 7;
    const uint64_t field_mask = sz == 1 ? 0xffff : 0xff;
    IR2_OPND label_ll = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND label_done = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND offset = ra_alloc_itemp();
    IR2_OPND aligned_addr = ra_alloc_itemp();
    IR2_OPND word = ra_alloc_itemp();
    IR2_OPND mask = ra_alloc_itemp();
    IR2_OPND cmp_old = ra_alloc_itemp();
    IR2_OPND cmp_input = ra_alloc_itemp();

    la_label(label_ll);
    la_bstrpick_d(input_field, input, msb, 0);
    la_bstrpick_d(offset, addr, 2, 0);
    la_or(aligned_addr, addr, zero_ir2_opnd);
    la_bstrins_d(aligned_addr, zero_ir2_opnd, 2, 0);
    la_ll_d(word, aligned_addr, 0);
    la_slli_d(offset, offset, 3);

    li_d(mask, field_mask);
    la_sll_d(mask, mask, offset);
    la_srl_d(old_field, word, offset);
    la_bstrpick_d(old_field, old_field, msb, 0);

    switch (op) {
    case LATA_LSE_ADD:
        la_add_d(new_field, old_field, input_field);
        break;
    case LATA_LSE_CLR:
        la_andn(new_field, old_field, input_field);
        break;
    case LATA_LSE_EOR:
        la_xor(new_field, old_field, input_field);
        break;
    case LATA_LSE_SET:
        la_or(new_field, old_field, input_field);
        break;
    case LATA_LSE_SWP:
        la_or(new_field, input_field, zero_ir2_opnd);
        break;
    case LATA_LSE_SMAX:
    case LATA_LSE_SMIN:
        if (sz == 1) {
            la_ext_w_h(cmp_old, old_field);
            la_ext_w_h(cmp_input, input_field);
        } else {
            la_ext_w_b(cmp_old, old_field);
            la_ext_w_b(cmp_input, input_field);
        }
        la_or(new_field, input_field, zero_ir2_opnd);
        if (op == LATA_LSE_SMAX) {
            la_blt(cmp_old, cmp_input, label_done);
        } else {
            la_blt(cmp_input, cmp_old, label_done);
        }
        la_or(new_field, old_field, zero_ir2_opnd);
        la_label(label_done);
        break;
    case LATA_LSE_UMAX:
        la_or(new_field, input_field, zero_ir2_opnd);
        la_bltu(old_field, input_field, label_done);
        la_or(new_field, old_field, zero_ir2_opnd);
        la_label(label_done);
        break;
    case LATA_LSE_UMIN:
        la_or(new_field, input_field, zero_ir2_opnd);
        la_bltu(input_field, old_field, label_done);
        la_or(new_field, old_field, zero_ir2_opnd);
        la_label(label_done);
        break;
    }

    la_bstrpick_d(new_field, new_field, msb, 0);
    la_andn(word, word, mask);
    la_sll_d(new_field, new_field, offset);
    la_or(word, word, new_field);
    la_sc_d(word, aligned_addr, 0);
    la_beqz(word, label_ll);

    free_alloc_gpr(offset);
    free_alloc_gpr(aligned_addr);
    free_alloc_gpr(word);
    free_alloc_gpr(mask);
    free_alloc_gpr(cmp_old);
    free_alloc_gpr(cmp_input);
}

static bool do_lse_atomic(DisasContext* s, LATALseAtomicOp op)
{
    int acquire = extract32(s->insn, 23, 1);
    int release = extract32(s->insn, 22, 1);

    arg_atomic* a = &(s->arg.f_atomic);
    IR2_OPND reg_s = alloc_gpr_src(a->rs);
    IR2_OPND reg_t = a->rt == 31 ? ra_alloc_itemp() : alloc_gpr_dst(a->rt);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND src = ra_alloc_itemp();
    IR2_OPND dest = ra_alloc_itemp();

    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    if (release) {
        la_dbar(0);
    }

    if (a->sz == 3) {
        la_or(src, reg_s, zero_ir2_opnd);
        switch (op) {
        case LATA_LSE_ADD: la_amadd_d(reg_t, src, reg_n); break;
        case LATA_LSE_CLR:
            la_orn(src, zero_ir2_opnd, src);
            la_amand_d(reg_t, src, reg_n);
            break;
        case LATA_LSE_EOR: la_amxor_d(reg_t, src, reg_n); break;
        case LATA_LSE_SET: la_amor_d(reg_t, src, reg_n); break;
        case LATA_LSE_SMAX: la_ammax_d(reg_t, src, reg_n); break;
        case LATA_LSE_SMIN: la_ammin_d(reg_t, src, reg_n); break;
        case LATA_LSE_UMAX: la_ammax_du(reg_t, src, reg_n); break;
        case LATA_LSE_UMIN: la_ammin_du(reg_t, src, reg_n); break;
        case LATA_LSE_SWP: la_amswap_d(reg_t, src, reg_n); break;
        }
    } else if (a->sz == 2) {
        la_bstrpick_d(src, reg_s, 31, 0);
        switch (op) {
        case LATA_LSE_ADD: la_amadd_w(reg_t, src, reg_n); break;
        case LATA_LSE_CLR:
            la_orn(src, zero_ir2_opnd, src);
            la_amand_w(reg_t, src, reg_n);
            break;
        case LATA_LSE_EOR: la_amxor_w(reg_t, src, reg_n); break;
        case LATA_LSE_SET: la_amor_w(reg_t, src, reg_n); break;
        case LATA_LSE_SMAX: la_ammax_w(reg_t, src, reg_n); break;
        case LATA_LSE_SMIN: la_ammin_w(reg_t, src, reg_n); break;
        case LATA_LSE_UMAX: la_ammax_wu(reg_t, src, reg_n); break;
        case LATA_LSE_UMIN: la_ammin_wu(reg_t, src, reg_n); break;
        case LATA_LSE_SWP: la_amswap_w(reg_t, src, reg_n); break;
        }
        la_bstrpick_d(reg_t, reg_t, 31, 0);
    } else {
        gen_lse_atomic_narrow_llsc(reg_t, reg_n, reg_s, src, dest, a->sz, op);
    }

    if (acquire) {
        la_dbar(0);
    }

    if (a->rt != 31) {
        store_gpr_dst(a->rt, reg_t);
    }
    free_alloc_gpr(reg_s);
    free_alloc_gpr(reg_t);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(src);
    free_alloc_gpr(dest);
    return true;
}

static bool trans_LDADD(DisasContext* s)
{
    return do_lse_atomic(s, LATA_LSE_ADD);
}

static bool trans_LDCLR(DisasContext* s)
{
    return do_lse_atomic(s, LATA_LSE_CLR);
}

static bool trans_LDEOR(DisasContext* s)
{
    return do_lse_atomic(s, LATA_LSE_EOR);
}

static bool trans_LDSET(DisasContext* s)
{
    return do_lse_atomic(s, LATA_LSE_SET);
}

static bool trans_LDSMAX(DisasContext* s)
{
    return do_lse_atomic(s, LATA_LSE_SMAX);
}

static bool trans_LDSMIN(DisasContext* s)
{
    return do_lse_atomic(s, LATA_LSE_SMIN);
}

static bool trans_LDUMAX(DisasContext* s)
{
    return do_lse_atomic(s, LATA_LSE_UMAX);
}

static bool trans_LDUMIN(DisasContext* s)
{
    return do_lse_atomic(s, LATA_LSE_UMIN);
}

static bool trans_SWP(DisasContext* s)
{
    return do_lse_atomic(s, LATA_LSE_SWP);
}

static bool trans_LDAPR(DisasContext* s)
{
    arg_decode_insn3227* a = &(s->arg.f_decode_insn3227);
    IR2_OPND reg_t = alloc_gpr_dst(a->rt);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);

    if (!dc_isar_feature(aa64_atomics, s) || !dc_isar_feature(aa64_rcpc_8_3, s)) {
        return false;
    }
    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);
    switch (a->sz) {
        case 0:
            la_ld_bu(reg_t, reg_n, 0);
            break;
        case 1:
            la_ld_hu(reg_t, reg_n, 0);
            break;
        case 2:
            la_ld_wu(reg_t, reg_n, 0);
            break;
        case 3:
            la_ld_d(reg_t, reg_n, 0);
            break;
        default:
            g_assert_not_reached();
    }
    lata_gen_mb();

    if (a->rt != 31 && arm_la_map[a->rt] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rt, TRUE);
    }
    store_gpr_dst(a->rt, reg_t);
    free_alloc_gpr(reg_t);
    free_alloc_gpr(reg_n);
    return true;
}

static bool trans_LDRA(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_LDAPR_i(DisasContext* s)
{
    arg_ldapr_stlr_i* a = &(s->arg.f_ldapr_stlr_i);
    bool iss_sf = ldst_iss_sf(a->sz, a->sign, a->ext);
    IR2_OPND reg_t = alloc_gpr_dst(a->rt);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);

    if (!dc_isar_feature(aa64_rcpc_8_4, s)) {
        return false;
    }
    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);
    assist_trans_LDR_i(&reg_t, &reg_n, sextract32(a->imm, 0, 9), a->sz, a->sign, iss_sf);
    lata_gen_mb();

    if (a->rt != 31 && arm_la_map[a->rt] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rt, !(a->sign && !iss_sf));
    } else if (a->sign && !iss_sf) {
        la_bstrpick_d(reg_t, reg_t, 31, 0);
    }
    store_gpr_dst(a->rt, reg_t);
    free_alloc_gpr(reg_t);
    free_alloc_gpr(reg_n);
    return true;
}

static bool trans_STLR_i(DisasContext* s)
{
    arg_ldapr_stlr_i* a = &(s->arg.f_ldapr_stlr_i);
    IR2_OPND reg_t = alloc_gpr_src(a->rt);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);

    if (!dc_isar_feature(aa64_rcpc_8_4, s)) {
        return false;
    }
    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    lata_clean_data_tbi(s, &reg_n, &reg_n, s->tbid);
    lata_gen_mb();
    lata_store_gpr_by_size(&reg_t, &reg_n, sextract32(a->imm, 0, 9), a->sz);

    free_alloc_gpr(reg_t);
    free_alloc_gpr(reg_n);
    return true;
}

static bool trans_LD_mult(DisasContext* s)
{
    arg_ldst_mult* a = &(s->arg.f_ldst_mult);
    IR2_OPND vreg_d, reg_n, reg_m;

    int total; /* total bytes */
    int size = a->sz;

    if (!a->p && a->rm != 0) {
        /* For non-postindexed accesses the Rm field must be 0 */
        return false;
    }
    if (size == 3 && !a->q && a->selem != 1) {
        return false;
    }
    if (!fp_access_check(s)) {
        return true;
    }

    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    reg_n = alloc_gpr_src_sp(a->rn);
    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (a->selem == 1) {              /* LD1(multiple structures) */
        int vbytes = (a->q ? 16 : 8); /* bytes per vector */
        total = a->rpt * vbytes;

        /*  这里默认是小尾端，
            使用vld读取16个字节和使用16次ld_B的效果相同(H, W, D同理)
        */
        for (int r = 0; r < a->rpt; r++) {
            int tt = (a->rt + r) % 32;
            int offset = r * vbytes;
            vreg_d = alloc_fpr_dst(tt);
            if (a->q) {
                IR2_OPND scratch = ra_alloc_itemp();
                vector_load(vreg_d, reg_n, offset, scratch);
                free_alloc_gpr(scratch);
                store_fpr_dst(tt, vreg_d);
            } else {
                bool high_clean = scalar_elem_load(vreg_d, reg_n, offset, 3,
                                                   tt);
                store_scalar_fpr_dst(tt, vreg_d, 3, high_clean);
            }
            free_alloc_fpr(vreg_d);
        }
    } else {                                    /* LD2/LD3/LD4, both are multiple structures */
        int elements = (a->q ? 16 : 8) >> size; /* elements per vector */
        int ebytes = 1 << size;                 /* bytes per element */
        total = a->selem * elements * ebytes;

        IR2_OPND vtemp = ra_alloc_ftemp();
        IR2_OPND scratch = ra_alloc_itemp();
        for (int r = 0; r < a->selem; r++) {
            int tt = (a->rt + r) % 32;
            vreg_d = alloc_fpr_dst(tt);
            la_vxor_v(vreg_d, vreg_d, vreg_d);
            for (int e = 0; e < elements; e++) {
                int offset = (e * a->selem + r) * ebytes;
                vldrepl_elem(vtemp, reg_n, offset, ebytes, scratch);
                switch (ebytes) {
                    case 1:
                        la_vextrins_b(vreg_d, vtemp, e << 4);
                        break;
                    case 2:
                        la_vextrins_h(vreg_d, vtemp, e << 4);
                        break;
                    case 4:
                        la_vextrins_w(vreg_d, vtemp, e << 4);
                        break;
                    case 8:
                        la_vextrins_d(vreg_d, vtemp, e << 4);
                        break;
                    default:
                        break;
                }
            }
            if (!a->q) {
                bool high_clean = fpr_clear_high_if_live(vreg_d, tt, 3);
                store_scalar_fpr_dst(tt, vreg_d, 3, high_clean);
            } else {
                store_fpr_dst(tt, vreg_d);
            }

            free_alloc_fpr(vreg_d);
        }
        free_alloc_gpr(scratch);
        free_alloc_fpr(vtemp);
    }

    if (a->p) {
        if (a->rm == 31) {
            assert(total <= 2047 && total >= -2048); /* addi的立即数是imm12 */
            la_addi_d(reg_n, reg_n, total);
        } else {
            reg_m = alloc_gpr_src(a->rm);

            if (clearGprHigh && arm_la_map[a->rm] >= 0 && a->rm != 31) { /* reg_m is 64-bit size*/
                clear_gpr_high(a->rm);
            }

            la_add_d(reg_n, reg_n, reg_m);
            free_alloc_gpr(reg_m);
        }
    }

    store_gpr_dst(a->rn, reg_n);
    free_alloc_gpr(reg_n);
    return true;
}

static bool trans_ST_mult(DisasContext* s)
{
    // assert(0);
    arg_ldst_mult* a = &(s->arg.f_ldst_mult);
    IR2_OPND vreg_d, reg_n, reg_m;

    int total; /* total bytes */
    int size = a->sz;

    if (!a->p && a->rm != 0) {
        /* For non-postindexed accesses the Rm field must be 0 */
        return false;
    }
    if (size == 3 && !a->q && a->selem != 1) {
        return false;
    }
    if (!fp_access_check(s)) {
        return true;
    }

    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    reg_n = alloc_gpr_src_sp(a->rn);
    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    if (a->selem == 1) {              /* ST1(multiple structures) */
        int vbytes = (a->q ? 16 : 8); /* bytes per vector */
        total = a->rpt * vbytes;

        /*  这里默认是小尾端，
            使用vst写入16个字节和使用16次st_B的效果相同(H, W, D同理)
        */
        for (int r = 0; r < a->rpt; r++) {
            int tt = (a->rt + r) % 32;
            int offset = r * vbytes;
            vreg_d = alloc_fpr_src(tt);
            if (a->q) {
                IR2_OPND scratch = ra_alloc_itemp();
                vector_store(vreg_d, reg_n, offset, scratch);
                free_alloc_gpr(scratch);
            } else {
                /* 这里和LD1有点差别，load多了可以高位清零，但是store不行 */
                IR2_OPND scratch = ra_alloc_itemp();
                fpu_store(vreg_d, reg_n, offset, 3, scratch);
                free_alloc_gpr(scratch);
            }
            free_alloc_fpr(vreg_d);
        }
    } else {                                    /* ST2/ST3/ST4, both are multiple structures */
        int elements = (a->q ? 16 : 8) >> size; /* elements per vector */
        int ebytes = 1 << size;                 /* bytes per element */
        total = a->selem * elements * ebytes;

        for (int r = 0; r < a->selem; r++) { /* structure elements 等于需要store的寄存器个数 */
            int tt = (a->rt + r) % 32;
            vreg_d = alloc_fpr_src(tt);
            IR2_OPND scratch = ra_alloc_itemp();
            for (int e = 0; e < elements; e++) {
                int offset = (e * a->selem + r) * ebytes;
                vstelm_elem(vreg_d, reg_n, offset, ebytes, e, scratch);
            }

            free_alloc_gpr(scratch);
            free_alloc_fpr(vreg_d);
        }
    }

    if (a->p) {
        if (a->rm == 31) {
            assert(total <= 2047 && total >= -2048); /* addi的立即数是imm12 */
            la_addi_d(reg_n, reg_n, total);
        } else {
            reg_m = alloc_gpr_src(a->rm);

            if (clearGprHigh && arm_la_map[a->rm] >= 0 && a->rm != 31) { /* reg_m is 64-bit size*/
                clear_gpr_high(a->rm);
            }

            la_add_d(reg_n, reg_n, reg_m);
            free_alloc_gpr(reg_m);
        }
    }

    store_gpr_dst(a->rn, reg_n);
    free_alloc_gpr(reg_n);
    return true;
}

static bool trans_ST_single(DisasContext* s)
{
    arg_ldst_single* a = &(s->arg.f_ldst_single);
    IR2_OPND vreg_d, reg_n, reg_m;
    int total; /* total bytes */
    int esize;
    int xs, rt;

    if (!a->p && a->rm != 0) {
        return false;
    }
    if (!fp_access_check(s)) {
        return true;
    }

    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    total = a->selem << a->scale;
    esize = 1 << a->scale;

    reg_n = alloc_gpr_src_sp(a->rn);
    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    for (xs = 0, rt = a->rt; xs < a->selem; xs++, rt = (rt + 1) % 32) {
        vreg_d = alloc_fpr_src(rt);
        IR2_OPND scratch = ra_alloc_itemp();
        vstelm_elem(vreg_d, reg_n, xs * esize, esize, a->index, scratch);
        free_alloc_gpr(scratch);
        free_alloc_fpr(vreg_d);
    }

    if (a->p) {
        if (a->rm == 31) {
            assert(total <= 2047 && total >= -2048); /* addi的立即数是imm12 */
            la_addi_d(reg_n, reg_n, total);
        } else {
            reg_m = alloc_gpr_src(a->rm);
            if (clearGprHigh && arm_la_map[a->rm] >= 0 && a->rm != 31) { /* reg_m is 64-bit size*/
                clear_gpr_high(a->rm);
            }

            la_add_d(reg_n, reg_n, reg_m);
            free_alloc_gpr(reg_m);
        }
    }

    store_gpr_dst(a->rn, reg_n);
    free_alloc_gpr(reg_n);
    return true;
}

static bool trans_LD_single(DisasContext* s)
{
    arg_ldst_single* a = &(s->arg.f_ldst_single);
    IR2_OPND vreg_d, reg_n, reg_m, vtemp;
    int total; /* total bytes */
    int esize;
    int xs, rt;

    if (!a->p && a->rm != 0) {
        return false;
    }
    if (!fp_access_check(s)) {
        return true;
    }

    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    total = a->selem << a->scale;
    esize = 1 << a->scale;
    reg_n = alloc_gpr_src_sp(a->rn);
    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    vtemp = ra_alloc_ftemp();
    IR2_OPND scratch = ra_alloc_itemp();
    for (xs = 0, rt = a->rt; xs < a->selem; xs++, rt = (rt + 1) % 32) {
        vreg_d = alloc_fpr_src(rt);
        int offset = xs * esize;
        vldrepl_elem(vtemp, reg_n, offset, esize, scratch);
        switch (esize) {
            case 1:
                la_vextrins_b(vreg_d, vtemp, a->index << 4);
                break;
            case 2:
                la_vextrins_h(vreg_d, vtemp, a->index << 4);
                break;
            case 4:
                la_vextrins_w(vreg_d, vtemp, a->index << 4);
                break;
            case 8:
                la_vextrins_d(vreg_d, vtemp, a->index << 4);
                break;
            default:
                break;
        }
        store_fpr_dst(rt, vreg_d);
        free_alloc_fpr(vreg_d);
    }

    if (a->p) {
        if (a->rm == 31) {
            assert(total <= 2047 && total >= -2048); /* addi的立即数是imm12 */
            la_addi_d(reg_n, reg_n, total);
        } else {
            reg_m = alloc_gpr_src(a->rm);
            if (clearGprHigh && arm_la_map[a->rm] >= 0 && a->rm != 31) { /* reg_m is 64-bit size*/
                clear_gpr_high(a->rm);
            }

            la_add_d(reg_n, reg_n, reg_m);
            free_alloc_gpr(reg_m);
        }
    }

    store_gpr_dst(a->rn, reg_n);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(scratch);
    free_alloc_fpr(vtemp);
    return true;
}

static bool trans_LD_single_repl(DisasContext* s)
{
    arg_LD_single_repl* a = &(s->arg.f_decode_insn3232);
    IR2_OPND vreg_d, reg_n, reg_m;
    int xs, total, rt; /* total bytes */
    int esize;

    if (!a->p && a->rm != 0) {
        return false;
    }
    if (!fp_access_check(s)) {
        return true;
    }

    if (a->rn == 31) {
        gen_check_sp_alignment(s);
    }

    total = a->selem << a->scale;
    esize = 1 << a->scale;

    reg_n = alloc_gpr_src_sp(a->rn);
    if (clearGprHigh && arm_la_map[a->rn] >= 0) { /* all reg_n is 64-bit size*/
        clear_gpr_high(a->rn);
    }

    for (xs = 0, rt = a->rt; xs < a->selem; xs++, rt = (rt + 1) % 32) {
        IR2_OPND scratch = ra_alloc_itemp();
        bool high_clean = true;

        vreg_d = alloc_fpr_dst(rt);
        vldrepl_elem(vreg_d, reg_n, xs * esize, esize, scratch);
        if (!a->q) {
            high_clean = fpr_clear_high_if_live(vreg_d, rt, 3);
            store_scalar_fpr_dst(rt, vreg_d, 3, high_clean);
        } else {
            store_fpr_dst(rt, vreg_d);
        }
        free_alloc_gpr(scratch);
        free_alloc_fpr(vreg_d);
    }

    if (a->p) {
        if (a->rm == 31) {
            assert(total <= 2047 && total >= -2048); /* addi的立即数是imm12 */
            la_addi_d(reg_n, reg_n, total);
        } else {
            reg_m = alloc_gpr_src(a->rm);
            if (clearGprHigh && arm_la_map[a->rm] >= 0 && a->rm != 31) { /* reg_m is 64-bit size*/
                clear_gpr_high(a->rm);
            }

            la_add_d(reg_n, reg_n, reg_m);
            free_alloc_gpr(reg_m);
        }
    }

    store_gpr_dst(a->rn, reg_n);
    free_alloc_gpr(reg_n);
    return true;
}

static bool trans_STZGM(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_STGM(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_LDGM(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_LDG(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool do_STG(DisasContext* s, arg_ldst_tag* a, bool is_zero, bool is_pair)
{
    lata_unallocated_encoding(s);
    return true;
}

TRANS_FEAT_LDST_TAG(STG, aa64_mte_insn_reg, do_STG, false, false)
TRANS_FEAT_LDST_TAG(STZG, aa64_mte_insn_reg, do_STG, true, false)
TRANS_FEAT_LDST_TAG(ST2G, aa64_mte_insn_reg, do_STG, false, true)
TRANS_FEAT_LDST_TAG(STZ2G, aa64_mte_insn_reg, do_STG, true, true)

/*
 * PC-rel. addressing
 */

static bool trans_ADR(DisasContext* s)
{
    arg_ri* a = &(s->arg.f_ri);
    IR2_OPND reg_d = alloc_gpr_dst(a->rd);
    li_d(reg_d, (int64_t)(a->imm + s->pc_curr));

    if (a->rd != 31 && arm_la_map[a->rd] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rd, TRUE);
    }

    store_gpr_dst(a->rd, reg_d);
    free_alloc_gpr(reg_d);
    return true;
}

static bool trans_ADRP(DisasContext* s)
{
    arg_ri* a = &(s->arg.f_ri);
    int64_t offset = a->imm << 12;

    /* The page offset is ok for CF_PCREL. */
    offset -= s->pc_curr & 0xfff;
    IR2_OPND reg_d = alloc_gpr_dst(a->rd);
    li_d(reg_d, (int64_t)(offset + s->pc_curr));

    if (a->rd != 31 && arm_la_map[a->rd] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rd, TRUE);
    }

    store_gpr_dst(a->rd, reg_d);
    free_alloc_gpr(reg_d);
    return true;
}

/*
 * Add/subtract (immediate)
 */

static bool trans_ADD_i(DisasContext* s)
{
    arg_ADD_i* a = &(s->arg.f_rri_sf);
    IR2_OPND reg_d = alloc_gpr_dst_sp(a->rd);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND temp = ra_alloc_itemp();

    if (clearGprHigh && a->sf && arm_la_map[a->rn] >= 0 && a->rn != 31) {
        clear_gpr_high(a->rn);
    }

    uint8_t shift = extract32(s->insn, 22, 1);
    switch (shift) {
        case 0:
            if (a->imm <= 0x7ff) {
                if (a->sf) {
                    la_addi_d(reg_d, reg_n, a->imm);
                } else {
                    la_addi_w(reg_d, reg_n, a->imm);
                }
            } else {
                la_ori(temp, zero_ir2_opnd, a->imm);
                if (a->sf) {
                    la_add_d(reg_d, reg_n, temp);
                } else {
                    la_add_w(reg_d, reg_n, temp);
                }
            }
            break;
        case 1:
            la_lu12i_w(temp, a->imm >> 12);
            if (a->sf) {
                la_add_d(reg_d, reg_n, temp);
            } else {
                la_add_w(reg_d, reg_n, temp);
            }
            break;
        default:
            lata_unallocated_encoding(s);
            return true;
            break;
    }

    store_gpr_dst_reg_width(a->rd, reg_d, a->sf);
    free_alloc_gpr(temp);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_n);
    return true;
}

static bool trans_SUB_i(DisasContext* s)
{
    arg_SUB_i* a = &(s->arg.f_rri_sf);
    IR2_OPND reg_d = alloc_gpr_dst_sp(a->rd);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND temp = ra_alloc_itemp();

    if (clearGprHigh && a->sf && arm_la_map[a->rn] >= 0 && a->rn != 31) {
        clear_gpr_high(a->rn);
    }

    uint8_t shift = extract32(s->insn, 22, 1);
    switch (shift) {
        case 0:
            if (a->imm <= 0x7ff) {
                if (a->sf) {
                    la_addi_d(reg_d, reg_n, -a->imm);
                } else {
                    la_addi_w(reg_d, reg_n, -a->imm);
                }
            } else {
                la_ori(temp, zero_ir2_opnd, a->imm);
                if (a->sf) {
                    la_sub_d(reg_d, reg_n, temp);
                } else {
                    la_sub_w(reg_d, reg_n, temp);
                }
            }
            break;
        case 1:
            la_lu12i_w(temp, a->imm >> 12);
            if (a->sf) {
                la_sub_d(reg_d, reg_n, temp);
            } else {
                la_sub_w(reg_d, reg_n, temp);
            }
            break;
        default:
            lata_unallocated_encoding(s);
            return true;
            break;
    }

    store_gpr_dst_reg_width(a->rd, reg_d, a->sf);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(temp);
    return true;
}

static bool trans_ADDS_i(DisasContext* s)
{
    arg_ADDS_i* a = &(s->arg.f_rri_sf);
    IR2_OPND reg_d = alloc_gpr_dst(a->rd);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND temp = ra_alloc_itemp();

    if (clearGprHigh && a->sf && arm_la_map[a->rn] >= 0 && a->rn != 31) {
        clear_gpr_high(a->rn);
    }

    uint8_t shift = extract32(s->insn, 22, 1);
    switch (shift) {
        case 0:
            la_ori(temp, zero_ir2_opnd, a->imm);
            break;
        case 1:
            la_lu12i_w(temp, a->imm >> 12);
            break;
        default:
            lata_unallocated_encoding(s);
            return true;
            break;
    }

    gen_add_CC(&reg_n, &temp, a->sf);
    gen_add(&reg_d, &reg_n, &temp, a->sf);

    store_gpr_dst_reg_width(a->rd, reg_d, a->sf);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(temp);
    return true;
}

static bool trans_SUBS_i(DisasContext* s)
{
    arg_SUBS_i* a = &(s->arg.f_rri_sf);
    IR2_OPND reg_d = alloc_gpr_dst(a->rd);
    IR2_OPND reg_n = alloc_gpr_src_sp(a->rn);
    IR2_OPND temp = ra_alloc_itemp();

    if (clearGprHigh && a->sf && arm_la_map[a->rn] >= 0 && a->rn != 31) {
        clear_gpr_high(a->rn);
    }

    uint8_t shift = extract32(s->insn, 22, 1);
    switch (shift) {
        case 0:
            la_ori(temp, zero_ir2_opnd, a->imm);
            break;
        case 1:
            la_lu12i_w(temp, a->imm >> 12);
            break;
        default:
            lata_unallocated_encoding(s);
            return true;
            break;
    }

    gen_sub_CC(&reg_n, &temp, a->sf);
    gen_sub(&reg_d, &reg_n, &temp, a->sf);

    store_gpr_dst_reg_width(a->rd, reg_d, a->sf);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(temp);
    return true;
}

/*
 * Add/subtract (immediate, with tags)
 */
static bool trans_ADDG_i(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

static bool trans_SUBG_i(DisasContext* s)
{
    lata_unallocated_encoding(s);
    return true;
}

/* The input should be a value in the bottom e bits (with higher
 * bits zero); returns that value replicated into every element
 * of size e in a 64 bit integer.
 */
static uint64_t bitfield_replicate(uint64_t mask, unsigned int e)
{
    assert(e != 0);
    while (e < 64) {
        mask |= mask << e;
        e *= 2;
    }
    return mask;
}

/*
 * Logical (immediate)
 */

/*
 * Simplified variant of pseudocode DecodeBitMasks() for the case where we
 * only require the wmask. Returns false if the imms/immr/immn are a reserved
 * value (ie should cause a guest UNDEF exception), and true if they are
 * valid, in which case the decoded bit pattern is written to result.
 */
bool logic_imm_decode_wmask(uint64_t* result, unsigned int immn,
    unsigned int imms, unsigned int immr)
{
    uint64_t mask;
    unsigned e, levels, s, r;
    int len;

    assert(immn < 2 && imms < 64 && immr < 64);

    /* The bit patterns we create here are 64 bit patterns which
     * are vectors of identical elements of size e = 2, 4, 8, 16, 32 or
     * 64 bits each. Each element contains the same value: a run
     * of between 1 and e-1 non-zero bits, rotated within the
     * element by between 0 and e-1 bits.
     *
     * The element size and run length are encoded into immn (1 bit)
     * and imms (6 bits) as follows:
     * 64 bit elements: immn = 1, imms = <length of run - 1>
     * 32 bit elements: immn = 0, imms = 0 : <length of run - 1>
     * 16 bit elements: immn = 0, imms = 10 : <length of run - 1>
     *  8 bit elements: immn = 0, imms = 110 : <length of run - 1>
     *  4 bit elements: immn = 0, imms = 1110 : <length of run - 1>
     *  2 bit elements: immn = 0, imms = 11110 : <length of run - 1>
     * Notice that immn = 0, imms = 11111x is the only combination
     * not covered by one of the above options; this is reserved.
     * Further, <length of run - 1> all-ones is a reserved pattern.
     *
     * In all cases the rotation is by immr % e (and immr is 6 bits).
     */

    /* First determine the element size */
    len = 31 - clz32((immn << 6) | (~imms & 0x3f));
    if (len < 1) {
        /* This is the immn == 0, imms == 0x11111x case */
        return false;
    }
    e = 1 << len;

    levels = e - 1;
    s = imms & levels;
    r = immr & levels;

    if (s == levels) {
        /* <length of run - 1> mustn't be all-ones. */
        return false;
    }

    /* Create the value of one element: s+1 set bits rotated
     * by r within the element (which is e bits wide)...
     */
    mask = MAKE_64BIT_MASK(0, s + 1);
    if (r) {
        mask = (mask >> r) | (mask << (e - r));
        mask &= MAKE_64BIT_MASK(0, e);
    }
    /* ...then replicate the element over the whole 64 bit value */
    mask = bitfield_replicate(mask, e);
    *result = mask;
    return true;
}

static bool trans_AND_i(DisasContext* s)
{
    arg_AND_i* a = &(s->arg.f_rri_log);
    uint64_t imm;
    /* Some immediate field values are reserved. */
    if (!logic_imm_decode_wmask(&imm, extract32(a->dbm, 12, 1),
            extract32(a->dbm, 0, 6),
            extract32(a->dbm, 6, 6))) {
        return false;
    }

    if (!a->sf) {
        imm &= 0xffffffffull;
    }

    IR2_OPND reg_d = alloc_gpr_dst_sp(a->rd);
    IR2_OPND reg_n = alloc_gpr_src_ro(a->rn);

    if (clearGprHigh && a->sf && arm_la_map[a->rn] >= 0 && a->rn != 31) {
        clear_gpr_high(a->rn);
    }

    if (imm > 0xfff) {
        IR2_OPND temp = ra_alloc_itemp();
        li_d(temp, imm);
        la_and(reg_d, reg_n, temp);
        free_alloc_gpr(temp);
    } else {
        la_andi(reg_d, reg_n, imm);
    }

    store_gpr_dst_reg_width(a->rd, reg_d, a->sf);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_d);
    return true;
}

static bool trans_ORR_i(DisasContext* s)
{
    arg_ORR_i* a = &(s->arg.f_rri_log);
    uint64_t imm;
    /* Some immediate field values are reserved. */
    if (!logic_imm_decode_wmask(&imm, extract32(a->dbm, 12, 1),
            extract32(a->dbm, 0, 6),
            extract32(a->dbm, 6, 6))) {
        return false;
    }

    if (!a->sf) {
        imm &= 0xffffffffull;
    }

    IR2_OPND reg_d = alloc_gpr_dst_sp(a->rd);
    IR2_OPND reg_n = alloc_gpr_src_ro(a->rn);

    if (clearGprHigh && a->sf && arm_la_map[a->rn] >= 0 && a->rn != 31) {
        clear_gpr_high(a->rn);
    }

    if (imm > 0xfff) {
        IR2_OPND temp = ra_alloc_itemp();
        li_d(temp, imm);
        la_or(reg_d, reg_n, temp);
        free_alloc_gpr(temp);
    } else {
        la_ori(reg_d, reg_n, imm);
    }

    store_gpr_dst_reg_width(a->rd, reg_d, a->sf);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_d);
    return true;
}

static bool trans_EOR_i(DisasContext* s)
{
    arg_EOR_i* a = &(s->arg.f_rri_log);
    uint64_t imm;
    /* Some immediate field values are reserved. */
    if (!logic_imm_decode_wmask(&imm, extract32(a->dbm, 12, 1),
            extract32(a->dbm, 0, 6),
            extract32(a->dbm, 6, 6))) {
        return false;
    }

    if (!a->sf) {
        imm &= 0xffffffffull;
    }

    IR2_OPND reg_d = alloc_gpr_dst_sp(a->rd);
    IR2_OPND reg_n = alloc_gpr_src_ro(a->rn);

    if (clearGprHigh && a->sf && arm_la_map[a->rn] >= 0 && a->rn != 31) {
        clear_gpr_high(a->rn);
    }

    if (imm > 0xfff) {
        IR2_OPND temp = ra_alloc_itemp();
        li_d(temp, imm);
        la_xor(reg_d, reg_n, temp);
        free_alloc_gpr(temp);
    } else {
        la_xori(reg_d, reg_n, imm);
    }

    store_gpr_dst_reg_width(a->rd, reg_d, a->sf);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_d);
    return true;
}

static bool trans_ANDS_i(DisasContext* s)
{
    arg_ANDS_i* a = &(s->arg.f_rri_log);
    uint64_t imm;
    /* Some immediate field values are reserved. */
    if (!logic_imm_decode_wmask(&imm, extract32(a->dbm, 12, 1),
            extract32(a->dbm, 0, 6),
            extract32(a->dbm, 6, 6))) {
        return false;
    }

    if (!a->sf) {
        imm &= 0xffffffffull;
    }

    IR2_OPND reg_d = alloc_gpr_dst(a->rd);
    IR2_OPND reg_n = alloc_gpr_src_ro(a->rn);
    IR2_OPND temp = ra_alloc_itemp();

    if (clearGprHigh && a->sf && arm_la_map[a->rn] >= 0 && a->rn != 31) {
        clear_gpr_high(a->rn);
    }

    li_d(temp, imm);
    la_and(reg_d, reg_n, temp);
    if (!a->sf) {
        la_x86and_w(reg_n, temp);
    } else {
        la_x86and_d(reg_n, temp);
    }

    store_gpr_dst_reg_width(a->rd, reg_d, a->sf);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(temp);
    return true;
}

/*
 * Move wide (immediate)
 */

static bool trans_MOVZ(DisasContext* s)
{
    arg_MOVZ* a = &(s->arg.f_movw);
    int pos = a->hw << 4;
    uint64_t imm = (uint64_t)a->imm << pos;

    IR2_OPND reg_d = alloc_gpr_dst(a->rd);
    if (imm > 0xfff) {
        li_d(reg_d, imm);
    } else if (imm) {
        la_ori(reg_d, zero_ir2_opnd, imm);
    }
    if (a->rd != 31 && arm_la_map[a->rd] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rd, TRUE);
    }

    if (!imm) {
        store_gpr_zero(a->rd);
    } else {
        store_gpr_dst(a->rd, reg_d);
    }

    free_alloc_gpr(reg_d);
    return true;
}

static bool trans_MOVN(DisasContext* s)
{
    arg_movw* a = &(s->arg.f_movw);
    int pos = a->hw << 4;

    IR2_OPND reg_d = alloc_gpr_dst(a->rd);

    uint64_t imm = a->imm;
    if (~(imm << pos) > 0xfff) {
        li_d(reg_d, ~(imm << pos));
    } else {
        la_ori(reg_d, zero_ir2_opnd, ~(imm << pos));
    }

    if (a->rd != 31 && arm_la_map[a->rd] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rd, a->sf);
    } else {
        if (!a->sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(a->rd, reg_d);
    free_alloc_gpr(reg_d);
    return true;
}

static bool trans_MOVK(DisasContext* s)
{
    arg_movw* a = &(s->arg.f_movw);
    int pos = a->hw << 4;
    IR2_OPND reg_d = alloc_gpr_src(a->rd);
    IR2_OPND temp = ra_alloc_itemp();

    if (clearGprHigh && a->sf && arm_la_map[a->rd] >= 0 && a->rd != 31) {
        clear_gpr_high(a->rd);
    }

    if (a->imm > 0xfff) {
        li_d(temp, a->imm);
    } else {
        la_ori(temp, zero_ir2_opnd, a->imm);
    }

    if (a->sf) {
        la_bstrins_d(reg_d, temp, pos + 15, pos);
    } else {
        la_bstrins_w(reg_d, temp, pos + 15, pos);
    }

    if (a->rd != 31 && arm_la_map[a->rd] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rd, a->sf);
    } else {
        if (!a->sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(a->rd, reg_d);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(temp);
    return true;
}

/*
 * Bitfield
 */

static bool trans_SBFM(DisasContext* s)
{
    arg_SBFM* a = &(s->arg.f_bitfield);
    unsigned int bitsize = a->sf ? 64 : 32;
    unsigned int ri = a->immr;
    unsigned int si = a->imms;

    IR2_OPND reg_d = alloc_gpr_dst(a->rd);
    IR2_OPND reg_n = alloc_gpr_src_ro(a->rn);

    if (clearGprHigh && a->sf && arm_la_map[a->rn] >= 0 && a->rn != 31) {
        clear_gpr_high(a->rn);
    }

    if (bitsize == 32 && si == 31) { // 32-bit ASR
        la_srai_w(reg_d, reg_n, ri);
    } else if (bitsize == 64 && si == 63) { // 64-bit ASR
        la_srai_d(reg_d, reg_n, ri);
    }
    /* Wd<s-r:0> = Wn<s:r> */
    else if (ri == 0 && si == 7) { // SXTB
        la_ext_w_b(reg_d, reg_n);
    } else if (ri == 0 && si == 15) { // SXTH
        la_ext_w_h(reg_d, reg_n);
    } else if (ri == 0 && si == 31) { // SXTW
        la_add_w(reg_d, zero_ir2_opnd, reg_n);
    } else if (si >= ri) { // SBFX
        if (bitsize == 64) {
            la_slli_d(reg_d, reg_n, 63 - si);
            la_srai_d(reg_d, reg_d, 63 - si + ri);
        } else {
            la_slli_w(reg_d, reg_n, 31 - si);
            la_srai_w(reg_d, reg_d, 31 - si + ri);
        }
    } else { // SBFIZ
        /* Wd<32+s-r,32-r> = Wn<s:0> */
        if (bitsize == 64) {
            la_slli_d(reg_d, reg_n, 63 - si);
            la_srai_d(reg_d, reg_d, ri - si - 1);
        } else {
            la_slli_w(reg_d, reg_n, 31 - si);
            la_srai_w(reg_d, reg_d, ri - si - 1);
        }
    }

    if (a->rd != 31 && arm_la_map[a->rd] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rd, a->sf);
    } else {
        if (!a->sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(a->rd, reg_d);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_n);
    return true;
}

static bool trans_UBFM(DisasContext* s)
{
    arg_UBFM* a = &(s->arg.f_bitfield);
    unsigned int bitsize = a->sf ? 64 : 32;
    unsigned int ri = a->immr;
    unsigned int si = a->imms;

    IR2_OPND reg_d = alloc_gpr_dst(a->rd);
    IR2_OPND reg_n = alloc_gpr_src_ro(a->rn);
    if (clearGprHigh && a->sf && arm_la_map[a->rn] >= 0 && a->rn != 31) {
        clear_gpr_high(a->rn);
    }

    if (si >= ri) { // LSR, UXTB, UXTH, UBFX
        /* Wd<s-r:0> = Wn<s:r> */
        if (a->sf) {
            la_bstrpick_d(reg_d, reg_n, si, ri);
        } else {
            la_bstrpick_w(reg_d, reg_n, si, ri);
        }
    } else {
        /* Wd<32+s-r,32-r> = Wn<s:0> */
        if ((!a->sf) && (si != 31) && (si + 1 == ri)) { // 32-bit LSL
            la_slli_w(reg_d, reg_n, bitsize - ri);
        } else if (a->sf && (si != 63) && (si + 1 == ri)) { // 64-bit LSL
            la_slli_d(reg_d, reg_n, bitsize - ri);
        } else { // UBFIZ
            if (a->sf) {
                la_bstrpick_d(reg_d, reg_n, si, 0);
                la_slli_d(reg_d, reg_d, bitsize - ri);
            } else {
                la_bstrpick_w(reg_d, reg_n, si, 0);
                la_slli_d(reg_d, reg_d, bitsize - ri);
            }
        }
    }

    if (a->rd != 31 && arm_la_map[a->rd] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rd, a->sf);
    } else {
        if (!a->sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(a->rd, reg_d);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_n);
    return true;
}

static bool trans_BFM(DisasContext* s)
{
    arg_BFM* a = &(s->arg.f_bitfield);
    unsigned int bitsize = a->sf ? 64 : 32;
    unsigned int ri = a->immr;
    unsigned int si = a->imms;

    IR2_OPND reg_d = alloc_gpr_src(a->rd);
    IR2_OPND reg_n = alloc_gpr_src_ro(a->rn);
    IR2_OPND temp;
    if (clearGprHigh && a->sf && arm_la_map[a->rd] >= 0 && a->rd != 31) {
        clear_gpr_high(a->rd);
    }
    if (clearGprHigh && a->sf && arm_la_map[a->rn] >= 0 && a->rn != 31) {
        clear_gpr_high(a->rn);
    }

    if (si >= ri) { // BFXIL
        /* Wd<s-r:0> = Wn<s:r> */
        temp = ra_alloc_itemp();
        if (a->sf) {
            la_srli_d(temp, reg_n, ri);
            la_bstrins_d(reg_d, temp, si - ri, 0);
        } else {
            la_srli_w(temp, reg_n, ri);
            la_bstrins_w(reg_d, temp, si - ri, 0);
        }
        free_alloc_gpr(temp);
    } else {
        /* Wd<32+s-r,32-r> = Wn<s:0> */
        // if(a->rn == 31){ // BFC
        //     if(a->sf){
        //         la_bstrins_d(reg_d, zero_ir2_opnd, bitsize + si - ri, bitsize - ri);
        //     }else{
        //         la_bstrins_w(reg_d, zero_ir2_opnd, bitsize + si - ri, bitsize - ri);
        //     }
        // }else{ // BFI
        //     reg_n = alloc_gpr_src(a->rn);
        //     if(a->sf){
        //         la_bstrins_d(reg_d, reg_n, bitsize + si - ri, bitsize - ri);
        //     }else{
        //         la_bstrins_w(reg_d, reg_n, bitsize + si - ri, bitsize - ri);
        //     }
        //     free_alloc_gpr(reg_n);
        // }
        if (a->sf) {
            la_bstrins_d(reg_d, reg_n, bitsize + si - ri, bitsize - ri);
        } else {
            la_bstrins_w(reg_d, reg_n, bitsize + si - ri, bitsize - ri);
        }
    }

    if (a->rd != 31 && arm_la_map[a->rd] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rd, a->sf);
    } else {
        if (!a->sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(a->rd, reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_d);
    return true;
}

static bool trans_EXTR(DisasContext* s)
{
    arg_extract* a = &(s->arg.f_extract);
    IR2_OPND reg_d = alloc_gpr_dst(a->rd);
    IR2_OPND reg_m = alloc_gpr_src_ro(a->rm);
    IR2_OPND reg_n = alloc_gpr_src_ro(a->rn);
    IR2_OPND temp = ra_alloc_itemp();

    if (clearGprHigh && a->sf && arm_la_map[a->rm] >= 0 && a->rm != 31) {
        clear_gpr_high(a->rm);
    }
    if (clearGprHigh && a->sf && arm_la_map[a->rn] >= 0 && a->rn != 31) {
        clear_gpr_high(a->rn);
    }

    if (unlikely(a->imm == 0)) {
        la_or(reg_d, reg_m, zero_ir2_opnd);
    } else if (a->rn == a->rm) {
        if (!a->sf) {
            lsassert(a->imm <= 31);
            la_rotri_w(reg_d, reg_m, a->imm);
        } else {
            la_rotri_d(reg_d, reg_m, a->imm);
        }
    } else {
        if (!a->sf) {
            la_srli_w(temp, reg_m, a->imm);
            la_bstrins_w(temp, reg_n, 31, 32 - a->imm);
        } else {
            la_srli_d(temp, reg_m, a->imm);
            la_bstrins_d(temp, reg_n, 63, 64 - a->imm);
        }
        la_or(reg_d, temp, zero_ir2_opnd);
    }

    if (a->rd != 31 && arm_la_map[a->rd] >= 0 && clearGprHigh) {
        set_w_write_flag(a->rd, a->sf);
    } else {
        if (!a->sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(a->rd, reg_d);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_m);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(temp);
    return true;
}

static void shift_reg_imm(IR2_OPND* dst, IR2_OPND* src, int sf,
    enum a64_shift_type shift_type, unsigned int shift_i)
{
    assert(shift_i < (sf ? 64 : 32));

    switch (shift_type) {
        case A64_SHIFT_TYPE_LSL:
            la_slli_d(*dst, *src, shift_i);
            break;
        case A64_SHIFT_TYPE_LSR:
            if (!sf) {
                la_srli_w(*dst, *src, shift_i);
            } else {
                la_srli_d(*dst, *src, shift_i);
            }
            break;
        case A64_SHIFT_TYPE_ASR:
            if (!sf) {
                la_srai_w(*dst, *src, shift_i);
            } else {
                la_srai_d(*dst, *src, shift_i);
            }
            break;
        case A64_SHIFT_TYPE_ROR:
            if (!sf) {
                assert(shift_i <= 31);
                la_rotri_w(*dst, *src, shift_i);
            } else {
                la_rotri_d(*dst, *src, shift_i);
            }
            break;
        default:
            assert(FALSE); /* all shift types should be handled */
            break;
    }

}

/* Logical (shifted register)
 *   31  30 29 28       24 23   22 21  20  16 15    10 9    5 4    0
 * +----+-----+-----------+-------+---+------+--------+------+------+
 * | sf | opc | 0 1 0 1 0 | shift | N |  Rm  |  imm6  |  Rn  |  Rd  |
 * +----+-----+-----------+-------+---+------+--------+------+------+
 */
static void disas_logic_reg(DisasContext* s, uint32_t insn)
{
    unsigned int sf, opc, shift_type, invert, rm, shift_amount, rn, rd;

    sf = extract32(insn, 31, 1);
    opc = extract32(insn, 29, 2);
    shift_type = extract32(insn, 22, 2);
    invert = extract32(insn, 21, 1);
    rm = extract32(insn, 16, 5);
    shift_amount = extract32(insn, 10, 6);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);

    if (!sf && (shift_amount & (1 << 5))) {
        lata_unallocated_encoding(s);
        return;
    }

    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND reg_m = alloc_gpr_src_ro(rm);

    if (clearGprHigh && sf && arm_la_map[rm] >= 0 && rm != 31) {
        clear_gpr_high(rm);
    }

    if (opc == 1 && shift_amount == 0 && shift_type == 0 && rn == 31) {
        /* Unshifted ORR and ORN with WZR/XZR is the standard encoding for
         * register-register MOV and MVN, so it is worth special casing.
         */
        // IR2_OPND reg_d = alloc_gpr_dst(rd);
        // IR2_OPND reg_m = alloc_gpr_src(rm);

        if (invert) {
            la_orn(reg_d, zero_ir2_opnd, reg_m);
        } else {
            la_or(reg_d, zero_ir2_opnd, reg_m);
        }

        store_gpr_dst_reg_width(rd, reg_d, sf);
        free_alloc_gpr(reg_d);
        free_alloc_gpr(reg_m);
        return;
    }

    IR2_OPND reg_n = alloc_gpr_src_ro(rn);
    IR2_OPND temp = ra_alloc_itemp();

    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }

    if (shift_amount) {
        shift_reg_imm(&temp, &reg_m, sf, shift_type, shift_amount);

        switch (opc | (invert << 2)) {
            case 0: /* AND */
            case 3: /* ANDS */
                if (opc == 3) {
                    if (sf) {
                        la_x86and_d(reg_n, temp);
                    } else {
                        la_x86and_w(reg_n, temp);
                    }
                }
                la_and(reg_d, reg_n, temp);
                break;
            case 1: /* ORR */
                la_or(reg_d, reg_n, temp);
                break;
            case 2: /* EOR */
                la_xor(reg_d, reg_n, temp);
                break;
            case 4: /* BIC */
            case 7: /* BICS */
                la_andn(reg_d, reg_n, temp);
                if (opc == 3) {
                    la_nor(temp, zero_ir2_opnd, temp);
                    if (sf) {
                        la_x86and_d(reg_n, temp);
                    } else {
                        la_x86and_w(reg_n, temp);
                    }
                }
                break;
            case 5: /* ORN */
                la_orn(reg_d, reg_n, temp);
                break;
            case 6: /* EON */
                la_nor(temp, zero_ir2_opnd, temp);
                la_xor(reg_d, reg_n, temp);
                break;
            default:
                assert(FALSE);
                break;
        }
    } else {
        switch (opc | (invert << 2)) {
            case 0: /* AND */
            case 3: /* ANDS */
                if (opc == 3) {
                    if (sf) {
                        la_x86and_d(reg_n, reg_m);
                    } else {
                        la_x86and_w(reg_n, reg_m);
                    }
                }
                la_and(reg_d, reg_n, reg_m);
                break;
            case 1: /* ORR */
                la_or(reg_d, reg_n, reg_m);
                break;
            case 2: /* EOR */
                la_xor(reg_d, reg_n, reg_m);
                break;
            case 4: /* BIC */
            case 7: /* BICS */
                if (opc == 3) {
                    la_nor(temp, zero_ir2_opnd, reg_m);
                    if (sf) {
                        la_x86and_d(reg_n, temp);
                    } else {
                        la_x86and_w(reg_n, temp);
                    }
                }
                la_andn(reg_d, reg_n, reg_m);
                break;
            case 5: /* ORN */
                la_orn(reg_d, reg_n, reg_m);
                break;
            case 6: /* EON */
                la_nor(temp, zero_ir2_opnd, reg_m);
                la_xor(reg_d, reg_n, temp);
                break;
            default:
                assert(FALSE);
                break;
        }
    }

    store_gpr_dst_reg_width(rd, reg_d, sf);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_m);
    free_alloc_gpr(temp);
}

static void gen_add_sub_reg_result(bool setflags, bool sub_op, bool sf,
    IR2_OPND* reg_d, IR2_OPND* reg_n, IR2_OPND* temp)
{

    if (setflags) {
        if (sub_op) {
            gen_sub_CC(reg_n, temp, sf);
        } else {
            gen_add_CC(reg_n, temp, sf);
        }
    }

    if (sub_op) {
        gen_sub(reg_d, reg_n, temp, sf);
    } else {
        gen_add(reg_d, reg_n, temp, sf);
    }
}
/*
 * Add/subtract (extended register)
 *
 *  31|30|29|28       24|23 22|21|20   16|15  13|12  10|9  5|4  0|
 * +--+--+--+-----------+-----+--+-------+------+------+----+----+
 * |sf|op| S| 0 1 0 1 1 | opt | 1|  Rm   |option| imm3 | Rn | Rd |
 * +--+--+--+-----------+-----+--+-------+------+------+----+----+
 *
 *  sf: 0 -> 32bit, 1 -> 64bit
 *  op: 0 -> add  , 1 -> sub
 *   S: 1 -> set flags
 * opt: 00
 * option: extension type (see DecodeRegExtend)
 * imm3: optional shift to Rm
 *
 * Rd = Rn + LSL(extend(Rm), amount)
 */
static void disas_add_sub_ext_reg(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int imm3 = extract32(insn, 10, 3);
    int option = extract32(insn, 13, 3);
    int rm = extract32(insn, 16, 5);
    int opt = extract32(insn, 22, 2);
    bool setflags = extract32(insn, 29, 1);
    bool sub_op = extract32(insn, 30, 1);
    bool sf = extract32(insn, 31, 1);
    int extsize = extract32(option, 0, 2);
    bool is_signed = extract32(option, 2, 1);
    if (imm3 > 4 || opt != 0) {
        lata_unallocated_encoding(s);
        return;
    }

    IR2_OPND reg_d;
    IR2_OPND reg_n = alloc_gpr_src_sp_ro(rn);
    IR2_OPND reg_m = alloc_gpr_src_ro(rm);
    IR2_OPND temp = ra_alloc_itemp();

    if (clearGprHigh && sf && arm_la_map[rn] >= 0) {
        clear_gpr_high(rn);
    }
    if (clearGprHigh && sf && arm_la_map[rm] >= 0 && rm != 31) {
        clear_gpr_high(rm);
    }

    /* non-flag setting ops may use SP */
    if (!setflags) {
        reg_d = alloc_gpr_dst_sp(rd);
    } else {
        reg_d = alloc_gpr_dst(rd);
    }

    if (is_signed) {
        switch (extsize) {
            case 0:
                la_ext_w_b(temp, reg_m);
                break;
            case 1:
                la_ext_w_h(temp, reg_m);
                break;
            case 2:
                la_bstrpick_w(temp, reg_m, 31, 0);
                break;
            case 3:
                // la_or(*dst,*src,zero_ir2_opnd);
                break;
        }
    } else {
        switch (extsize) {
            case 0:
                la_bstrpick_d(temp, reg_m, 7, 0);
                break;
            case 1:
                la_bstrpick_d(temp, reg_m, 15, 0);
                break;
            case 2:
                la_bstrpick_d(temp, reg_m, 31, 0);
                break;
            case 3:
                // la_or(*dst,*src,zero_ir2_opnd);
                break;
        }
    }

    if (imm3) {
        if (extsize == 3)
            la_slli_d(temp, reg_m, imm3);
        else
            la_slli_d(temp, temp, imm3);
        gen_add_sub_reg_result(setflags, sub_op, sf, &reg_d, &reg_n, &temp);
    } else {
        if (extsize == 3)
            gen_add_sub_reg_result(setflags, sub_op, sf, &reg_d, &reg_n, &reg_m);
        else
            gen_add_sub_reg_result(setflags, sub_op, sf, &reg_d, &reg_n, &temp);
    }

    if ((rd != 31 || !setflags) && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, sf);
    } else {
        if (!sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_m);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(temp);
}

/*
 * Add/subtract (shifted register)
 *
 *  31 30 29 28       24 23 22 21 20   16 15     10 9    5 4    0
 * +--+--+--+-----------+-----+--+-------+---------+------+------+
 * |sf|op| S| 0 1 0 1 1 |shift| 0|  Rm   |  imm6   |  Rn  |  Rd  |
 * +--+--+--+-----------+-----+--+-------+---------+------+------+
 *
 *    sf: 0 -> 32bit, 1 -> 64bit
 *    op: 0 -> add  , 1 -> sub
 *     S: 1 -> set flags
 * shift: 00 -> LSL, 01 -> LSR, 10 -> ASR, 11 -> RESERVED
 *  imm6: Shift amount to apply to Rm before the add/sub
 */
static void disas_add_sub_reg(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int imm6 = extract32(insn, 10, 6);
    int rm = extract32(insn, 16, 5);
    int shift_type = extract32(insn, 22, 2);
    bool setflags = extract32(insn, 29, 1);
    bool sub_op = extract32(insn, 30, 1);
    bool sf = extract32(insn, 31, 1);

    if ((shift_type == 3) || (!sf && (imm6 > 31))) {
        lata_unallocated_encoding(s);
        return;
    }

    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND reg_n = alloc_gpr_src_ro(rn);
    IR2_OPND reg_m = alloc_gpr_src_ro(rm);

    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }
    if (clearGprHigh && sf && arm_la_map[rm] >= 0 && rm != 31) {
        clear_gpr_high(rm);
    }

    IR2_OPND temp = ra_alloc_itemp();
    if (imm6) {
        shift_reg_imm(&temp, &reg_m, sf, shift_type, imm6);
        gen_add_sub_reg_result(setflags, sub_op, sf, &reg_d, &reg_n, &temp);
    } else {

        gen_add_sub_reg_result(setflags, sub_op, sf, &reg_d, &reg_n, &reg_m);
    }

    store_gpr_dst_reg_width(rd, reg_d, sf);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_m);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(temp);
}

/* Data-processing (3 source)
 *
 *    31 30  29 28       24 23 21  20  16  15  14  10 9    5 4    0
 *  +--+------+-----------+------+------+----+------+------+------+
 *  |sf| op54 | 1 1 0 1 1 | op31 |  Rm  | o0 |  Ra  |  Rn  |  Rd  |
 *  +--+------+-----------+------+------+----+------+------+------+
 */
static void disas_data_proc_3src(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int ra = extract32(insn, 10, 5);
    int rm = extract32(insn, 16, 5);
    int op_id = (extract32(insn, 29, 3) << 4) | (extract32(insn, 21, 3) << 1) | extract32(insn, 15, 1);
    bool sf = extract32(insn, 31, 1);
    bool is_sub = extract32(op_id, 0, 1);
    // bool is_high = extract32(op_id, 2, 1);
    // bool is_signed = false;

    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND reg_n = alloc_gpr_src(rn);
    IR2_OPND reg_a, temp;
    IR2_OPND reg_m = alloc_gpr_src(rm);

    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }
    if (clearGprHigh && sf && arm_la_map[rm] >= 0 && rm != 31) {
        clear_gpr_high(rm);
    }

    /* Note that op_id is sf:op54:op31:o0 so it includes the 32/64 size flag */
    switch (op_id) {
        case 0x42: /* SMADDL */
        case 0x43: /* SMSUBL */
            /*
                SMADDL <Xd>, <Wn>, <Wm>, <Xa>
                SMSUBL <Xd>, <Wn>, <Wm>, <Xa>
            */
            if (ra == 31 && !is_sub) {
                /* Special-case MADD with rA == XZR; it is the standard MUL alias */
                la_mulw_d_w(reg_d, reg_n, reg_m);
            } else {
                reg_a = alloc_gpr_src(ra);
                if (clearGprHigh && arm_la_map[ra] >= 0 && ra != 31) {
                    clear_gpr_high(ra);
                }

                temp = ra_alloc_itemp();
                la_mulw_d_w(temp, reg_m, reg_n);
                if (is_sub) {
                    la_sub_d(reg_d, reg_a, temp);
                } else {
                    la_add_d(reg_d, reg_a, temp);
                }

                free_alloc_gpr(reg_a);
                free_alloc_gpr(temp);
            }
            break;
        case 0x44: /* SMULH */
            la_mulh_d(reg_d, reg_n, reg_m);
            break;
        case 0x0:  /* MADD (32bit) */
        case 0x1:  /* MSUB (32bit) */
        case 0x40: /* MADD (64bit) */
        case 0x41: /* MSUB (64bit) */
            if (ra == 31 && !is_sub) {
                /* Special-case MADD with rA == XZR; it is the standard MUL alias */
                if (sf) {
                    la_mul_d(reg_d, reg_n, reg_m);
                } else {
                    la_mul_w(reg_d, reg_n, reg_m);
                }
            } else {
                reg_a = alloc_gpr_src(ra);
                if (clearGprHigh && arm_la_map[ra] >= 0 && ra != 31) {
                    clear_gpr_high(ra);
                }

                temp = ra_alloc_itemp();
                if (sf) {
                    la_mul_d(temp, reg_n, reg_m);
                } else {
                    la_mul_w(temp, reg_n, reg_m);
                }
                if (is_sub) {
                    if (sf) {
                        la_sub_d(reg_d, reg_a, temp);
                    } else {
                        la_sub_w(reg_d, reg_a, temp);
                    }
                } else {
                    if (sf) {
                        la_add_d(reg_d, reg_a, temp);
                    } else {
                        la_add_w(reg_d, reg_a, temp);
                    }
                }

                free_alloc_gpr(reg_a);
                free_alloc_gpr(temp);
            }
            break;
        case 0x4a: /* UMADDL */
        case 0x4b: /* UMSUBL */
            if (ra == 31 && !is_sub) {
                /* Special-case MADD with rA == XZR; it is the standard MUL alias */
                la_mulw_d_wu(reg_d, reg_n, reg_m);
            } else {
                reg_a = alloc_gpr_src(ra);
                if (clearGprHigh && arm_la_map[ra] >= 0 && ra != 31) {
                    clear_gpr_high(ra);
                }

                temp = ra_alloc_itemp();
                la_mulw_d_wu(temp, reg_n, reg_m);
                if (is_sub) {
                    la_sub_d(reg_d, reg_a, temp);
                } else {
                    la_add_d(reg_d, reg_a, temp);
                }

                free_alloc_gpr(reg_a);
                free_alloc_gpr(temp);
            }
            break;
        case 0x4c: /* UMULH */
            la_mulh_du(reg_d, reg_n, reg_m);
            break;
        default:
            lata_unallocated_encoding(s);
            return;
    }

    if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, sf);
    } else {
        if (!sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_m);
}

/* Add/subtract (with carry)
 *  31 30 29 28 27 26 25 24 23 22 21  20  16  15       10  9    5 4   0
 * +--+--+--+------------------------+------+-------------+------+-----+
 * |sf|op| S| 1  1  0  1  0  0  0  0 |  rm  | 0 0 0 0 0 0 |  Rn  |  Rd |
 * +--+--+--+------------------------+------+-------------+------+-----+
 */

static void disas_adc_sbc(DisasContext* s, uint32_t insn)
{
    unsigned int sf, op, setflags, rm, rn, rd;

    sf = extract32(insn, 31, 1);
    op = extract32(insn, 30, 1);
    setflags = extract32(insn, 29, 1);
    rm = extract32(insn, 16, 5);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);

    IR2_OPND reg_n = alloc_gpr_src_ro(rn);
    IR2_OPND reg_m = alloc_gpr_src_ro(rm);
    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND temp2 = ra_alloc_itemp();
    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }
    if (clearGprHigh && sf && arm_la_map[rm] >= 0 && rm != 31) {
        clear_gpr_high(rm);
    }

    if (op) {
        la_orn(temp, zero_ir2_opnd, reg_m);
        la_or(temp2, reg_n, zero_ir2_opnd);
        if (sf) {
            la_adc_d(reg_d, reg_n, temp);
        } else {
            la_adc_w(reg_d, reg_n, temp);
        }
        if (setflags) {
            if (sf) {
                la_x86adc_d(temp2, temp);
            } else {
                la_x86adc_w(temp2, temp);
            }
        }
    } else {
        la_or(temp2, reg_n, zero_ir2_opnd);
        if (sf) {
            la_adc_d(reg_d, reg_n, reg_m);
        } else {
            la_adc_w(reg_d, reg_n, reg_m);
        }
        if (setflags) {
            if (sf) {
                la_x86adc_d(temp2, reg_m);
            } else {
                la_x86adc_w(temp2, reg_m);
            }
        }
    }

    if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, sf);
    } else {
        if (!sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_m);
    free_alloc_gpr(temp);
    free_alloc_gpr(temp2);
    store_gpr_dst(rd, reg_d);
}

/*
 * Rotate right into flags
 *  31 30 29                21       15          10      5  4      0
 * +--+--+--+-----------------+--------+-----------+------+--+------+
 * |sf|op| S| 1 1 0 1 0 0 0 0 |  imm6  | 0 0 0 0 1 |  Rn  |o2| mask |
 * +--+--+--+-----------------+--------+-----------+------+--+------+
 */
static void disas_rotate_right_into_flags(DisasContext* s, uint32_t insn) { lata_unallocated_encoding(s); }

/*
 * Evaluate into flags
 *  31 30 29                21        15   14        10      5  4      0
 * +--+--+--+-----------------+---------+----+---------+------+--+------+
 * |sf|op| S| 1 1 0 1 0 0 0 0 | opcode2 | sz | 0 0 1 0 |  Rn  |o3| mask |
 * +--+--+--+-----------------+---------+----+---------+------+--+------+
 */
static void disas_evaluate_into_flags(DisasContext* s, uint32_t insn)
{
    /* SETF8 / SETF16:
     * N = bit 7/15 of the selected byte/halfword
     * Z = selected byte/halfword is zero
     * C is unchanged
     * V = bit 8/16 xor bit 7/15, matching QEMU's flag representation.
     */
    int rn = extract32(insn, 5, 5);
    bool sz = extract32(insn, 14, 1); /* sz=1: SETF16, sz=0: SETF8 */
    int bit_n = sz ? 15 : 7;
    int bit_v_hi = sz ? 16 : 8;
    int low_msb = sz ? 15 : 7;

    IR2_OPND reg_n = alloc_gpr_src_ro(rn);
    IR2_OPND n = ra_alloc_itemp();
    IR2_OPND z = ra_alloc_itemp();
    IR2_OPND v = ra_alloc_itemp();
    IR2_OPND flags = ra_alloc_itemp();
    IR2_OPND tmp = ra_alloc_itemp();

    /* Extract bit_n -> N (bit 31). */
    la_srli_d(n, reg_n, bit_n);
    la_andi(n, n, 1);
    la_slli_d(n, n, 31);

    /* Z is set when the selected low byte/halfword is zero. */
    la_bstrpick_d(z, reg_n, low_msb, 0);
    la_sltui(z, z, 1);
    la_slli_d(z, z, 30);

    /* V is the sign overflow bit for the selected byte/halfword. */
    la_srli_d(v, reg_n, bit_v_hi);
    la_srli_d(tmp, reg_n, bit_n);
    la_xor(v, v, tmp);
    la_andi(v, v, 1);
    la_slli_d(v, v, 28);

    /* Combine N | Z | V; the LBT sub-mask preserves C. */
    la_or(flags, n, z);
    la_or(flags, flags, v);
    la_armmtflag(flags, 0x38);

    free_alloc_gpr(reg_n);
    free_alloc_gpr(n);
    free_alloc_gpr(z);
    free_alloc_gpr(v);
    free_alloc_gpr(flags);
    free_alloc_gpr(tmp);
}

/* Conditional compare (immediate / register)
 *  31 30 29 28 27 26 25 24 23 22 21  20    16 15  12  11  10  9   5  4 3   0
 * +--+--+--+------------------------+--------+------+----+--+------+--+-----+
 * |sf|op| S| 1  1  0  1  0  0  1  0 |imm5/rm | cond |i/r |o2|  Rn  |o3|nzcv |
 * +--+--+--+------------------------+--------+------+----+--+------+--+-----+
 *        [1]                             y                [0]       [0]
 */
static void disas_cc(DisasContext* s, uint32_t insn)
{
    unsigned int sf, op, y, cond, rn, nzcv, is_imm;

    if (!extract32(insn, 29, 1)) {
        lata_unallocated_encoding(s);
        return;
    }
    if (insn & (1 << 10 | 1 << 4)) {
        lata_unallocated_encoding(s);
        return;
    }
    sf = extract32(insn, 31, 1);
    op = extract32(insn, 30, 1);
    is_imm = extract32(insn, 11, 1);
    y = extract32(insn, 16, 5); /* y = rm (reg) or imm5 (imm) */
    cond = extract32(insn, 12, 4);
    rn = extract32(insn, 5, 5);
    nzcv = extract32(insn, 0, 4);

    IR2_OPND reg_n = alloc_gpr_src_ro(rn);
    IR2_OPND reg_m;
    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND label_false = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND label_end = ir2_opnd_new_type(IR2_OPND_LABEL);
    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }

    la_setarmj(temp, cond);
    la_beqz(temp, label_false);

    /* TRUE */
    if (is_imm) {
        if (y) {
            reg_m = ra_alloc_itemp();
            la_addi_d(reg_m, zero_ir2_opnd, y);
        } else {
            reg_m = zero_ir2_opnd;
        }
    } else {
        reg_m = alloc_gpr_src(y);
        if (clearGprHigh && sf && arm_la_map[y] >= 0 && y != 31) {
            clear_gpr_high(y);
        }
    }

    if (op) { // CCMP
        gen_sub_CC(&reg_n, &reg_m, sf);
    } else { // CCMN
        gen_add_CC(&reg_n, &reg_m, sf);
    }
    la_b(label_end);

    la_label(label_false);
    /* FALSE */
    la_addi_w(temp, zero_ir2_opnd, nzcv);
    la_slli_w(temp, temp, 28);
    la_armmtflag(temp, 0x39);

    la_label(label_end);

    free_alloc_gpr(reg_m);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(temp);
}

/* Conditional select
 *   31   30  29  28             21 20  16 15  12 11 10 9    5 4    0
 * +----+----+---+-----------------+------+------+-----+------+------+
 * | sf | op | S | 1 1 0 1 0 1 0 0 |  Rm  | cond | op2 |  Rn  |  Rd  |
 * +----+----+---+-----------------+------+------+-----+------+------+
 */
static void disas_cond_select(DisasContext* s, uint32_t insn)
{
    unsigned int sf, else_inv, rm, cond, else_inc, rn, rd;

    if (extract32(insn, 29, 1) || extract32(insn, 11, 1)) {
        /* S == 1 or op2<1> == 1 */
        lata_unallocated_encoding(s);
        return;
    }
    sf = extract32(insn, 31, 1);
    else_inv = extract32(insn, 30, 1);
    rm = extract32(insn, 16, 5);
    cond = extract32(insn, 12, 4);
    else_inc = extract32(insn, 10, 1);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);

    /*
    CSEL                          00
    CSNEG CNEG                    11
    CSINC CINC CSET(rm==rn==xzr)  01
    CSINV CINV CSETM(rm==rn==xzr) 10
    */
    IR2_OPND reg_d = alloc_gpr_dst(rd);

    if (rn == 31 && rm == 31 && (else_inc ^ else_inv)) {
        /* CSET & CSETM.  */
        la_addi_d(reg_d, zero_ir2_opnd, 1);
        la_armmove(reg_d, zero_ir2_opnd, cond); // CSET: reg_d = cond ? 0 : 1
        if (else_inv) {                         // CSETM
            la_orn(reg_d, zero_ir2_opnd, reg_d);
            la_addi_d(reg_d, reg_d, 1);
        }
    } else {
        IR2_OPND reg_n = alloc_gpr_src(rn);
        IR2_OPND reg_m = alloc_gpr_src(rm);
        IR2_OPND temp_m = ra_alloc_itemp();
        IR2_OPND temp_n = ra_alloc_itemp();

        if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
            clear_gpr_high(rn);
        }
        if (clearGprHigh && sf && arm_la_map[rm] >= 0 && rm != 31) {
            clear_gpr_high(rm);
        }

        if (else_inv && else_inc) { // CSNEG, CNEG(FALSE)
            la_orn(temp_m, zero_ir2_opnd, reg_m);
            la_addi_d(temp_m, temp_m, 1);
        } else if (else_inv) { // CSINV, CINV(FALSE)
            la_orn(temp_m, zero_ir2_opnd, reg_m);
        } else if (else_inc) { // CSINC, CINC(FALSE)
            la_addi_d(temp_m, reg_m, 1);
        } else { // CSEL(FALSE)
            la_or(temp_m, zero_ir2_opnd, reg_m);
        }

        if (rd == rn) {
            la_or(temp_n, zero_ir2_opnd, reg_n);
        }

        la_or(reg_d, zero_ir2_opnd, temp_m);

        /* CSNEG, CNEG, CSINV, CINV, CSINC, CINC, CSEL(TRUE)*/
        if (rd == rn) {
            la_armmove(reg_d, temp_n, cond);
        } else {
            la_armmove(reg_d, reg_n, cond);
        }

        free_alloc_gpr(reg_n);
        free_alloc_gpr(reg_m);
        free_alloc_gpr(temp_n);
        free_alloc_gpr(temp_m);
    }

    if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, sf);
    } else {
        if (!sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_d);
}

static void handle_clz(DisasContext* s, unsigned int sf,
    unsigned int rn, unsigned int rd)
{
    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND reg_n = alloc_gpr_src_ro(rn);
    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }

    if (sf) {
        la_clz_d(reg_d, reg_n);
    } else {
        la_clz_w(reg_d, reg_n);
    }

    if (arm_la_map[rd] >= 0 && rd != 31 && clearGprHigh) {
        set_w_write_flag(rd, TRUE);
    }

    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_d);
}

static void handle_cls(DisasContext* s, unsigned int sf,
    unsigned int rn, unsigned int rd)
{
    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND reg_n = alloc_gpr_src_ro(rn);
    IR2_OPND temp_cls = ra_alloc_itemp();
    IR2_OPND zero_label = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND exit_label = ir2_opnd_new_type(IR2_OPND_LABEL);
    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }

    if (sf) {
        la_bstrpick_d(temp_cls, reg_n, 63, 63);
        la_beqz(temp_cls, zero_label);
        la_clo_d(reg_d, reg_n);
        la_b(exit_label);
        la_label(zero_label);
        la_clz_d(reg_d, reg_n);
        la_label(exit_label);
    } else {
        la_bstrpick_d(temp_cls, reg_n, 31, 31);
        la_beqz(temp_cls, zero_label);
        la_clo_w(reg_d, reg_n);
        la_b(exit_label);
        la_label(zero_label);
        la_clz_w(reg_d, reg_n);
        la_label(exit_label);
    }
    la_addi_d(reg_d, reg_d, -1);

    if (arm_la_map[rd] >= 0 && rd != 31 && clearGprHigh) {
        set_w_write_flag(rd, TRUE);
    }

    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(temp_cls);
}

static void handle_rbit(DisasContext* s, unsigned int sf,
    unsigned int rn, unsigned int rd)
{
    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND reg_n = alloc_gpr_src(rn);
    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }

    if (sf) {
        la_bitrev_d(reg_d, reg_n);
    } else {
        la_bitrev_w(reg_d, reg_n);
    }

    if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, sf);
    } else {
        if (!sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }
    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_d);
}

/* REV with sf==1, opcode==3 ("REV64") */
static void handle_rev64(DisasContext* s, unsigned int sf,
    unsigned int rn, unsigned int rd)
{
    if (!sf) {
        lata_unallocated_encoding(s);
        return;
    }

    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND reg_n = alloc_gpr_src(rn);
    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }

    la_revb_d(reg_d, reg_n);

    if (arm_la_map[rd] >= 0 && rd != 31 && clearGprHigh) {
        set_w_write_flag(rd, TRUE);
    }

    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_d);
}

/* REV with sf==0, opcode==2
 * REV32 (sf==1, opcode==2)
 */
static void handle_rev32(DisasContext* s, unsigned int sf,
    unsigned int rn, unsigned int rd)
{
    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND reg_n = alloc_gpr_src(rn);
    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }

    la_revb_2w(reg_d, reg_n);

    if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, sf);
    } else {
        if (!sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_d);
}

/* REV16 (opcode==1) */
static void handle_rev16(DisasContext* s, unsigned int sf,
    unsigned int rn, unsigned int rd)
{
    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND reg_n = alloc_gpr_src(rn);
    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }

    if (sf) {
        la_revb_4h(reg_d, reg_n);
    } else {
        la_revb_2h(reg_d, reg_n);
    }

    if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, sf);
    } else {
        if (!sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_d);
}

/* Data-processing (1 source)
 *   31  30  29  28             21 20     16 15    10 9    5 4    0
 * +----+---+---+-----------------+---------+--------+------+------+
 * | sf | 1 | S | 1 1 0 1 0 1 1 0 | opcode2 | opcode |  Rn  |  Rd  |
 * +----+---+---+-----------------+---------+--------+------+------+
 */
static void disas_data_proc_1src(DisasContext* s, uint32_t insn)
{
    unsigned int sf, opcode, opcode2, rn, rd;

    if (extract32(insn, 29, 1)) {
        lata_unallocated_encoding(s);
        return;
    }

    sf = extract32(insn, 31, 1);
    opcode = extract32(insn, 10, 6);
    opcode2 = extract32(insn, 16, 5);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);

#define MAP(SF, O2, O1) ((SF) | (O1 << 1) | (O2 << 7))

    switch (MAP(sf, opcode2, opcode)) {
        case MAP(0, 0x00, 0x00): /* RBIT */
        case MAP(1, 0x00, 0x00):
            handle_rbit(s, sf, rn, rd);
            break;
        case MAP(0, 0x00, 0x01): /* REV16 */
        case MAP(1, 0x00, 0x01):
            handle_rev16(s, sf, rn, rd);
            break;
        case MAP(0, 0x00, 0x02): /* REV/REV32 */
        case MAP(1, 0x00, 0x02):
            handle_rev32(s, sf, rn, rd);
            break;
        case MAP(1, 0x00, 0x03): /* REV64 */
            handle_rev64(s, sf, rn, rd);
            break;
        case MAP(0, 0x00, 0x04): /* CLZ */
        case MAP(1, 0x00, 0x04):
            handle_clz(s, sf, rn, rd);
            break;
        case MAP(0, 0x00, 0x05): /* CLS */
        case MAP(1, 0x00, 0x05):
            handle_cls(s, sf, rn, rd);
            break;
        case MAP(1, 0x01, 0x00): /* PACIA */
        case MAP(1, 0x01, 0x01): /* PACIB */
        case MAP(1, 0x01, 0x02): /* PACDA */
        case MAP(1, 0x01, 0x03): /* PACDB */
        case MAP(1, 0x01, 0x04): /* AUTIA */
        case MAP(1, 0x01, 0x05): /* AUTIB */
        case MAP(1, 0x01, 0x06): /* AUTDA */
        case MAP(1, 0x01, 0x07): /* AUTDB */
        case MAP(1, 0x01, 0x08): /* PACIZA */
        case MAP(1, 0x01, 0x09): /* PACIZB */
        case MAP(1, 0x01, 0x0a): /* PACDZA */
        case MAP(1, 0x01, 0x0b): /* PACDZB */
        case MAP(1, 0x01, 0x0c): /* AUTIZA */
        case MAP(1, 0x01, 0x0d): /* AUTIZB */
        case MAP(1, 0x01, 0x0e): /* AUTDZA */
        case MAP(1, 0x01, 0x0f): /* AUTDZB */
        case MAP(1, 0x01, 0x10): /* XPACI */
        case MAP(1, 0x01, 0x11): /* XPACD */
            lata_unallocated_encoding(s);
            return;
            break;
        default:
            lata_unallocated_encoding(s);
            break;
    }

#undef MAP
}

static void handle_div(DisasContext* s, bool is_signed, unsigned int sf,
    unsigned int rm, unsigned int rn, unsigned int rd)
{
    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND reg_n = alloc_gpr_src_ro(rn);
    IR2_OPND reg_m = alloc_gpr_src_ro(rm);
    IR2_OPND temp_m = ra_alloc_itemp();
    IR2_OPND temp_n = ra_alloc_itemp();
    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }
    if (clearGprHigh && sf && arm_la_map[rm] >= 0 && rm != 31) {
        clear_gpr_high(rm);
    }

    if (is_signed) {
        if (sf) {
            la_div_d(reg_d, reg_n, reg_m);
        } else {
            la_bstrpick_w(temp_m, reg_m, 31, 0);
            la_bstrpick_w(temp_n, reg_n, 31, 0);
            la_div_d(reg_d, temp_n, temp_m);
        }
    } else {
        if (sf) {
            la_div_du(reg_d, reg_n, reg_m);
        } else {
            la_div_wu(reg_d, reg_n, reg_m);
        }
    }

    // arm : x / 0 = 0
    la_maskeqz(reg_d, reg_d, reg_m);

    if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, sf);
    } else {
        if (!sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_m);
    free_alloc_gpr(temp_m);
    free_alloc_gpr(temp_n);
}

/* LSLV, LSRV, ASRV, RORV */
static void handle_shift_reg(DisasContext* s,
    enum a64_shift_type shift_type, unsigned int sf,
    unsigned int rm, unsigned int rn, unsigned int rd)
{
    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND reg_n = alloc_gpr_src_ro(rn);
    IR2_OPND reg_m = alloc_gpr_src_ro(rm);
    if (clearGprHigh && sf && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }
    if (clearGprHigh && sf && arm_la_map[rm] >= 0 && rm != 31) {
        clear_gpr_high(rm);
    }

    switch (shift_type) {
        case A64_SHIFT_TYPE_LSL:
            if (sf) {
                la_sll_d(reg_d, reg_n, reg_m);
            } else {
                la_sll_w(reg_d, reg_n, reg_m);
            }
            break;
        case A64_SHIFT_TYPE_LSR:
            if (sf) {
                la_srl_d(reg_d, reg_n, reg_m);
            } else {
                la_srl_w(reg_d, reg_n, reg_m);
            }
            break;
        case A64_SHIFT_TYPE_ASR:
            if (sf) {
                la_sra_d(reg_d, reg_n, reg_m);
            } else {
                la_sra_w(reg_d, reg_n, reg_m);
            }
            break;
        case A64_SHIFT_TYPE_ROR:
            if (sf) {
                la_rotr_d(reg_d, reg_n, reg_m);
            } else {
                la_rotr_w(reg_d, reg_n, reg_m);
            }
            break;
        default:
            assert(FALSE); /* all shift types should be handled */
            break;
    }

    if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, sf);
    } else {
        if (!sf) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_m);
}

/* CRC32[BHWX], CRC32C[BHWX] */
static void handle_crc32(DisasContext* s,
    unsigned int sf, unsigned int sz, bool crc32c,
    unsigned int rm, unsigned int rn, unsigned int rd)
{
    if (!dc_isar_feature(aa64_crc32, s) || (sf == 1 && sz != 3) || (sf == 0 && sz == 3)) {
        lata_unallocated_encoding(s);
        return;
    }

    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND reg_n = alloc_gpr_src(rn);
    IR2_OPND reg_m = alloc_gpr_src(rm);

    if (clearGprHigh && arm_la_map[rn] >= 0 && rn != 31) {
        clear_gpr_high(rn);
    }

    if (clearGprHigh && arm_la_map[rm] >= 0 && rm != 31) {
        clear_gpr_high(rm);
    }

    if (crc32c) {
        switch (sz) {
            case 0:
                la_crcc_w_b_w(reg_d, reg_m, reg_n);
                break;
            case 1:
                la_crcc_w_h_w(reg_d, reg_m, reg_n);
                break;
            case 2:
                la_crcc_w_w_w(reg_d, reg_m, reg_n);
                break;
            case 3:
                la_crcc_w_d_w(reg_d, reg_m, reg_n);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
        }
    } else {
        switch (sz) {
            case 0:
                la_crc_w_b_w(reg_d, reg_m, reg_n);
                break;
            case 1:
                la_crc_w_h_w(reg_d, reg_m, reg_n);
                break;
            case 2:
                la_crc_w_w_w(reg_d, reg_m, reg_n);
                break;
            case 3:
                la_crc_w_d_w(reg_d, reg_m, reg_n);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
        }
    }

    if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, sf);
    }

    /* CRC32/CRC32C produce 32-bit results; LA .w ops sign-extend. Zero upper 32 bits. */
    la_bstrpick_d(reg_d, reg_d, 31, 0);

    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(reg_n);
    free_alloc_gpr(reg_m);
}

/* Data-processing (2 source)
 *   31   30  29 28             21 20  16 15    10 9    5 4    0
 * +----+---+---+-----------------+------+--------+------+------+
 * | sf | 0 | S | 1 1 0 1 0 1 1 0 |  Rm  | opcode |  Rn  |  Rd  |
 * +----+---+---+-----------------+------+--------+------+------+
 */
static void disas_data_proc_2src(DisasContext* s, uint32_t insn)
{
    unsigned int sf, rm, opcode, rn, rd, setflag;
    sf = extract32(insn, 31, 1);
    setflag = extract32(insn, 29, 1);
    rm = extract32(insn, 16, 5);
    opcode = extract32(insn, 10, 6);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);

    if (setflag && opcode != 0) {
        lata_unallocated_encoding(s);
        return;
    }

    switch (opcode) {
        case 0: /* SUBP(S) */
            if (sf == 0 || !dc_isar_feature(aa64_mte_insn_reg, s)) {
                goto do_unallocated;
            } else {
                lata_unallocated_encoding(s);
                return;
            }
            break;
        case 2: /* UDIV */
            handle_div(s, false, sf, rm, rn, rd);
            break;
        case 3: /* SDIV */
            handle_div(s, true, sf, rm, rn, rd);
            break;
        case 4: /* IRG */
            lata_unallocated_encoding(s);
            return;
            break;
        case 5: /* GMI */
            lata_unallocated_encoding(s);
            return;
            break;
        case 8: /* LSLV */
            handle_shift_reg(s, A64_SHIFT_TYPE_LSL, sf, rm, rn, rd);
            break;
        case 9: /* LSRV */
            handle_shift_reg(s, A64_SHIFT_TYPE_LSR, sf, rm, rn, rd);
            break;
        case 10: /* ASRV */
            handle_shift_reg(s, A64_SHIFT_TYPE_ASR, sf, rm, rn, rd);
            break;
        case 11: /* RORV */
            handle_shift_reg(s, A64_SHIFT_TYPE_ROR, sf, rm, rn, rd);
            break;
        case 12: /* PACGA */
            lata_unallocated_encoding(s);
            return;
            break;
        case 16:
        case 17:
        case 18:
        case 19:
        case 20:
        case 21:
        case 22:
        case 23: /* CRC32 */
        {
            int sz = extract32(opcode, 0, 2);
            bool crc32c = extract32(opcode, 2, 1);
            handle_crc32(s, sf, sz, crc32c, rm, rn, rd);
            break;
        }
        default:
        do_unallocated:
            lata_unallocated_encoding(s);
            break;
    }
}

/*
 * Data processing - register
 *  31  30 29  28      25    21  20  16      10         0
 * +--+---+--+---+-------+-----+-------+-------+---------+
 * |  |op0|  |op1| 1 0 1 | op2 |       |  op3  |         |
 * +--+---+--+---+-------+-----+-------+-------+---------+
 */
static bool disas_data_proc_reg(DisasContext* s)
{
    uint32_t insn = s->insn;
    int op0 = extract32(insn, 30, 1);
    int op1 = extract32(insn, 28, 1);
    int op2 = extract32(insn, 21, 4);
    int op3 = extract32(insn, 10, 6);

    if (!op1) {
        if (op2 & 8) {
            if (op2 & 1) {
                /* Add/sub (extended register) */
                disas_add_sub_ext_reg(s, insn);
            } else {
                /* Add/sub (shifted register) */
                disas_add_sub_reg(s, insn);
            }
        } else {
            /* Logical (shifted register) */
            disas_logic_reg(s, insn);
        }
        return true;
    }

    switch (op2) {
        case 0x0:
            switch (op3) {
                case 0x00: /* Add/subtract (with carry) */
                    disas_adc_sbc(s, insn);
                    break;

                case 0x01: /* Rotate right into flags */
                case 0x21:
                    lata_unallocated_encoding(s);
                    return true;
                    disas_rotate_right_into_flags(s, insn);
                    break;

                case 0x02: /* Evaluate into flags (SETF8/SETF16) */
                case 0x12:
                case 0x22:
                case 0x32:
                    disas_evaluate_into_flags(s, insn);
                    return true;

                default:
                    goto do_unallocated;
            }
            break;

        case 0x2:              /* Conditional compare */
            disas_cc(s, insn); /* both imm and reg forms */
            break;

        case 0x4: /* Conditional select */
            disas_cond_select(s, insn);
            break;

        case 0x6:      /* Data-processing */
            if (op0) { /* (1 source) */
                disas_data_proc_1src(s, insn);
            } else { /* (2 source) */
                disas_data_proc_2src(s, insn);
            }
            break;
        case 0x8 ... 0xf: /* (3 source) */
            disas_data_proc_3src(s, insn);
            break;

        default:
        do_unallocated:
            lata_unallocated_encoding(s);
            break;
    }

    return true;
}

static void handle_fp_compare(DisasContext* s, int size,
    unsigned int rn, unsigned int rm,
    bool cmp_with_zero, bool signal_all_nans)
{
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m;
    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND l_equal = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND l_less = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND l_greater = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND l_exit = ir2_opnd_new_type(IR2_OPND_LABEL);

    if (cmp_with_zero) {
        vreg_m = ra_alloc_ftemp();
        la_movgr2fr_d(vreg_m, zero_ir2_opnd);
    } else {
        vreg_m = alloc_fpr_src(rm);
    }

    /*  res     equal   less    greater     unordered
        NZCV    0110    1000    0010        0011
    */
    if (size == MO_64) {
        la_fcmp_cond_d(fcc0_ir2_opnd, vreg_n, vreg_m,
            signal_all_nans ? FCMP_COND_SEQ : FCMP_COND_CEQ);
        la_bcnez(fcc0_ir2_opnd, l_equal);
        la_fcmp_cond_d(fcc0_ir2_opnd, vreg_n, vreg_m,
            signal_all_nans ? FCMP_COND_SLT : FCMP_COND_CLT);
        la_bcnez(fcc0_ir2_opnd, l_less);
        la_fcmp_cond_d(fcc0_ir2_opnd, vreg_m, vreg_n,
            signal_all_nans ? FCMP_COND_SLT : FCMP_COND_CLT);
        la_bcnez(fcc0_ir2_opnd, l_greater);

        la_addi_d(temp, zero_ir2_opnd, 0b0011);
        la_b(l_exit);

        la_label(l_equal);
        la_addi_d(temp, zero_ir2_opnd, 0b0110);
        la_b(l_exit);

        la_label(l_less);
        la_addi_d(temp, zero_ir2_opnd, 0b1000);
        la_b(l_exit);

        la_label(l_greater);
        la_addi_d(temp, zero_ir2_opnd, 0b0010);

        la_label(l_exit);
        la_slli_d(temp, temp, 0x1c); /* 左移28位 */
        la_armmtflag(temp, 0x39);
    } else if (size == MO_32) {
        la_fcmp_cond_s(fcc0_ir2_opnd, vreg_n, vreg_m,
            signal_all_nans ? FCMP_COND_SEQ : FCMP_COND_CEQ);
        la_bcnez(fcc0_ir2_opnd, l_equal);
        la_fcmp_cond_s(fcc0_ir2_opnd, vreg_n, vreg_m,
            signal_all_nans ? FCMP_COND_SLT : FCMP_COND_CLT);
        la_bcnez(fcc0_ir2_opnd, l_less);
        la_fcmp_cond_s(fcc0_ir2_opnd, vreg_m, vreg_n,
            signal_all_nans ? FCMP_COND_SLT : FCMP_COND_CLT);
        la_bcnez(fcc0_ir2_opnd, l_greater);

        la_addi_d(temp, zero_ir2_opnd, 0b0011);
        la_b(l_exit);

        la_label(l_equal);
        la_addi_d(temp, zero_ir2_opnd, 0b0110);
        la_b(l_exit);

        la_label(l_less);
        la_addi_d(temp, zero_ir2_opnd, 0b1000);
        la_b(l_exit);

        la_label(l_greater);
        la_addi_d(temp, zero_ir2_opnd, 0b0010);

        la_label(l_exit);
        la_slli_d(temp, temp, 0x1c); /* 左移28位 */
        la_armmtflag(temp, 0x39);
    } else {
        lata_unallocated_encoding(s);
        return;
    }

    free_alloc_fpr(vreg_m);
    free_alloc_fpr(vreg_n);
    free_alloc_gpr(temp);
}

/* Floating point compare
 *   31  30  29 28       24 23  22  21 20  16 15 14 13  10    9    5 4     0
 * +---+---+---+-----------+------+---+------+-----+---------+------+-------+
 * | M | 0 | S | 1 1 1 1 0 | type | 1 |  Rm  | op  | 1 0 0 0 |  Rn  |  op2  |
 * +---+---+---+-----------+------+---+------+-----+---------+------+-------+
 */
static void disas_fp_compare(DisasContext* s, uint32_t insn)
{
    unsigned int mos, type, rm, op, rn, opc, op2r;
    int size;

    mos = extract32(insn, 29, 3);
    type = extract32(insn, 22, 2);
    rm = extract32(insn, 16, 5);
    op = extract32(insn, 14, 2);
    rn = extract32(insn, 5, 5);
    opc = extract32(insn, 3, 2);
    op2r = extract32(insn, 0, 3);

    if (mos || op || op2r) {
        lata_unallocated_encoding(s);
        return;
    }

    switch (type) {
        case 0:
            size = MO_32;
            break;
        case 1:
            size = MO_64;
            break;
        case 3:
            size = MO_16;
            if (dc_isar_feature(aa64_fp16, s)) {
                break;
            }
            /* fallthru */
        default:
            lata_unallocated_encoding(s);
            return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    handle_fp_compare(s, size, rn, rm, opc & 1, opc & 2);
}

/* Floating point conditional compare
 *   31  30  29 28       24 23  22  21 20  16 15  12 11 10 9    5  4   3    0
 * +---+---+---+-----------+------+---+------+------+-----+------+----+------+
 * | M | 0 | S | 1 1 1 1 0 | type | 1 |  Rm  | cond | 0 1 |  Rn  | op | nzcv |
 * +---+---+---+-----------+------+---+------+------+-----+------+----+------+
 */
static void disas_fp_ccomp(DisasContext* s, uint32_t insn)
{
    unsigned int mos, type, rm, cond, rn, op, nzcv;
    int size;

    mos = extract32(insn, 29, 3);
    type = extract32(insn, 22, 2);
    rm = extract32(insn, 16, 5);
    cond = extract32(insn, 12, 4);
    rn = extract32(insn, 5, 5);
    op = extract32(insn, 4, 1);
    nzcv = extract32(insn, 0, 4);

    if (mos) {
        lata_unallocated_encoding(s);
        return;
    }

    switch (type) {
        case 0:
            size = MO_32;
            break;
        case 1:
            size = MO_64;
            break;
        case 3:
            size = MO_16;
            if (dc_isar_feature(aa64_fp16, s)) {
                break;
            }
            /* fallthru */
        default:
            lata_unallocated_encoding(s);
            return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND label_match = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND label_end = ir2_opnd_new_type(IR2_OPND_LABEL);

    if (cond < 0x0e) { /* not always */
        la_setarmj(temp, cond);
        la_bnez(temp, label_match);

        /* nomatch: */
        la_addi_w(temp, zero_ir2_opnd, nzcv);
        la_slli_w(temp, temp, 28);
        la_armmtflag(temp, 0x39);
        la_b(label_end);

        la_label(label_match);
    }

    handle_fp_compare(s, size, rn, rm, false, op);

    if (cond < 0x0e) {
        la_label(label_end);
    }

    free_alloc_gpr(temp);
}

/* Floating point conditional select
 *   31  30  29 28       24 23  22  21 20  16 15  12 11 10 9    5 4    0
 * +---+---+---+-----------+------+---+------+------+-----+------+------+
 * | M | 0 | S | 1 1 1 1 0 | type | 1 |  Rm  | cond | 1 1 |  Rn  |  Rd  |
 * +---+---+---+-----------+------+---+------+------+-----+------+------+
 */
static void disas_fp_csel(DisasContext* s, uint32_t insn)
{
    unsigned int mos, type, rm, cond, rn, rd;

    mos = extract32(insn, 29, 3);
    type = extract32(insn, 22, 2);
    rm = extract32(insn, 16, 5);
    cond = extract32(insn, 12, 4);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);

    if (mos) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND l_false = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND l_end = ir2_opnd_new_type(IR2_OPND_LABEL);

    la_setarmj(temp, cond);
    la_beqz(temp, l_false);

    /* TRUE */
    switch (type) {
        case 0:
            la_fmov_s(vreg_d, vreg_n);
            la_movgr2frh_w(vreg_d, zero_ir2_opnd);
            break;
        case 1:
            la_fmov_d(vreg_d, vreg_n);
            break;
        case 3:
            lata_unallocated_encoding(s);
            return;
            if (dc_isar_feature(aa64_fp16, s)) {
                break;
            }
            /* fallthru */
        default:
            lata_unallocated_encoding(s);
            return;
    }
    la_b(l_end);

    /* FALSE */
    la_label(l_false);
    switch (type) {
        case 0:
            la_fmov_s(vreg_d, vreg_m);
            la_movgr2frh_w(vreg_d, zero_ir2_opnd);
            break;
        case 1:
            la_fmov_d(vreg_d, vreg_m);
            break;
        case 3:
            lata_unallocated_encoding(s);
            return;
            if (dc_isar_feature(aa64_fp16, s)) {
                break;
            }
            /* fallthru */
        default:
            lata_unallocated_encoding(s);
            return;
    }

    la_label(l_end);

    if (type == 0 || type == 1) {
        bool high_clean = fpr_clear_high_if_live(vreg_d, rd,
                                                 type == 0 ? 2 : 3);
        store_scalar_fpr_dst(rd, vreg_d, type == 0 ? 2 : 3, high_clean);
    } else {
        store_fpr_dst(rd, vreg_d);
    }
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
    free_alloc_gpr(temp);
}

/* Floating-point data-processing (1 source) - half precision */
static void handle_fp_1src_half(DisasContext* s, int opcode, int rd, int rn)
{
    /* LoongArch has no native half-precision computation instructions.
     * Strategy: convert half→single, do the operation in single precision,
     * then convert single→half.
     */
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp_s = ra_alloc_ftemp();
    IR2_OPND vtemp_result = ra_alloc_ftemp();
    IR2_OPND vtemp_abs = ra_alloc_ftemp();
    IR2_OPND temp = ra_alloc_itemp();

    /* Convert half→single for computation */
    la_vfcvtl_s_h(vtemp_s, vreg_n);
    la_vand_v(vtemp_s, vtemp_s, fsmask_ir2_opnd);

    switch (opcode) {
        case 0x0: /* FMOV */
            la_fmov_s(vtemp_result, vtemp_s);
            goto do_convert_back;
        case 0x1: /* FABS */
            la_fabs_s(vtemp_result, vtemp_s);
            goto do_convert_back;
        case 0x2: /* FNEG */
            la_fneg_s(vtemp_result, vtemp_s);
            goto do_convert_back;
        case 0x3: /* FSQRT */
            la_fsqrt_s(vtemp_result, vtemp_s);
            goto do_convert_back;
        case 0x8: /* FRINTN */
            la_vfrintrne_s(vtemp_result, vtemp_s);
            goto do_convert_back;
        case 0x9: /* FRINTP */
            la_vfrintrp_s(vtemp_result, vtemp_s);
            goto do_convert_back;
        case 0xa: /* FRINTM */
            la_vfrintrm_s(vtemp_result, vtemp_s);
            goto do_convert_back;
        case 0xb: /* FRINTZ */
            la_vfrintrz_s(vtemp_result, vtemp_s);
            goto do_convert_back;
        case 0xc:                                             /* FRINTA: sign(x) * floor(|x| + 0.5) */
            li_d(temp, 0x3f000000);                           /* 0.5f */
            la_movgr2fr_w(vtemp_abs, temp);                   /* vtemp_abs = 0.5f */
            la_fabs_s(vtemp_result, vtemp_s);                 /* vtemp_result = |x| */
            la_fadd_s(vtemp_abs, vtemp_result, vtemp_abs);    /* |x| + 0.5 */
            la_vfrintrm_s(vtemp_abs, vtemp_abs);              /* floor(|x| + 0.5) */
            la_fcopysign_s(vtemp_result, vtemp_abs, vtemp_s); /* sign(x) * result */
            goto do_convert_back;
        case 0xe: /* FRINTX */
            la_vfrint_s(vtemp_result, vtemp_s);
            goto do_convert_back;
        case 0xf: /* FRINTI */
            la_vfrint_s(vtemp_result, vtemp_s);
            goto do_convert_back;
        default:
            free_alloc_fpr(vtemp_s);
            free_alloc_fpr(vtemp_result);
            free_alloc_fpr(vtemp_abs);
            free_alloc_gpr(temp);
            lata_unallocated_encoding(s);
            return;
    }

do_convert_back:
{
    /* Convert single→half back to get final result */
    la_vfcvt_h_s(vreg_d, vtemp_result, vtemp_result);
    bool high_clean = fpr_clear_high_if_live(vreg_d, rd, 1);

    store_scalar_fpr_dst(rd, vreg_d, 1, high_clean);
}
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp_s);
    free_alloc_fpr(vtemp_result);
    free_alloc_fpr(vtemp_abs);
    free_alloc_gpr(temp);
}

/* Floating-point data-processing (1 source) - single precision */
static void handle_fp_1src_single(DisasContext* s, int opcode, int rd, int rn)
{
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND vreg_temp = ra_alloc_ftemp();
    IR2_OPND vreg_abs = ra_alloc_ftemp();

    switch (opcode) {
        case 0x0: /* FMOV */
            la_fmov_s(vreg_d, vreg_n);
            goto done;
        case 0x1: /* FABS */
            la_fabs_s(vreg_d, vreg_n);
            goto done;
        case 0x2: /* FNEG */
            la_fneg_s(vreg_d, vreg_n);
            goto done;
        case 0x3: /* FSQRT */
            la_fsqrt_s(vreg_d, vreg_n);
            goto done;
        case 0x6: /* BFCVT */
            // gen_fpst = gen_helper_bfcvt;
            break;
        case 0x8: /* FRINTN */
            la_vfrintrne_s(vreg_d, vreg_n);
            goto done;
            break;
        case 0x9: /* FRINTP */
            la_vfrintrp_s(vreg_d, vreg_n);
            goto done;
            break;
        case 0xa: /* FRINTM */
            la_vfrintrm_s(vreg_d, vreg_n);
            goto done;
            break;
        case 0xb: /* FRINTZ */
            la_vfrintrz_s(vreg_d, vreg_n);
            goto done;
            break;
        case 0xc: /* FRINTA */
            // res = sign(x) * floor(|x| + 0.5)
            li_d(temp, 0x3f000000); // 0.5
            la_movgr2fr_w(vreg_temp, temp);
            la_fabs_s(vreg_abs, vreg_n);
            la_fadd_s(vreg_abs, vreg_abs, vreg_temp);
            la_vfrintrm_s(vreg_abs, vreg_abs);
            la_fcopysign_s(vreg_d, vreg_abs, vreg_n);
            goto done;
            break;
        case 0xe: /* FRINTX */
            la_vfrint_s(vreg_d, vreg_n);
            goto done;
            break;
        case 0xf: /* FRINTI: round to integral per FPCR */
            la_vfrint_s(vreg_d, vreg_n);
            goto done;
            break;
        case 0x10: /* FRINT32Z */
            // rmode = FPROUNDING_ZERO;
            // gen_fpst = gen_helper_frint32_s;
            break;
        case 0x11: /* FRINT32X */
            // gen_fpst = gen_helper_frint32_s;
            break;
        case 0x12: /* FRINT64Z */
            // rmode = FPROUNDING_ZERO;
            // gen_fpst = gen_helper_frint64_s;
            break;
        case 0x13: /* FRINT64X */
            // gen_fpst = gen_helper_frint64_s;
            break;
        default:
            g_assert_not_reached();
    }

    lata_unallocated_encoding(s);
    return;

done:
{
    bool high_clean = fpr_clear_high_if_live(vreg_d, rd, 2);

    store_scalar_fpr_dst(rd, vreg_d, 2, high_clean);
}
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_gpr(temp);
    free_alloc_fpr(vreg_temp);
    free_alloc_fpr(vreg_abs);
}

/* Floating-point data-processing (1 source) - double precision */
static void handle_fp_1src_double(DisasContext* s, int opcode, int rd, int rn)
{
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND vreg_temp = ra_alloc_ftemp();
    IR2_OPND vreg_abs = ra_alloc_ftemp();

    switch (opcode) {
        case 0x0: /* FMOV */
            la_fmov_d(vreg_d, vreg_n);
            goto done;
        case 0x1: /* FABS */
            la_fabs_d(vreg_d, vreg_n);
            goto done;
        case 0x2: /* FNEG */
            la_fneg_d(vreg_d, vreg_n);
            goto done;
        case 0x3: /* FSQRT */
            la_fsqrt_d(vreg_d, vreg_n);
            goto done;
        case 0x8: /* FRINTN */
            la_vfrintrne_d(vreg_d, vreg_n);
            goto done;
            break;
        case 0x9: /* FRINTP */
            la_vfrintrp_d(vreg_d, vreg_n);
            goto done;
            break;
        case 0xa: /* FRINTM */
            la_vfrintrm_d(vreg_d, vreg_n);
            goto done;
            break;
        case 0xb: /* FRINTZ */
            la_vfrintrz_d(vreg_d, vreg_n);
            goto done;
            break;
        case 0xc: /* FRINTA */
            // res = sign(x) * floor(|x| + 0.5)
            li_d(temp, 0x3fe0000000000000); // 0.5
            la_movgr2fr_d(vreg_temp, temp);
            la_fabs_d(vreg_abs, vreg_n);
            la_fadd_d(vreg_abs, vreg_abs, vreg_temp);
            la_vfrintrm_d(vreg_abs, vreg_abs);
            la_fcopysign_d(vreg_d, vreg_abs, vreg_n);
            goto done;
            break;
        case 0xe: /* FRINTX */
            la_vfrint_d(vreg_d, vreg_n);
            goto done;
            break;
        case 0xf: /* FRINTI: round to integral per FPCR */
            la_vfrint_d(vreg_d, vreg_n);
            goto done;
            break;
        case 0x10: /* FRINT32Z */
            // rmode = FPROUNDING_ZERO;
            // gen_fpst = gen_helper_frint32_d;
            break;
        case 0x11: /* FRINT32X */
            // gen_fpst = gen_helper_frint32_d;
            break;
        case 0x12: /* FRINT64Z */
            // rmode = FPROUNDING_ZERO;
            // gen_fpst = gen_helper_frint64_d;
            break;
        case 0x13: /* FRINT64X */
            // gen_fpst = gen_helper_frint64_d;
            break;
        default:
            g_assert_not_reached();
    }

    lata_unallocated_encoding(s);
    return;

done:
{
    bool high_clean = fpr_clear_high_if_live(vreg_d, rd, 3);

    store_scalar_fpr_dst(rd, vreg_d, 3, high_clean);
}
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_gpr(temp);
    free_alloc_fpr(vreg_temp);
    free_alloc_fpr(vreg_abs);
}

static void handle_fp_fcvt(DisasContext* s, int opcode,
    int rd, int rn, int dtype, int ntype)
{
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);

    switch (ntype) {
        case 0x0: {
            if (dtype == 1) {
                /* Single to double */
                la_fcvt_d_s(vreg_d, vreg_n);
            } else {
                /* Single to half.  vfcvt.h.s writes the half results into the
                 * low 64 bits from its third source, so keep the scalar value
                 * in lane 0 and clear the rest after packing. */
                la_vfcvt_h_s(vreg_d, vreg_n, vreg_n);
            }
            break;
        }
        case 0x1: {
            if (dtype == 0) {
                /* Double to single */
                la_fcvt_s_d(vreg_d, vreg_n);
            } else {
                /* Double to half: first double→single, then single→half */
                IR2_OPND vtemp = ra_alloc_ftemp();
                la_fcvt_s_d(vtemp, vreg_n);
                la_vfcvt_h_s(vreg_d, vtemp, vtemp);
                free_alloc_fpr(vtemp);
            }
            break;
        }
        case 0x3: {
            if (dtype == 0) {
                /* Half to single */
                la_vfcvtl_s_h(vreg_d, vreg_n);
                la_vand_v(vreg_d, vreg_d, fsmask_ir2_opnd);
            } else {
                /* Half to double: first half→single, then single→double */
                IR2_OPND vtemp = ra_alloc_ftemp();
                la_vfcvtl_s_h(vtemp, vreg_n);
                la_vand_v(vtemp, vtemp, fsmask_ir2_opnd);
                la_fcvt_d_s(vreg_d, vtemp);
                free_alloc_fpr(vtemp);
            }
            break;
        }
        default:
            g_assert_not_reached();
    }

    {
        unsigned out_size = fp_type_to_vec_size(dtype);
        bool high_clean = fpr_clear_high_if_live(vreg_d, rd, out_size);
        store_scalar_fpr_dst(rd, vreg_d, out_size, high_clean);
    }
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
}

/* Floating point data-processing (1 source)
 *   31  30  29 28       24 23  22  21 20    15 14       10 9    5 4    0
 * +---+---+---+-----------+------+---+--------+-----------+------+------+
 * | M | 0 | S | 1 1 1 1 0 | type | 1 | opcode | 1 0 0 0 0 |  Rn  |  Rd  |
 * +---+---+---+-----------+------+---+--------+-----------+------+------+
 */
static void disas_fp_1src(DisasContext* s, uint32_t insn)
{
    int mos = extract32(insn, 29, 3);
    int type = extract32(insn, 22, 2);
    int opcode = extract32(insn, 15, 6);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);

    if (mos) {
        goto do_unallocated;
    }

    switch (opcode) {
        case 0x4:
        case 0x5:
        case 0x7: {
            /* FCVT between half, single and double precision */
            int dtype = extract32(opcode, 0, 2);
            if (type == 2 || dtype == type) {
                goto do_unallocated;
            }
            if (!fp_access_check(s)) {
                return;
            }

            handle_fp_fcvt(s, opcode, rd, rn, dtype, type);
            break;
        }

        case 0x10 ... 0x13: /* FRINT{32,64}{X,Z} */
            if (type > 1 || !dc_isar_feature(aa64_frint, s)) {
                goto do_unallocated;
            }
            /* fall through */
        case 0x0 ... 0x3:
        case 0x8 ... 0xc:
        case 0xe ... 0xf:
            /* 32-to-32 and 64-to-64 ops */
            switch (type) {
                case 0:
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_fp_1src_single(s, opcode, rd, rn);
                    break;
                case 1:
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_fp_1src_double(s, opcode, rd, rn);
                    break;
                case 3:
                    if (!dc_isar_feature(aa64_fp16, s)) {
                        goto do_unallocated;
                    }

                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_fp_1src_half(s, opcode, rd, rn);
                    break;
                default:
                    goto do_unallocated;
            }
            break;

        case 0x6:
            switch (type) {
                case 1: /* BFCVT */
                    if (!dc_isar_feature(aa64_bf16, s)) {
                        goto do_unallocated;
                    }
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_fp_1src_single(s, opcode, rd, rn);
                    break;
                default:
                    goto do_unallocated;
            }
            break;

        default:
        do_unallocated:
            lata_unallocated_encoding(s);
            break;
    }
}

/* Replace NaN result with default NaN when FPCR.DN is set.
 * Must be called before store_fpr_dst/vand_v fsmask. */
static void sanitize_fpcr_dn(IR2_OPND vreg_d, bool is_double)
{
    if (!option_fp_precise) return;

    IR2_OPND fpcr = ra_alloc_itemp();
    IR2_OPND imm_tmp = ra_alloc_itemp();
    IR2_OPND label_done = ir2_opnd_new_type(IR2_OPND_LABEL);

    li_d(fpcr, env_offset_FPSCR());
    la_ldx_wu(fpcr, env_ir2_opnd, fpcr);
    li_d(imm_tmp, (1 << 25)); /* FPCR.DN = bit 25 */
    la_and(fpcr, fpcr, imm_tmp);
    free_alloc_gpr(imm_tmp);
    la_beqz(fpcr, label_done);

    /* Detect NaN: vfcmp.cun dest, dest, dest → all 1s if NaN */
    IR2_OPND nan_mask = ra_alloc_ftemp();
    if (is_double) {
        la_vfcmp_cond_d(nan_mask, vreg_d, vreg_d, FCMP_COND_CUN);
    } else {
        la_vfcmp_cond_s(nan_mask, vreg_d, vreg_d, FCMP_COND_CUN);
    }

    /* Load default NaN and replace via vbitsel */
    IR2_OPND default_nan = ra_alloc_ftemp();
    if (is_double) {
        li_d(fpcr, 0x7ff8000000000000ULL);
        la_vreplgr2vr_d(default_nan, fpcr);
    } else {
        li_d(fpcr, 0x7fc00000);
        la_vreplgr2vr_w(default_nan, fpcr);
    }
    la_vbitsel_v(vreg_d, vreg_d, default_nan, nan_mask);

    free_alloc_fpr(nan_mask);
    free_alloc_fpr(default_nan);

    la_label(label_done);
    free_alloc_gpr(fpcr);
}

/* Floating-point data-processing (2 source) - single precision */
static void handle_fp_2src_single(DisasContext* s, int opcode,
    int rd, int rn, int rm)
{
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vtemp, vtemp1;

    switch (opcode) {
        case 0x0: /* FMUL */
            la_fmul_s(vreg_d, vreg_n, vreg_m);
            break;
        case 0x1: /* FDIV */
            la_fdiv_s(vreg_d, vreg_n, vreg_m);
            break;
        case 0x2: /* FADD */
            la_fadd_s(vreg_d, vreg_n, vreg_m);
            break;
        case 0x3: /* FSUB */
            la_fsub_s(vreg_d, vreg_n, vreg_m);
            break;
        case 0x4: /* FMAX */
        case 0x5: /* FMIN */
            vtemp = ra_alloc_ftemp();
            vtemp1 = ra_alloc_ftemp();
            if (opcode & 0x1) {
                la_fmin_s(vtemp, vreg_n, vreg_m);
            } else {
                la_fmax_s(vtemp, vreg_n, vreg_m);
            }
            la_fcmp_cond_s(fcc0_ir2_opnd, vreg_n, vreg_m, FCMP_COND_CUN);
            la_fcmp_cond_s(fcc1_ir2_opnd, vreg_n, vreg_n, FCMP_COND_CUN);
            la_fsel(vtemp1, vreg_m, vreg_n, fcc1_ir2_opnd);
            la_fsel(vreg_d, vtemp, vtemp1, fcc0_ir2_opnd);
            free_alloc_fpr(vtemp);
            free_alloc_fpr(vtemp1);
            break;
        case 0x6: /* FMAXNM */
            la_fmax_s(vreg_d, vreg_n, vreg_m);
            break;
        case 0x7: /* FMINNM */
            la_fmin_s(vreg_d, vreg_n, vreg_m);
            break;
        case 0x8: /* FNMUL */
            la_fmul_s(vreg_d, vreg_n, vreg_m);
            la_fneg_s(vreg_d, vreg_d);
            break;
    }
    sanitize_fpcr_dn(vreg_d, false);
    bool high_clean = fpr_clear_high_if_live(vreg_d, rd, 2);

    store_scalar_fpr_dst(rd, vreg_d, 2, high_clean);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
}

/* Floating-point data-processing (2 source) - double precision */
static void handle_fp_2src_double(DisasContext* s, int opcode,
    int rd, int rn, int rm)
{
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vtemp, vtemp1;

    switch (opcode) {
        case 0x0: /* FMUL */
            la_fmul_d(vreg_d, vreg_n, vreg_m);
            break;
        case 0x1: /* FDIV */
            la_fdiv_d(vreg_d, vreg_n, vreg_m);
            break;
        case 0x2: /* FADD */
            la_fadd_d(vreg_d, vreg_n, vreg_m);
            break;
        case 0x3: /* FSUB */
            la_fsub_d(vreg_d, vreg_n, vreg_m);
            break;
        case 0x4: /* FMAX */
        case 0x5: /* FMIN */
            vtemp = ra_alloc_ftemp();
            vtemp1 = ra_alloc_ftemp();
            if (opcode & 0x1) {
                la_fmin_d(vtemp, vreg_n, vreg_m);
            } else {
                la_fmax_d(vtemp, vreg_n, vreg_m);
            }
            la_fcmp_cond_d(fcc0_ir2_opnd, vreg_n, vreg_m, FCMP_COND_CUN);
            la_fcmp_cond_d(fcc1_ir2_opnd, vreg_n, vreg_n, FCMP_COND_CUN);
            la_fsel(vtemp1, vreg_m, vreg_n, fcc1_ir2_opnd);
            la_fsel(vreg_d, vtemp, vtemp1, fcc0_ir2_opnd);
            free_alloc_fpr(vtemp);
            free_alloc_fpr(vtemp1);
            break;
        case 0x6: /* FMAXNM */
            la_fmax_d(vreg_d, vreg_n, vreg_m);
            break;
        case 0x7: /* FMINNM */
            la_fmin_d(vreg_d, vreg_n, vreg_m);
            break;
        case 0x8: /* FNMUL */
            la_fmul_d(vreg_d, vreg_n, vreg_m);
            la_fneg_d(vreg_d, vreg_d);
            break;
    }
    bool high_clean = fpr_clear_high_if_live(vreg_d, rd, 3);

    store_scalar_fpr_dst(rd, vreg_d, 3, high_clean);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
}

/* Floating-point data-processing (2 source) - half precision */
static void handle_fp_2src_half(DisasContext* s, int opcode,
    int rd, int rn, int rm) { lata_unallocated_encoding(s); }

/* Floating point data-processing (2 source)
 *   31  30  29 28       24 23  22  21 20  16 15    12 11 10 9    5 4    0
 * +---+---+---+-----------+------+---+------+--------+-----+------+------+
 * | M | 0 | S | 1 1 1 1 0 | type | 1 |  Rm  | opcode | 1 0 |  Rn  |  Rd  |
 * +---+---+---+-----------+------+---+------+--------+-----+------+------+
 */

static void disas_simd_two_reg_misc(DisasContext* s, uint32_t insn);
static void disas_fp_2src(DisasContext* s, uint32_t insn)
{
    int mos = extract32(insn, 29, 3);
    int type = extract32(insn, 22, 2);
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int rm = extract32(insn, 16, 5);
    int opcode = extract32(insn, 12, 4);

    if (opcode > 8 || mos) {
        lata_unallocated_encoding(s);
        return;
    }

    switch (type) {
        case 0:
            if (!fp_access_check(s)) {
                return;
            }
            handle_fp_2src_single(s, opcode, rd, rn, rm);
            break;
        case 1:
            if (!fp_access_check(s)) {
                return;
            }
            handle_fp_2src_double(s, opcode, rd, rn, rm);
            break;
        case 3:
            if (!dc_isar_feature(aa64_fp16, s)) {
                lata_unallocated_encoding(s);
                return;
            }
            if (!fp_access_check(s)) {
                return;
            }
            handle_fp_2src_half(s, opcode, rd, rn, rm);
            break;
        default:
            lata_unallocated_encoding(s);
    }
}

/* Floating-point data-processing (3 source) - single precision */
static void handle_fp_3src_single(DisasContext* s, bool o0, bool o1,
    int rd, int rn, int rm, int ra)
{
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vreg_a = alloc_fpr_src(ra);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp1 = ra_alloc_ftemp();

    /* These are fused multiply-add, and must be done as one
     * floating point operation with no rounding between the
     * multiplication and addition steps.
     * NB that doing the negations here as separate steps is
     * correct : an input NaN should come out with its sign bit
     * flipped if it is a negated-input.
     */

    if (o0 != o1) {
        la_fneg_s(vtemp, vreg_n);
        if (o1 == true) { /* FNMADD */
            la_fneg_s(vtemp1, vreg_a);
            la_fmadd_s(vreg_d, vtemp, vreg_m, vtemp1);
        } else { /* FMSUB */
            la_fmadd_s(vreg_d, vtemp, vreg_m, vreg_a);
        }
    } else {
        if (o1 == true) { /* FNMSUB */
            la_fneg_s(vtemp1, vreg_a);
            la_fmadd_s(vreg_d, vreg_n, vreg_m, vtemp1);
        } else { /* FMADD */
            la_fmadd_s(vreg_d, vreg_n, vreg_m, vreg_a);
        }
    }
    sanitize_fpcr_dn(vreg_d, false);
    bool high_clean = fpr_clear_high_if_live(vreg_d, rd, 2);

    store_scalar_fpr_dst(rd, vreg_d, 2, high_clean);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
    free_alloc_fpr(vreg_a);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp1);
}

/* Floating-point data-processing (3 source) - double precision */
static void handle_fp_3src_double(DisasContext* s, bool o0, bool o1,
    int rd, int rn, int rm, int ra)
{
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vreg_a = alloc_fpr_src(ra);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp1 = ra_alloc_ftemp();

    /* These are fused multiply-add, and must be done as one
     * floating point operation with no rounding between the
     * multiplication and addition steps.
     * NB that doing the negations here as separate steps is
     * correct : an input NaN should come out with its sign bit
     * flipped if it is a negated-input.
     */

    if (o0 != o1) {
        la_fneg_d(vtemp, vreg_n);
        if (o1 == true) { /* FNMADD */
            la_fneg_d(vtemp1, vreg_a);
            la_fmadd_d(vreg_d, vtemp, vreg_m, vtemp1);
        } else { /* FMSUB */
            la_fmadd_d(vreg_d, vtemp, vreg_m, vreg_a);
        }
    } else {
        if (o1 == true) { /* FNMSUB */
            la_fneg_d(vtemp1, vreg_a);
            la_fmadd_d(vreg_d, vreg_n, vreg_m, vtemp1);
        } else { /* FMADD */
            la_fmadd_d(vreg_d, vreg_n, vreg_m, vreg_a);
        }
    }
    bool high_clean = fpr_clear_high_if_live(vreg_d, rd, 3);

    store_scalar_fpr_dst(rd, vreg_d, 3, high_clean);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
    free_alloc_fpr(vreg_a);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp1);
}

/* Floating-point data-processing (3 source) - half precision */
static void handle_fp_3src_half(DisasContext* s, bool o0, bool o1,
    int rd, int rn, int rm, int ra) { lata_unallocated_encoding(s); }

/* Floating point data-processing (3 source)
 *   31  30  29 28       24 23  22  21  20  16  15  14  10 9    5 4    0
 * +---+---+---+-----------+------+----+------+----+------+------+------+
 * | M | 0 | S | 1 1 1 1 1 | type | o1 |  Rm  | o0 |  Ra  |  Rn  |  Rd  |
 * +---+---+---+-----------+------+----+------+----+------+------+------+
 */
static void disas_fp_3src(DisasContext* s, uint32_t insn)
{
    int mos = extract32(insn, 29, 3);
    int type = extract32(insn, 22, 2);
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int ra = extract32(insn, 10, 5);
    int rm = extract32(insn, 16, 5);
    bool o0 = extract32(insn, 15, 1);
    bool o1 = extract32(insn, 21, 1);

    if (mos) {
        lata_unallocated_encoding(s);
        return;
    }

    switch (type) {
        case 0:
            if (!fp_access_check(s)) {
                return;
            }
            handle_fp_3src_single(s, o0, o1, rd, rn, rm, ra);
            break;
        case 1:
            if (!fp_access_check(s)) {
                return;
            }
            handle_fp_3src_double(s, o0, o1, rd, rn, rm, ra);
            break;
        case 3:
            if (!dc_isar_feature(aa64_fp16, s)) {
                lata_unallocated_encoding(s);
                return;
            }
            if (!fp_access_check(s)) {
                return;
            }
            handle_fp_3src_half(s, o0, o1, rd, rn, rm, ra);
            break;
        default:
            lata_unallocated_encoding(s);
    }
}

/* Floating point immediate
 *   31  30  29 28       24 23  22  21 20        13 12   10 9    5 4    0
 * +---+---+---+-----------+------+---+------------+-------+------+------+
 * | M | 0 | S | 1 1 1 1 0 | type | 1 |    imm8    | 1 0 0 | imm5 |  Rd  |
 * +---+---+---+-----------+------+---+------------+-------+------+------+
 */
static void disas_fp_imm(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int imm5 = extract32(insn, 5, 5);
    int imm8 = extract32(insn, 13, 8);
    int type = extract32(insn, 22, 2);
    int mos = extract32(insn, 29, 3);
    uint64_t imm;
    MemOp sz;

    if (mos || imm5) {
        lata_unallocated_encoding(s);
        return;
    }

    switch (type) {
        case 0:
            sz = MO_32;
            break;
        case 1:
            sz = MO_64;
            break;
        case 3:
            sz = MO_16;
            if (dc_isar_feature(aa64_fp16, s)) {
                break;
            }
            /* fallthru */
        default:
            lata_unallocated_encoding(s);
            return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    imm = vfp_expand_imm(sz, imm8);
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND temp = ra_alloc_itemp();

    li_d(temp, (int64_t)imm);
    la_movgr2fr_d(vreg_d, temp);
    /* 高64位清零 */
    la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_gpr(temp);
}

/* Handle floating point <=> fixed point conversions. Note that we can
 * also deal with fp <=> integer conversions as a special case (scale == 64)
 * OPTME: consider handling that special case specially or at least skipping
 * the call to scalbn in the helpers for zero shifts.
 */
static uint32_t fp32_pow2_bits(int exp)
{
    return (uint32_t)(127 + exp) << 23;
}

static uint64_t fp64_pow2_bits(int exp)
{
    return (uint64_t)(1023 + exp) << 52;
}

static bool handle_fp_to_uint_rz_fastpath(DisasContext *s, int rd, int rn,
    int scale, int sf, int type)
{
    if (scale != 64 || (type != 0 && type != 1)) {
        return false;
    }

    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vbound = ra_alloc_ftemp();
    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND done = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND high_half = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND saturate = ir2_opnd_new_type(IR2_OPND_LABEL);

    la_mov64(reg_d, zero_ir2_opnd);

    if (type == 0) {
        la_movgr2fr_w(vbound, zero_ir2_opnd);
        la_fcmp_cond_s(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
        la_bceqz(fcc0_ir2_opnd, done);

        li_w(temp, sf ? 0x5f800000u : 0x4f800000u);
        la_movgr2fr_w(vbound, temp);
        la_fcmp_cond_s(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
        la_bcnez(fcc0_ir2_opnd, saturate);

        if (sf) {
            li_w(temp, 0x5f000000u); /* 2^63 as f32 */
            la_movgr2fr_w(vbound, temp);
            la_fcmp_cond_s(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
            la_bcnez(fcc0_ir2_opnd, high_half);
            la_ftintrz_l_s(vtemp, vreg_n);
            la_movfr2gr_d(reg_d, vtemp);
            la_b(done);

            la_label(high_half);
            la_fsub_s(vtemp, vreg_n, vbound);
            la_ftintrz_l_s(vtemp, vtemp);
            la_movfr2gr_d(reg_d, vtemp);
            la_bstrins_d(reg_d, zero_ir2_opnd, 62, 0);
            li_d(temp, 0x8000000000000000ULL);
            la_or(reg_d, reg_d, temp);
        } else {
            li_w(temp, 0x4f000000u); /* 2^31 as f32 */
            la_movgr2fr_w(vbound, temp);
            la_fcmp_cond_s(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
            la_bcnez(fcc0_ir2_opnd, high_half);
            la_ftintrz_w_s(vtemp, vreg_n);
            la_movfr2gr_s(reg_d, vtemp);
            la_b(done);

            la_label(high_half);
            la_fsub_s(vtemp, vreg_n, vbound);
            la_ftintrz_w_s(vtemp, vtemp);
            la_movfr2gr_s(reg_d, vtemp);
            li_wu(temp, 0x80000000u);
            la_add_d(reg_d, reg_d, temp);
        }
    } else {
        la_movgr2fr_d(vbound, zero_ir2_opnd);
        la_fcmp_cond_d(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
        la_bceqz(fcc0_ir2_opnd, done);

        li_d(temp, sf ? 0x43f0000000000000ULL : 0x41f0000000000000ULL);
        la_movgr2fr_d(vbound, temp);
        la_fcmp_cond_d(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
        la_bcnez(fcc0_ir2_opnd, saturate);

        if (sf) {
            li_d(temp, 0x43e0000000000000ULL); /* 2^63 as f64 */
            la_movgr2fr_d(vbound, temp);
            la_fcmp_cond_d(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
            la_bcnez(fcc0_ir2_opnd, high_half);
            la_ftintrz_l_d(vtemp, vreg_n);
            la_movfr2gr_d(reg_d, vtemp);
            la_b(done);

            la_label(high_half);
            la_fsub_d(vtemp, vreg_n, vbound);
            la_ftintrz_l_d(vtemp, vtemp);
            la_movfr2gr_d(reg_d, vtemp);
            la_bstrins_d(reg_d, zero_ir2_opnd, 62, 0);
            li_d(temp, 0x8000000000000000ULL);
            la_or(reg_d, reg_d, temp);
        } else {
            li_d(temp, 0x41e0000000000000ULL); /* 2^31 as f64 */
            la_movgr2fr_d(vbound, temp);
            la_fcmp_cond_d(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
            la_bcnez(fcc0_ir2_opnd, high_half);
            la_ftintrz_w_d(vtemp, vreg_n);
            la_movfr2gr_s(reg_d, vtemp);
            la_b(done);

            la_label(high_half);
            la_fsub_d(vtemp, vreg_n, vbound);
            la_ftintrz_w_d(vtemp, vtemp);
            la_movfr2gr_s(reg_d, vtemp);
            li_wu(temp, 0x80000000u);
            la_add_d(reg_d, reg_d, temp);
        }
    }
    la_b(done);

    la_label(saturate);
    if (sf) {
        li_d(reg_d, UINT64_MAX);
    } else {
        li_wu(reg_d, UINT32_MAX);
    }

    la_label(done);
    if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, sf);
    } else if (!sf) {
        la_bstrpick_d(reg_d, reg_d, 31, 0);
    }
    store_gpr_dst(rd, reg_d);
    free_alloc_gpr(reg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vbound);
    free_alloc_gpr(temp);
    return true;
}

static void handle_fpfpcvt(DisasContext* s, int rd, int rn, int opcode,
    bool itof, int rmode, int scale, int sf, int type)
{
    bool is_signed = !(opcode & 1);

    if (itof) {
        IR2_OPND vreg_d = alloc_fpr_dst(rd);
        IR2_OPND reg_n = alloc_gpr_src(rn);
        IR2_OPND vtemp = ra_alloc_ftemp();

        if (sf && clearGprHigh && arm_la_map[rn] >= 0 && rn != 31) {
            clear_gpr_high(rn);
        }

        switch (type) {
            case 1: /* float64 */
                if (sf) {
                    la_movgr2fr_d(vtemp, reg_n);
                    if (is_signed) {
                        la_vffint_d_l(vreg_d, vtemp);
                    } else {
                        la_vffint_d_lu(vreg_d, vtemp);
                    }
                } else {
                    la_movgr2fr_w(vtemp, reg_n);
                    if (is_signed) {
                        la_ffint_d_w(vreg_d, vtemp);
                    } else {
                        la_movgr2frh_w(vtemp, zero_ir2_opnd);
                        la_vffint_d_lu(vreg_d, vtemp);
                    }
                }
                break;
            case 0: /* float32 */
                if (sf) {
                    la_movgr2fr_d(vtemp, reg_n);
                    if (is_signed) {
                        la_ffint_s_l(vreg_d, vtemp);
                    } else {
                        la_vffint_d_lu(vtemp, vtemp);
                        la_fcvt_s_d(vreg_d, vtemp);
                    }
                } else {
                    la_movgr2fr_w(vtemp, reg_n);
                    if (is_signed) {
                        la_vffint_s_w(vreg_d, vtemp);
                    } else {
                        la_vffint_s_wu(vreg_d, vtemp);
                    }
                }
                break;

            case 3: /* float16 */
            {
                /* Integer to float16: generate float32 first, then narrow to float16 */
                IR2_OPND vtemp_f32 = ra_alloc_ftemp();
                if (sf) {
                    la_movgr2fr_d(vtemp, reg_n);
                    if (is_signed) {
                        la_vffint_d_l(vtemp_f32, vtemp);
                    } else {
                        la_vffint_d_lu(vtemp_f32, vtemp);
                    }
                } else {
                    la_movgr2fr_w(vtemp, reg_n);
                    if (is_signed) {
                        la_vffint_s_w(vtemp_f32, vtemp);
                    } else {
                        la_vffint_s_wu(vtemp_f32, vtemp);
                    }
                }
                la_vfcvt_h_s(vreg_d, vtemp_f32, vtemp_f32);
                free_alloc_fpr(vtemp_f32);
                break;
            }

            default:
                g_assert_not_reached();
        }
        if (scale != 64) {
            IR2_OPND vscale = ra_alloc_ftemp();
            IR2_OPND temp = ra_alloc_itemp();
            int fracbits = 64 - scale;

            if (type == 1) {
                li_d(temp, fp64_pow2_bits(-fracbits));
                la_movgr2fr_d(vscale, temp);
                la_fmul_d(vreg_d, vreg_d, vscale);
            } else {
                li_w(temp, fp32_pow2_bits(-fracbits));
                la_movgr2fr_w(vscale, temp);
                if (type == 3) {
                    IR2_OPND vtemp_f32 = ra_alloc_ftemp();
                    la_vfcvtl_s_h(vtemp_f32, vreg_d);
                    la_vand_v(vtemp_f32, vtemp_f32, fsmask_ir2_opnd);
                    la_fmul_s(vtemp_f32, vtemp_f32, vscale);
                    la_vfcvt_h_s(vreg_d, vtemp_f32, vtemp_f32);
                    free_alloc_fpr(vtemp_f32);
                } else {
                    la_fmul_s(vreg_d, vreg_d, vscale);
                }
            }
            free_alloc_fpr(vscale);
            free_alloc_gpr(temp);
        }
        {
            unsigned out_size = fp_type_to_vec_size(type);
            bool high_clean = fpr_clear_high_if_live(vreg_d, rd, out_size);
            store_scalar_fpr_dst(rd, vreg_d, out_size, high_clean);
        }
        free_alloc_fpr(vreg_d);
        free_alloc_fpr(vtemp);
        free_alloc_gpr(reg_n);
    } else {

        if (!is_signed && rmode == FPROUNDING_ZERO &&
            handle_fp_to_uint_rz_fastpath(s, rd, rn, scale, sf, type)) {
            return;
        }

        if (extract32(opcode, 2, 1)) {
            /* There are too many rounding modes to all fit into rmode,
             * so FCVTA[US] is a special case.
             */
            rmode = FPROUNDING_TIEAWAY;
        }
        if (!extract32(opcode, 2, 1) && scale != 64 && type != 3) {
            IR2_OPND reg_d = alloc_gpr_dst(rd);
            IR2_OPND vreg_n = alloc_fpr_src(rn);
            IR2_OPND vscaled = ra_alloc_ftemp();
            IR2_OPND vscale = ra_alloc_ftemp();
            IR2_OPND temp = ra_alloc_itemp();
            int fracbits = 64 - scale;

            if (type == 1) {
                li_d(temp, fp64_pow2_bits(fracbits));
                la_movgr2fr_d(vscale, temp);
                la_fmul_d(vscaled, vreg_n, vscale);
                if (sf) {
                    if (is_signed) {
                        la_ftintrz_l_d(vscaled, vscaled);
                    } else {
                        la_vftintrz_lu_d(vscaled, vscaled);
                    }
                    la_movfr2gr_d(reg_d, vscaled);
                } else {
                    if (is_signed) {
                        la_ftintrz_w_d(vscaled, vscaled);
                    } else {
                        la_vftintrz_wu_s(vscaled, vscaled);
                    }
                    la_movfr2gr_s(reg_d, vscaled);
                }
            } else {
                li_w(temp, fp32_pow2_bits(fracbits));
                la_movgr2fr_w(vscale, temp);
                la_fmul_s(vscaled, vreg_n, vscale);
                if (sf) {
                    if (is_signed) {
                        la_ftintrz_l_s(vscaled, vscaled);
                    } else {
                        la_vftintrz_lu_d(vscaled, vscaled);
                    }
                    la_movfr2gr_d(reg_d, vscaled);
                } else {
                    if (is_signed) {
                        la_ftintrz_w_s(vscaled, vscaled);
                    } else {
                        la_vftintrz_wu_s(vscaled, vscaled);
                    }
                    la_movfr2gr_s(reg_d, vscaled);
                }
            }

            if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
                set_w_write_flag(rd, sf);
            } else if (!sf) {
                la_bstrpick_d(reg_d, reg_d, 31, 0);
            }
            store_gpr_dst(rd, reg_d);
            free_alloc_gpr(reg_d);
            free_alloc_fpr(vreg_n);
            free_alloc_fpr(vscaled);
            free_alloc_fpr(vscale);
            free_alloc_gpr(temp);
        } else if (is_signed && extract32(opcode, 2, 1) && scale == 64 && type == 0) {
            IR2_OPND reg_d = alloc_gpr_dst(rd);
            IR2_OPND vreg_n = alloc_fpr_src(rn);
            IR2_OPND vtemp = ra_alloc_ftemp();
            IR2_OPND vbound = ra_alloc_ftemp();
            IR2_OPND temp = ra_alloc_itemp();
            IR2_OPND done = ir2_opnd_new_type(IR2_OPND_LABEL);
            IR2_OPND fix_min = ir2_opnd_new_type(IR2_OPND_LABEL);
            IR2_OPND saturate_min = ir2_opnd_new_type(IR2_OPND_LABEL);
            IR2_OPND saturate_max = ir2_opnd_new_type(IR2_OPND_LABEL);

            if (sf) {
                li_w(temp, 0xdf000000u); /* -2^63 as f32 */
                la_movgr2fr_w(vbound, temp);
                la_fcmp_cond_s(fcc0_ir2_opnd, vreg_n, vbound, FCMP_COND_CLE);
                la_bcnez(fcc0_ir2_opnd, saturate_min);

                li_w(temp, 0x5f000000u); /* 2^63 as f32 */
                la_movgr2fr_w(vbound, temp);
                la_fcmp_cond_s(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
                la_bcnez(fcc0_ir2_opnd, saturate_max);
            } else {
                li_w(temp, 0xcf000000u); /* -2^31 as f32 */
                la_movgr2fr_w(vbound, temp);
                la_fcmp_cond_s(fcc0_ir2_opnd, vreg_n, vbound, FCMP_COND_CLE);
                la_bcnez(fcc0_ir2_opnd, saturate_min);

                li_w(temp, 0x4f000000u); /* 2^31 as f32 */
                la_movgr2fr_w(vbound, temp);
                la_fcmp_cond_s(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
                la_bcnez(fcc0_ir2_opnd, saturate_max);
            }

            li_w(temp, 0x3f000000u); /* 0.5f */
            la_movgr2fr_w(vbound, temp);
            la_fcopysign_s(vbound, vbound, vreg_n);
            la_fadd_s(vtemp, vreg_n, vbound);
            if (sf) {
                la_ftintrz_l_s(vtemp, vtemp);
                la_movfr2gr_d(reg_d, vtemp);
            } else {
                la_ftintrz_w_s(vtemp, vtemp);
                la_movfr2gr_s(reg_d, vtemp);
                la_bstrpick_d(reg_d, reg_d, 31, 0);
                li_wu(temp, 0x80000001u);
                la_bne(reg_d, temp, done);
                la_movgr2fr_w(vbound, zero_ir2_opnd);
                la_fcmp_cond_s(fcc0_ir2_opnd, vreg_n, vbound, FCMP_COND_CLT);
                la_bcnez(fcc0_ir2_opnd, fix_min);
            }
            la_b(done);

            la_label(fix_min);
            li_wu(reg_d, 0x80000000u);
            la_b(done);

            la_label(saturate_min);
            if (sf) {
                li_d(reg_d, INT64_MIN);
            } else {
                li_wu(reg_d, 0x80000000u);
            }
            la_b(done);

            la_label(saturate_max);
            if (sf) {
                li_d(reg_d, INT64_MAX);
            } else {
                li_wu(reg_d, 0x7fffffffu);
            }

            la_label(done);
            if (sf) {
                if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
                    set_w_write_flag(rd, true);
                }
            } else {
                la_sext_w_d(reg_d, reg_d);
            }
            store_gpr_dst(rd, reg_d);
            free_alloc_gpr(reg_d);
            free_alloc_fpr(vreg_n);
            free_alloc_fpr(vtemp);
            free_alloc_fpr(vbound);
            free_alloc_gpr(temp);
        } else if (is_signed && extract32(opcode, 2, 1) != 1 && scale == 64) { /* FCVT[NPMZ]S && SHIFT == 0 */
            IR2_OPND reg_d = alloc_gpr_dst(rd);
            IR2_OPND vreg_n = alloc_fpr_src(rn);
            IR2_OPND vtemp = ra_alloc_ftemp();

            switch (rmode) {
                case 0: /* Round to Nearest (RN) mode. */
                    switch (type) {
                        case 1: /* float64 */
                            if (sf) {
                                la_ftintrne_l_d(vtemp, vreg_n);
                                la_movfr2gr_d(reg_d, vtemp);
                            } else {
                                la_ftintrne_w_d(vtemp, vreg_n);
                                la_movfr2gr_s(reg_d, vtemp);
                            }
                            break;
                        case 0: /* float32 */
                            if (sf) {
                                la_ftintrne_l_s(vtemp, vreg_n);
                                la_movfr2gr_d(reg_d, vtemp);
                            } else {
                                la_ftintrne_w_s(vtemp, vreg_n);
                                la_movfr2gr_s(reg_d, vtemp);
                            }
                            break;
                        case 3: /* float16 */
                        {
                            IR2_OPND vtemp_fp32 = ra_alloc_ftemp();
                            la_vfcvtl_s_h(vtemp_fp32, vreg_n);
                            la_vand_v(vtemp_fp32, vtemp_fp32, fsmask_ir2_opnd);
                            if (sf) {
                                la_ftintrne_l_s(vtemp, vtemp_fp32);
                                la_movfr2gr_d(reg_d, vtemp);
                            } else {
                                la_ftintrne_w_s(vtemp, vtemp_fp32);
                                la_movfr2gr_s(reg_d, vtemp);
                            }
                            free_alloc_fpr(vtemp_fp32);
                            break;
                        }
                        default:
                            g_assert_not_reached();
                    }
                    break;
                case 1: /* Round towards Plus Infinity (RP) mode. */
                    switch (type) {
                        case 1: /* float64 */
                            if (sf) {
                                la_ftintrp_l_d(vtemp, vreg_n);
                                la_movfr2gr_d(reg_d, vtemp);
                            } else {
                                la_ftintrp_w_d(vtemp, vreg_n);
                                la_movfr2gr_s(reg_d, vtemp);
                            }
                            break;
                        case 0: /* float32 */
                            if (sf) {
                                la_ftintrp_l_s(vtemp, vreg_n);
                                la_movfr2gr_d(reg_d, vtemp);
                            } else {
                                la_ftintrp_w_s(vtemp, vreg_n);
                                la_movfr2gr_s(reg_d, vtemp);
                            }
                            break;
                        case 3: /* float16 */
                        {
                            IR2_OPND vtemp_fp32 = ra_alloc_ftemp();
                            la_vfcvtl_s_h(vtemp_fp32, vreg_n);
                            la_vand_v(vtemp_fp32, vtemp_fp32, fsmask_ir2_opnd);
                            if (sf) {
                                la_ftintrp_l_s(vtemp, vtemp_fp32);
                                la_movfr2gr_d(reg_d, vtemp);
                            } else {
                                la_ftintrp_w_s(vtemp, vtemp_fp32);
                                la_movfr2gr_s(reg_d, vtemp);
                            }
                            free_alloc_fpr(vtemp_fp32);
                            break;
                        }
                        default:
                            g_assert_not_reached();
                    }
                    break;
                case 2: /* Round towards Minus Infinity (RM) mode. */
                    switch (type) {
                        case 1: /* float64 */
                            if (sf) {
                                la_ftintrm_l_d(vtemp, vreg_n);
                                la_movfr2gr_d(reg_d, vtemp);
                            } else {
                                la_ftintrm_w_d(vtemp, vreg_n);
                                la_movfr2gr_s(reg_d, vtemp);
                            }
                            break;
                        case 0: /* float32 */
                            if (sf) {
                                la_ftintrm_l_s(vtemp, vreg_n);
                                la_movfr2gr_d(reg_d, vtemp);
                            } else {
                                la_ftintrm_w_s(vtemp, vreg_n);
                                la_movfr2gr_s(reg_d, vtemp);
                            }
                            break;
                        case 3: /* float16 */
                        {
                            IR2_OPND vtemp_fp32 = ra_alloc_ftemp();
                            la_vfcvtl_s_h(vtemp_fp32, vreg_n);
                            la_vand_v(vtemp_fp32, vtemp_fp32, fsmask_ir2_opnd);
                            if (sf) {
                                la_ftintrm_l_s(vtemp, vtemp_fp32);
                                la_movfr2gr_d(reg_d, vtemp);
                            } else {
                                la_ftintrm_w_s(vtemp, vtemp_fp32);
                                la_movfr2gr_s(reg_d, vtemp);
                            }
                            free_alloc_fpr(vtemp_fp32);
                            break;
                        }
                        default:
                            g_assert_not_reached();
                    }
                    break;
                case 3: /* Round towards Zero (RZ) mode. */
                    switch (type) {
                        case 1: /* float64 */
                            if (sf) {
                                la_ftintrz_l_d(vtemp, vreg_n);
                                la_movfr2gr_d(reg_d, vtemp);
                            } else {
                                la_ftintrz_w_d(vtemp, vreg_n);
                                la_movfr2gr_s(reg_d, vtemp);
                            }
                            break;
                        case 0: /* float32 */
                            if (sf) {
                                la_ftintrz_l_s(vtemp, vreg_n);
                                la_movfr2gr_d(reg_d, vtemp);
                            } else {
                                la_ftintrz_w_s(vtemp, vreg_n);
                                la_movfr2gr_s(reg_d, vtemp);
                            }
                            break;
                        case 3: /* float16 */
                        {
                            IR2_OPND vtemp_fp32 = ra_alloc_ftemp();
                            la_vfcvtl_s_h(vtemp_fp32, vreg_n);
                            la_vand_v(vtemp_fp32, vtemp_fp32, fsmask_ir2_opnd);
                            if (sf) {
                                la_ftintrz_l_s(vtemp, vtemp_fp32);
                                la_movfr2gr_d(reg_d, vtemp);
                            } else {
                                la_ftintrz_w_s(vtemp, vtemp_fp32);
                                la_movfr2gr_s(reg_d, vtemp);
                            }
                            free_alloc_fpr(vtemp_fp32);
                            break;
                        }
                        default:
                            g_assert_not_reached();
                    }
                    break;
                default:
                    g_assert_not_reached();
            }

            if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
                set_w_write_flag(rd, sf);
            } else {
                if (!sf) {
                    la_bstrpick_d(reg_d, reg_d, 31, 0);
                }
            }
            store_gpr_dst(rd, reg_d);
            free_alloc_gpr(reg_d);
            free_alloc_fpr(vreg_n);
            free_alloc_fpr(vtemp);
        } else { /* FCVT[NPMZ]U || (FCVT[NPMZ]S && SHIFT != 0) || FCVTA[U/S]*/
            /* 龙芯没有对应浮点数转成无符号整数的指令，
            当大于最大的无符号浮点数(0xffffffff或0xffffffffffffffff), arm64会置成最大的无符号整数。
            当小于0的浮点数转成无符号整数时， arm64直接置0。
            */

            if (!is_signed && !sf && scale == 64 && type == 0) {
                IR2_OPND reg_d = alloc_gpr_dst(rd);
                IR2_OPND vreg_n = alloc_fpr_src(rn);
                IR2_OPND vtemp = ra_alloc_ftemp();
                IR2_OPND vbound = ra_alloc_ftemp();
                IR2_OPND temp = ra_alloc_itemp();
                IR2_OPND done = ir2_opnd_new_type(IR2_OPND_LABEL);
                IR2_OPND high_half = ir2_opnd_new_type(IR2_OPND_LABEL);
                IR2_OPND saturate = ir2_opnd_new_type(IR2_OPND_LABEL);

                la_mov64(reg_d, zero_ir2_opnd);

                /* CLE is ordered: NaN is false, and x < 0 is false.  ARM
                 * unsigned FP-to-int maps both cases to zero, so one compare
                 * keeps them out of LoongArch's signed conversion path. */
                la_movgr2fr_w(vbound, zero_ir2_opnd);
                la_fcmp_cond_s(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
                la_bceqz(fcc0_ir2_opnd, done);

                li_w(temp, 0x4f800000u); /* 2^32 as f32 */
                la_movgr2fr_w(vbound, temp);
                la_fcmp_cond_s(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
                la_bcnez(fcc0_ir2_opnd, saturate);

                li_w(temp, 0x4f000000u); /* 2^31 as f32 */
                la_movgr2fr_w(vbound, temp);
                la_fcmp_cond_s(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
                la_bcnez(fcc0_ir2_opnd, high_half);

                switch (rmode) {
                    case FPROUNDING_TIEEVEN:
                        la_ftintrne_w_s(vtemp, vreg_n);
                        break;
                    case FPROUNDING_POSINF:
                        la_ftintrp_w_s(vtemp, vreg_n);
                        break;
                    case FPROUNDING_NEGINF:
                        la_ftintrm_w_s(vtemp, vreg_n);
                        break;
                    case FPROUNDING_ZERO:
                        la_ftintrz_w_s(vtemp, vreg_n);
                        break;
                    case FPROUNDING_TIEAWAY:
                        li_w(temp, 0x3f000000u); /* 0.5f */
                        la_movgr2fr_w(vbound, temp);
                        la_fadd_s(vtemp, vreg_n, vbound);
                        la_ftintrm_w_s(vtemp, vtemp);
                        break;
                    default:
                        g_assert_not_reached();
                }
                la_movfr2gr_s(reg_d, vtemp);
                la_b(done);

                la_label(high_half);
                li_w(temp, 0x4f000000u); /* 2^31 as f32 */
                la_movgr2fr_w(vbound, temp);
                la_fsub_s(vtemp, vreg_n, vbound);
                switch (rmode) {
                    case FPROUNDING_TIEEVEN:
                        la_ftintrne_w_s(vtemp, vtemp);
                        break;
                    case FPROUNDING_POSINF:
                        la_ftintrp_w_s(vtemp, vtemp);
                        break;
                    case FPROUNDING_NEGINF:
                        la_ftintrm_w_s(vtemp, vtemp);
                        break;
                    case FPROUNDING_ZERO:
                        la_ftintrz_w_s(vtemp, vtemp);
                        break;
                    case FPROUNDING_TIEAWAY:
                        li_w(temp, 0x3f000000u); /* 0.5f */
                        la_movgr2fr_w(vbound, temp);
                        la_fadd_s(vtemp, vtemp, vbound);
                        la_ftintrm_w_s(vtemp, vtemp);
                        break;
                    default:
                        g_assert_not_reached();
                }
                la_movfr2gr_s(reg_d, vtemp);
                li_wu(temp, 0x80000000u);
                la_add_d(reg_d, reg_d, temp);
                la_b(done);

                la_label(saturate);
                li_wu(reg_d, UINT32_MAX);

                la_label(done);
                if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
                    set_w_write_flag(rd, sf);
                } else if (!sf) {
                    la_bstrpick_d(reg_d, reg_d, 31, 0);
                }
                store_gpr_dst(rd, reg_d);
                free_alloc_gpr(reg_d);
                free_alloc_fpr(vreg_n);
                free_alloc_fpr(vtemp);
                free_alloc_fpr(vbound);
                free_alloc_gpr(temp);
                return;
            }

            IR2_OPND temp = ra_alloc_itemp();
            IR2_OPND reg_d = alloc_gpr_dst(rd);

            li_d(temp, s->base->pc_next);
            la_st_d(temp, env_ir2_opnd, env_offset_pc());
            lata_gen_call_helper_prologue(tcg_ctx);

            /* set rmode */
            li_d(a0_ir2_opnd, env_offset_RMODE());
            li_d(a1_ir2_opnd, arm_rmode_to_sf(rmode));
            la_stx_w(a1_ir2_opnd, env_ir2_opnd, a0_ir2_opnd);

            /* a2: fpstatus */
            li_d(temp, env_offset_fpstatus());
            la_add_d(a2_ir2_opnd, env_ir2_opnd, temp);
            /* a1: shift */
            li_d(a1_ir2_opnd, 64 - scale);
            /* a0: fp */
            li_d(temp, env_offset_fpr(rn));
            if (type == 1) {
                la_ldx_d(a0_ir2_opnd, env_ir2_opnd, temp);
            } else {
                la_ldx_wu(a0_ir2_opnd, env_ir2_opnd, temp);
            }

            switch (type) {
                case 1: /* float64 */
                    if (is_signed) {
                        if (sf) {
                            li_d(temp, (uint64_t)helper_vfp_tosqd);
                        } else {
                            li_d(temp, (uint64_t)helper_vfp_tosld);
                        }
                    } else {
                        if (sf) {
                            li_d(temp, (uint64_t)helper_vfp_touqd);
                        } else {
                            li_d(temp, (uint64_t)helper_vfp_tould);
                        }
                    }
                    break;
                case 0: /* float32 */
                    if (is_signed) {
                        if (sf) {
                            li_d(temp, (uint64_t)helper_vfp_tosqs);
                        } else {
                            li_d(temp, (uint64_t)helper_vfp_tosls);
                        }
                    } else {
                        if (sf) {
                            li_d(temp, (uint64_t)helper_vfp_touqs);
                        } else {
                            li_d(temp, (uint64_t)helper_vfp_touls);
                        }
                    }
                    break;
                case 3: /* float16 */
                {
                    /* Convert float16→float32 inline, then call float32 QEMU helper. */
                    IR2_OPND vtemp_h = ra_alloc_ftemp();
                    IR2_OPND vtemp_s = ra_alloc_ftemp();
                    /* a0 has fpregs[rn] (128-bit). Extract f16 from lower 16 bits. */
                    la_movfr2gr_s(reg_d, a0_ir2_opnd);
                    la_bstrpick_d(reg_d, reg_d, 15, 0);
                    la_movgr2fr_w(vtemp_h, reg_d);
                    la_vfcvtl_s_h(vtemp_s, vtemp_h);
                    la_vand_v(vtemp_s, vtemp_s, fsmask_ir2_opnd);
                    /* Move converted f32 to a0 (GPR) for QEMU helper */
                    la_movfr2gr_s(reg_d, vtemp_s);
                    la_mov64(a0_ir2_opnd, reg_d);
                    if (is_signed) {
                        if (sf)
                            li_d(temp, (uint64_t)helper_vfp_tosqs);
                        else
                            li_d(temp, (uint64_t)helper_vfp_tosls);
                    } else {
                        if (sf)
                            li_d(temp, (uint64_t)helper_vfp_touqs);
                        else
                            li_d(temp, (uint64_t)helper_vfp_touls);
                    }
                    free_alloc_fpr(vtemp_h);
                    free_alloc_fpr(vtemp_s);
                    break;
                }

                default:
                    g_assert_not_reached();
            }
            la_jirl(ra_ir2_opnd, temp, 0);
            if (rd != 31) {
                li_d(temp, env_offset_gpr(rd));
                if (sf) {
                    la_stx_d(a0_ir2_opnd, env_ir2_opnd, temp);
                } else {
                    la_stx_w(a0_ir2_opnd, env_ir2_opnd, temp);
                }
            }
            free_alloc_gpr(reg_d);

            /* set rmode */
            li_d(a6_ir2_opnd, env_offset_FPSCR());
            la_ldx_d(a7_ir2_opnd, env_ir2_opnd, a6_ir2_opnd);
            la_bstrpick_d(a7_ir2_opnd, a7_ir2_opnd, 23, 22);
            li_d(a6_ir2_opnd, env_offset_RMODE());
            la_stx_w(a7_ir2_opnd, env_ir2_opnd, a6_ir2_opnd);

            lata_gen_call_helper_epilogue(tcg_ctx);
            reg_d = alloc_gpr_dst(rd);
            if (rd != 31) {
                li_d(temp, env_offset_gpr(rd));
                if (sf) {
                    la_ldx_d(reg_d, env_ir2_opnd, temp);
                } else {
                    la_ldx_wu(reg_d, env_ir2_opnd, temp);
                }
            } else {
                la_mov64(reg_d, zero_ir2_opnd);
            }

            if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
                set_w_write_flag(rd, sf);
            } else {
                if (!sf) {
                    la_bstrpick_d(reg_d, reg_d, 31, 0);
                }
            }
            store_gpr_dst(rd, reg_d);
            free_alloc_gpr(reg_d);
            free_alloc_gpr(temp);
        }
    }
}

/* Floating point <-> fixed point conversions
 *   31   30  29 28       24 23  22  21 20   19 18    16 15   10 9    5 4    0
 * +----+---+---+-----------+------+---+-------+--------+-------+------+------+
 * | sf | 0 | S | 1 1 1 1 0 | type | 0 | rmode | opcode | scale |  Rn  |  Rd  |
 * +----+---+---+-----------+------+---+-------+--------+-------+------+------+
 */
static void disas_fp_fixed_conv(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int scale = extract32(insn, 10, 6);
    int opcode = extract32(insn, 16, 3);
    int rmode = extract32(insn, 19, 2);
    int type = extract32(insn, 22, 2);
    bool sbit = extract32(insn, 29, 1);
    bool sf = extract32(insn, 31, 1);
    bool itof;

    if (sbit || (!sf && scale < 32)) {
        lata_unallocated_encoding(s);
        return;
    }

    switch (type) {
        case 0: /* float32 */
        case 1: /* float64 */
            break;
        case 3: /* float16 */
            if (dc_isar_feature(aa64_fp16, s)) {
                break;
            }
            /* fallthru */
        default:
            lata_unallocated_encoding(s);
            return;
    }

    switch ((rmode << 3) | opcode) {
        case 0x2: /* SCVTF */
        case 0x3: /* UCVTF */
            itof = true;
            break;
        case 0x18: /* FCVTZS */
        case 0x19: /* FCVTZU */
            itof = false;
            break;
        default:
            lata_unallocated_encoding(s);
            return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    handle_fpfpcvt(s, rd, rn, opcode, itof, FPROUNDING_ZERO, scale, sf, type);
}

static void handle_fmov(DisasContext* s, int rd, int rn, int type, bool itof)
{
    /* FMOV: gpr to or from float, double, or top half of quad fp reg,
     * without conversion.
     */

    if (itof) {
        IR2_OPND reg_n = alloc_gpr_src(rn);
        IR2_OPND vreg_d;
        IR2_OPND temp = ra_alloc_itemp();

        if (type == 2) {
            vreg_d = alloc_fpr_src(rd);
        } else {
            vreg_d = alloc_fpr_dst(rd);
        }
        switch (type) {
            case 0:
                /* 32 bit */
                la_bstrpick_d(temp, reg_n, 31, 0);
                la_movgr2fr_w(vreg_d, temp);
                break;
            case 1:
                /* 64 bit */
                if (clearGprHigh && arm_la_map[rn] >= 0 && rn != 31) {
                    clear_gpr_high(rn);
                }
                la_movgr2fr_d(vreg_d, reg_n);
                break;
            case 2:
                /* 64 bit to top half. */
                if (clearGprHigh && arm_la_map[rn] >= 0 && rn != 31) {
                    clear_gpr_high(rn);
                }
                la_vinsgr2vr_d(vreg_d, reg_n, 1);
                break;
            case 3:
                /* 16 bit */
                la_bstrpick_d(temp, reg_n, 15, 0);
                la_movgr2fr_d(vreg_d, temp);
                break;
            default:
                g_assert_not_reached();
        }
        if (type != 2) {
            unsigned out_size = fp_type_to_vec_size(type);
            bool high_clean = fpr_clear_high_if_live(vreg_d, rd, out_size);

            store_scalar_fpr_dst(rd, vreg_d, out_size, high_clean);
        } else {
            store_fpr_dst(rd, vreg_d);
        }
        free_alloc_fpr(vreg_d);
        free_alloc_gpr(reg_n);
        free_alloc_gpr(temp);
    } else {
        IR2_OPND reg_d = alloc_gpr_dst(rd);
        IR2_OPND vreg_n = alloc_fpr_src(rn);
        IR2_OPND temp = ra_alloc_itemp();

        switch (type) {
            case 0:
                /* 32 bit */
                la_movfr2gr_d(temp, vreg_n);
                la_bstrpick_d(reg_d, temp, 31, 0);
                break;
            case 1:
                /* 64 bit */
                la_movfr2gr_d(reg_d, vreg_n);
                break;
            case 2:
                /* 64 bits from top half */
                la_vpickve2gr_du(reg_d, vreg_n, 1);
                break;
            case 3:
                /* 16 bit */
                la_movfr2gr_d(temp, vreg_n);
                la_bstrpick_d(reg_d, temp, 16, 0);
                break;
            default:
                g_assert_not_reached();
        }

        if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
            set_w_write_flag(rd, TRUE);
        }
        store_gpr_dst(rd, reg_d);
        free_alloc_gpr(reg_d);
        free_alloc_fpr(vreg_n);
        free_alloc_gpr(temp);
    }
}

static void handle_fjcvtzs(DisasContext* s, int rd, int rn)
{
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtmp = ra_alloc_ftemp();
    IR2_OPND vbound = ra_alloc_ftemp();
    IR2_OPND reg_d = alloc_gpr_dst(rd);
    IR2_OPND bits = ra_alloc_itemp();
    IR2_OPND tmp = ra_alloc_itemp();
    IR2_OPND flags = ra_alloc_itemp();
    IR2_OPND label_inexact_zero = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND label_fallback = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND label_exact = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND label_flags_done = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND label_fallback_inexact = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND label_fallback_flags_done = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND label_done = ir2_opnd_new_type(IR2_OPND_LABEL);

    /* JS ToInt32 is trunc(value) modulo 2^32.  For values that fit in int64,
     * FTINTRZ.L.D gives the truncated integer directly and the low 32 bits are
     * the architectural result.  The helper is kept for NaN/Inf and huge finite
     * inputs where exact modulo reduction is not a simple hardware conversion.
     */
    la_fcmp_cond_d(fcc0_ir2_opnd, vreg_n, vreg_n, FCMP_COND_CUN);
    la_bcnez(fcc0_ir2_opnd, label_fallback);

    la_movfr2gr_d(bits, vreg_n);
    li_d(tmp, (int64_t)0x8000000000000000ULL);
    la_beq(bits, tmp, label_inexact_zero);

    li_d(tmp, (int64_t)0xc3e0000000000000ULL); /* -2^63 as f64 */
    la_movgr2fr_d(vbound, tmp);
    la_fcmp_cond_d(fcc0_ir2_opnd, vreg_n, vbound, FCMP_COND_CLT);
    la_bcnez(fcc0_ir2_opnd, label_fallback);

    li_d(tmp, (int64_t)0x43e0000000000000ULL); /* +2^63 as f64 */
    la_movgr2fr_d(vbound, tmp);
    la_fcmp_cond_d(fcc0_ir2_opnd, vbound, vreg_n, FCMP_COND_CLE);
    la_bcnez(fcc0_ir2_opnd, label_fallback);

    la_ftintrz_l_d(vtmp, vreg_n);
    la_movfr2gr_d(bits, vtmp);
    la_bstrpick_d(reg_d, bits, 31, 0);

    la_movgr2fr_d(vtmp, bits);
    la_ffint_d_l(vtmp, vtmp);
    la_fcmp_cond_d(fcc0_ir2_opnd, vreg_n, vtmp, FCMP_COND_CEQ);
    la_bcnez(fcc0_ir2_opnd, label_exact);
    li_d(flags, 0);
    la_b(label_flags_done);

    la_label(label_exact);
    li_d(flags, 0x40000000); /* NZCV.Z = 1, N/C/V = 0 */
    la_label(label_flags_done);
    la_armmtflag(flags, 0x39);
    la_b(label_done);

    la_label(label_inexact_zero);
    la_mov64(reg_d, zero_ir2_opnd);
    la_armmtflag(zero_ir2_opnd, 0x39);
    la_b(label_done);

    la_label(label_fallback);
    li_d(tmp, s->base->pc_next);
    la_st_d(tmp, env_ir2_opnd, env_offset_pc());
    if (arm_la_fmap[rn] >= 0) {
        vector_store_to_env(rn, ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[rn]));
    }
    lata_gen_call_helper_prologue_no_flags(tcg_ctx);
    li_d(tmp, env_offset_fpr(rn));
    la_ldx_d(a0_ir2_opnd, env_ir2_opnd, tmp);
    li_d(tmp, env_offset_fpstatus());
    la_add_d(a1_ir2_opnd, env_ir2_opnd, tmp);
    li_d(tmp, (uint64_t)helper_fjcvtzs);
    la_jirl(ra_ir2_opnd, tmp, 0);
    la_srli_d(flags, a0_ir2_opnd, 32);
    la_bnez(flags, label_fallback_inexact);
    li_d(flags, 0x40000000);
    la_b(label_fallback_flags_done);
    la_label(label_fallback_inexact);
    li_d(flags, 0);
    la_label(label_fallback_flags_done);
    la_armmtflag(flags, 0x39);
    if (rd != 31) {
        li_d(tmp, env_offset_gpr(rd));
        la_stx_w(a0_ir2_opnd, env_ir2_opnd, tmp);
    }
    free_alloc_gpr(reg_d);
    lata_gen_call_helper_epilogue_no_flags(tcg_ctx);
    reg_d = alloc_gpr_dst(rd);
    if (rd != 31) {
        li_d(tmp, env_offset_gpr(rd));
        la_ldx_wu(reg_d, env_ir2_opnd, tmp);
    } else {
        la_mov64(reg_d, zero_ir2_opnd);
    }

    la_label(label_done);
    if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, TRUE);
    }
    store_gpr_dst(rd, reg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtmp);
    free_alloc_fpr(vbound);
    free_alloc_gpr(reg_d);
    free_alloc_gpr(bits);
    free_alloc_gpr(tmp);
    free_alloc_gpr(flags);
}

/* Floating point <-> integer conversions
 *   31   30  29 28       24 23  22  21 20   19 18 16 15         10 9  5 4  0
 * +----+---+---+-----------+------+---+-------+-----+-------------+----+----+
 * | sf | 0 | S | 1 1 1 1 0 | type | 1 | rmode | opc | 0 0 0 0 0 0 | Rn | Rd |
 * +----+---+---+-----------+------+---+-------+-----+-------------+----+----+
 */
static void disas_fp_int_conv(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int opcode = extract32(insn, 16, 3);
    int rmode = extract32(insn, 19, 2);
    int type = extract32(insn, 22, 2);
    bool sbit = extract32(insn, 29, 1);
    bool sf = extract32(insn, 31, 1);
    bool itof = false;

    if (sbit) {
        goto do_unallocated;
    }

    switch (opcode) {
        case 2: /* SCVTF */
        case 3: /* UCVTF */
            itof = true;
            /* fallthru */
        case 4: /* FCVTAS */
        case 5: /* FCVTAU */
            if (rmode != 0) goto do_unallocated;
            /* FCVTA[SU]: use the generic conversion path so that the same
             * saturation and helper fallbacks are shared with fixed-point
             * conversions. */
            /* fall through */
        case 0: /* FCVT[NPMZ]S */
        case 1: /* FCVT[NPMZ]U */
            switch (type) {
                case 0: /* float32 */
                case 1: /* float64 */
                    break;
                case 3: /* float16 */
                    if (!dc_isar_feature(aa64_fp16, s)) {
                        goto do_unallocated;
                    }
                    break;
                default:
                    goto do_unallocated;
            }
            if (!fp_access_check(s)) {
                return;
            }
            handle_fpfpcvt(s, rd, rn, opcode, itof, rmode, 64, sf, type);
            break;

        default:
            switch (sf << 7 | type << 5 | rmode << 3 | opcode) {
                case 0b01100110: /* FMOV half <-> 32-bit int */
                case 0b01100111:
                case 0b11100110: /* FMOV half <-> 64-bit int */
                case 0b11100111:
                    if (!dc_isar_feature(aa64_fp16, s)) {
                        goto do_unallocated;
                    }
                    /* fallthru */
                case 0b00000110: /* FMOV 32-bit */
                case 0b00000111:
                case 0b10100110: /* FMOV 64-bit */
                case 0b10100111:
                case 0b11001110: /* FMOV top half of 128-bit */
                case 0b11001111:
                    if (!fp_access_check(s)) {
                        return;
                    }
                    itof = opcode & 1;
                    handle_fmov(s, rd, rn, type, itof);
                    break;

                case 0b00111110: /* FJCVTZS */
                    if (!dc_isar_feature(aa64_jscvt, s)) {
                        goto do_unallocated;
                    } else if (fp_access_check(s)) {
                        handle_fjcvtzs(s, rd, rn);
                    }
                    break;

                default:
                do_unallocated:
                    lata_unallocated_encoding(s);
                    return;
            }
            break;
    }
}

/* FP-specific subcases of table C3-6 (SIMD and FP data processing)
 *   31  30  29 28     25 24                          0
 * +---+---+---+---------+-----------------------------+
 * |   | 0 |   | 1 1 1 1 |                             |
 * +---+---+---+---------+-----------------------------+
 */
static void disas_data_proc_simd(DisasContext* s, uint32_t insn);
static void disas_simd_scalar_two_reg_misc(DisasContext* s, uint32_t insn);

static void disas_data_proc_fp(DisasContext* s, uint32_t insn)
{
    if (extract32(insn, 24, 1)) {
        /* Floating point data-processing (3 source) */
        disas_fp_3src(s, insn);
    } else if (extract32(insn, 21, 1) == 0) {
        /* Floating point to fixed point conversions */
        disas_fp_fixed_conv(s, insn);
    } else {
        switch (extract32(insn, 10, 2)) {
            case 1:
                /* Floating point conditional compare */
                disas_fp_ccomp(s, insn);
                break;
            case 2:
                /* Floating point data-processing (2 source) */
                disas_fp_2src(s, insn);
                break;
            case 3:
                /* Floating point conditional select */
                disas_fp_csel(s, insn);
                break;
            case 0:
                switch (ctz32(extract32(insn, 12, 4))) {
                    case 0: /* [15:12] == xxx1 */
                        /* Floating point immediate */
                        disas_fp_imm(s, insn);
                        break;
                    case 1: /* [15:12] == xx10 */
                        /* Floating point compare */
                        disas_fp_compare(s, insn);
                        break;
                    case 2: /* [15:12] == x100 */
                        /* Floating point data-processing (1 source) */
                        disas_fp_1src(s, insn);
                        break;
                    case 3: /* [15:12] == 1000 */
                        lata_unallocated_encoding(s);
                        break;
                    default: /* [15:12] == 0000 */
                        /* Floating point <-> integer conversions */
                        disas_fp_int_conv(s, insn);
                        break;
                }
                break;
        }
    }
}

/* EXT
 *   31  30 29         24 23 22  21 20  16 15  14  11 10  9    5 4    0
 * +---+---+-------------+-----+---+------+---+------+---+------+------+
 * | 0 | Q | 1 0 1 1 1 0 | op2 | 0 |  Rm  | 0 | imm4 | 0 |  Rn  |  Rd  |
 * +---+---+-------------+-----+---+------+---+------+---+------+------+
 */
static void disas_simd_ext(DisasContext* s, uint32_t insn)
{
    int is_q = extract32(insn, 30, 1);
    int op2 = extract32(insn, 22, 2);
    int imm4 = extract32(insn, 11, 4);
    int rm = extract32(insn, 16, 5);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);

    if (op2 != 0 || (!is_q && extract32(imm4, 3, 1))) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp1 = ra_alloc_ftemp();

    /* Vd gets bits starting at pos bits into Vm:Vn. This is
     * either extracting 128 bits from a 128:128 concatenation, or
     * extracting 64 bits from a 64:64 concatenation.
     */
    if (!is_q) {
        if (imm4 == 0) {
            la_vori_b(vreg_d, vreg_n, 0);
        } else {
            la_vori_b(vtemp, vreg_n, 0);
            /* 高64位清零 */
            la_vinsgr2vr_d(vtemp, zero_ir2_opnd, 1);
            la_vbsrl_v(vtemp, vtemp, imm4);
            la_vbsll_v(vtemp1, vreg_m, 0x8 - imm4);
            la_vor_v(vreg_d, vtemp, vtemp1);
        }
        bool high_clean = fpr_clear_high_if_live(vreg_d, rd, 3);
        store_scalar_fpr_dst(rd, vreg_d, 3, high_clean);
    } else {
        if (imm4 == 0) {
            la_vori_b(vreg_d, vreg_n, 0);
        } else {
            la_vbsrl_v(vtemp, vreg_n, imm4);
            la_vbsll_v(vtemp1, vreg_m, 0x10 - imm4);
            la_vor_v(vreg_d, vtemp, vtemp1);
        }
    }
    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_m);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp1);
}

/* TBL/TBX
 *   31  30 29         24 23 22  21 20  16 15  14 13  12  11 10 9    5 4    0
 * +---+---+-------------+-----+---+------+---+-----+----+-----+------+------+
 * | 0 | Q | 0 0 1 1 1 0 | op2 | 0 |  Rm  | 0 | len | op | 0 0 |  Rn  |  Rd  |
 * +---+---+-------------+-----+---+------+---+-----+----+-----+------+------+
 */
static void disas_simd_tb(DisasContext* s, uint32_t insn)
{
    int op2 = extract32(insn, 22, 2);
    int is_q = extract32(insn, 30, 1);
    int rm = extract32(insn, 16, 5);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);
    int is_tbx = extract32(insn, 12, 1);
    int len = (extract32(insn, 13, 2) + 1) * 16;

    if (op2 != 0) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }
    IR2_OPND temp = ra_alloc_itemp();

    li_d(temp, s->base->pc_next);
    la_st_d(temp, env_ir2_opnd, env_offset_pc());

    lata_gen_call_helper_prologue(tcg_ctx);
    /* void HELPER(simd_tblx)(void *vd, void *vm, void *venv, uint32_t desc) */
    la_mov64(a2_ir2_opnd, env_ir2_opnd);
    li_d(a0_ir2_opnd, vec_full_reg_offset(s, rd));
    li_d(a1_ir2_opnd, vec_full_reg_offset(s, rm));
    la_add_d(a0_ir2_opnd, a0_ir2_opnd, a2_ir2_opnd);
    la_add_d(a1_ir2_opnd, a1_ir2_opnd, a2_ir2_opnd);
    li_d(a3_ir2_opnd, simd_desc(is_q ? 16 : 8, vec_full_reg_size(s), (len << 6) | (is_tbx << 5) | rn));
    li_d(temp, (int64_t)helper_simd_tblx);
    la_jirl(ra_ir2_opnd, temp, 0);
    lata_gen_call_helper_epilogue(tcg_ctx);

    free_alloc_gpr(temp);
}

/* ZIP/UZP/TRN
 *   31  30 29         24 23  22  21 20   16 15 14 12 11 10 9    5 4    0
 * +---+---+-------------+------+---+------+---+------------------+------+
 * | 0 | Q | 0 0 1 1 1 0 | size | 0 |  Rm  | 0 | opc | 1 0 |  Rn  |  Rd  |
 * +---+---+-------------+------+---+------+---+------------------+------+
 */
static void disas_simd_zip_trn(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int rm = extract32(insn, 16, 5);
    int size = extract32(insn, 22, 2);
    /* opc field bits [1:0] indicate ZIP/UZP/TRN;
     * bit 2 indicates 1 vs 2 variant of the insn.
     */
    int opcode = extract32(insn, 12, 2);
    bool part = extract32(insn, 14, 1);
    bool is_q = extract32(insn, 30, 1);

    if (opcode == 0 || (size == 3 && !is_q)) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp1 = ra_alloc_ftemp();

    switch (opcode) {
        case 1:        /* UZP1/2 */
            if (!part) /* UZP1 */
            {
                if (!is_q) {
                    switch (size) {
                        case 0:
                            la_vpickev_b(vtemp, vreg_m, vreg_n);
                            la_vpickev_b(vtemp1, vreg_m, vreg_n);
                            la_vbsrl_v(vtemp1, vtemp1, 8);
                            la_vpackev_w(vreg_d, vtemp1, vtemp);

                            break;
                        case 1:
                            la_vpickev_h(vtemp, vreg_m, vreg_n);
                            la_vpickev_h(vtemp1, vreg_m, vreg_n);
                            la_vbsrl_v(vtemp1, vtemp1, 8);
                            la_vpackev_w(vreg_d, vtemp1, vtemp);

                            break;
                        case 2:
                            la_vpickev_w(vtemp, vreg_m, vreg_n);
                            la_vpickev_w(vtemp1, vreg_m, vreg_n);
                            la_vbsrl_v(vtemp1, vtemp1, 8);
                            la_vpackev_w(vreg_d, vtemp1, vtemp);
                            break;
                        case 3:
                            la_vpickev_d(vtemp, vreg_m, vreg_n);
                            la_vpickev_d(vtemp1, vreg_m, vreg_n);
                            la_vbsrl_v(vtemp1, vtemp1, 8);
                            la_vpackev_w(vreg_d, vtemp1, vtemp);
                            break;
                        default:
                            lata_unallocated_encoding(s);
                            return;
                    }
                } else {
                    switch (size) {
                        case 0:
                            la_vpickev_b(vreg_d, vreg_m, vreg_n);
                            break;
                        case 1:
                            la_vpickev_h(vreg_d, vreg_m, vreg_n);
                            break;
                        case 2:
                            la_vpickev_w(vreg_d, vreg_m, vreg_n);
                            break;
                        case 3:
                            la_vpickev_d(vreg_d, vreg_m, vreg_n);
                            break;
                        default:
                            lata_unallocated_encoding(s);
                            return;
                    }
                }
            } else { /* UZP2 */
                if (!is_q) {
                    switch (size) {
                        case 0:
                            la_vpickod_b(vtemp, vreg_m, vreg_n);
                            la_vpickod_b(vtemp1, vreg_m, vreg_n);
                            la_vbsrl_v(vtemp1, vtemp1, 8);
                            la_vpackev_w(vreg_d, vtemp1, vtemp);

                            break;
                        case 1:
                            la_vpickod_h(vtemp, vreg_m, vreg_n);
                            la_vpickod_h(vtemp1, vreg_m, vreg_n);
                            la_vbsrl_v(vtemp1, vtemp1, 8);
                            la_vpackev_w(vreg_d, vtemp1, vtemp);

                            break;
                        case 2:
                            la_vpickod_w(vtemp, vreg_m, vreg_n);
                            la_vpickod_w(vtemp1, vreg_m, vreg_n);
                            la_vbsrl_v(vtemp1, vtemp1, 8);
                            la_vpackev_w(vreg_d, vtemp1, vtemp);
                            break;
                        case 3:
                            la_vpickod_d(vtemp, vreg_m, vreg_n);
                            la_vpickod_d(vtemp1, vreg_m, vreg_n);
                            la_vbsrl_v(vtemp1, vtemp1, 8);
                            la_vpackev_w(vreg_d, vtemp1, vtemp);
                            break;
                        default:
                            assert(0);
                    }
                } else {
                    switch (size) {
                        case 0:
                            la_vpickod_b(vreg_d, vreg_m, vreg_n);
                            break;
                        case 1:
                            la_vpickod_h(vreg_d, vreg_m, vreg_n);
                            break;
                        case 2:
                            la_vpickod_w(vreg_d, vreg_m, vreg_n);
                            break;
                        case 3:
                            la_vpickod_d(vreg_d, vreg_m, vreg_n);
                            break;
                        default:
                            assert(0);
                    }
                }
            }
            break;
        case 2: /* TRN1/2 */
            if (!part) {
                switch (size) {
                    case 0:
                        la_vpackev_b(vreg_d, vreg_m, vreg_n);
                        break;
                    case 1:
                        la_vpackev_h(vreg_d, vreg_m, vreg_n);
                        break;
                    case 2:
                        la_vpackev_w(vreg_d, vreg_m, vreg_n);
                        break;
                    case 3:
                        la_vpackev_d(vreg_d, vreg_m, vreg_n);
                        break;
                    default:
                        assert(0);
                }
            } else {
                switch (size) {
                    case 0:
                        la_vpackod_b(vreg_d, vreg_m, vreg_n);
                        break;
                    case 1:
                        la_vpackod_h(vreg_d, vreg_m, vreg_n);
                        break;
                    case 2:
                        la_vpackod_w(vreg_d, vreg_m, vreg_n);
                        break;
                    case 3:
                        la_vpackod_d(vreg_d, vreg_m, vreg_n);
                        break;
                    default:
                        assert(0);
                }
            }

            break;
        case 3: /* ZIP1/2 */
            if (!part) {
                switch (size) {
                    case 0:
                        la_vilvl_b(vreg_d, vreg_m, vreg_n);
                        break;
                    case 1:
                        la_vilvl_h(vreg_d, vreg_m, vreg_n);
                        break;
                    case 2:
                        la_vilvl_w(vreg_d, vreg_m, vreg_n);
                        break;
                    case 3:
                        la_vilvl_d(vreg_d, vreg_m, vreg_n);
                        break;
                    default:
                        assert(0);
                }
            } else {
                if (!is_q) {
                    switch (size) {
                        case 0:
                            la_vbsll_v(vtemp, vreg_n, 8);
                            la_vbsll_v(vtemp1, vreg_m, 8);
                            la_vilvh_b(vtemp, vtemp1, vtemp);
                            la_vbsrl_v(vreg_d, vtemp, 8);
                            break;
                        case 1:
                            la_vbsll_v(vtemp, vreg_n, 8);
                            la_vbsll_v(vtemp1, vreg_m, 8);
                            la_vilvh_h(vtemp, vtemp1, vtemp);
                            la_vbsrl_v(vreg_d, vtemp, 8);
                            break;
                        case 2:
                            la_vbsll_v(vtemp, vreg_n, 8);
                            la_vbsll_v(vtemp1, vreg_m, 8);
                            la_vilvh_w(vtemp, vtemp1, vtemp);
                            la_vbsrl_v(vreg_d, vtemp, 8);
                            break;
                        case 3:
                            la_vbsll_v(vtemp, vreg_n, 8);
                            la_vbsll_v(vtemp1, vreg_m, 8);
                            la_vilvh_d(vtemp, vtemp1, vtemp);
                            la_vbsrl_v(vreg_d, vtemp, 8);
                            break;
                        default:
                            assert(0);
                    }
                } else {
                    switch (size) {
                        case 0:
                            la_vilvh_b(vreg_d, vreg_m, vreg_n);
                            break;
                        case 1:
                            la_vilvh_h(vreg_d, vreg_m, vreg_n);
                            break;
                        case 2:
                            la_vilvh_w(vreg_d, vreg_m, vreg_n);
                            break;
                        case 3:
                            la_vilvh_d(vreg_d, vreg_m, vreg_n);
                            break;
                        default:
                            assert(0);
                    }
                }
            }

            break;
        default:
            g_assert_not_reached();
    }

    /* 高64位清零 */
    if (!is_q) {
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }
    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp1);
}

/* AdvSIMD across lanes
 *   31  30  29 28       24 23  22 21       17 16    12 11 10 9    5 4    0
 * +---+---+---+-----------+------+-----------+--------+-----+------+------+
 * | 0 | Q | U | 0 1 1 1 0 | size | 1 1 0 0 0 | opcode | 1 0 |  Rn  |  Rd  |
 * +---+---+---+-----------+------+-----------+--------+-----+------+------+
 */
static void disas_simd_across_lanes(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int size = extract32(insn, 22, 2);
    int opcode = extract32(insn, 12, 5);
    bool is_q = extract32(insn, 30, 1);
    bool is_u = extract32(insn, 29, 1);
    bool is_min = extract32(insn, 16, 1);
    ;
    int esize = 8 << size;
    int elements = (is_q ? 128 : 64) / esize;
    int i;

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp2 = ra_alloc_ftemp();

    switch (opcode) {
        case 0x1b: /* ADDV */
            if (is_u || size == 3 || (size == 2 && !is_q)) {
                lata_unallocated_encoding(s);
                return;
            }

            la_vslli_d(vtemp2, vreg_n, 0);
            for (i = 1; i < elements; i++) {
                if (is_q && i >= elements / 2) {
                    la_vpickod_d(vtemp, vreg_n, vreg_n);
                    la_vsrli_d(vtemp, vtemp, esize * (i - elements / 2));
                } else {
                    la_vpickev_d(vtemp, vreg_n, vreg_n);
                    la_vsrli_d(vtemp, vtemp, esize * i);
                }
                switch (size) {
                    case 0:
                        la_vadd_b(vtemp2, vtemp2, vtemp);
                        break;
                    case 1:
                        la_vadd_h(vtemp2, vtemp2, vtemp);
                        break;
                    case 2:
                        la_vadd_w(vtemp2, vtemp2, vtemp);
                        break;
                    default:
                        lata_unallocated_encoding(s);
                        return;
                }
            }

            la_vslli_d(vtemp2, vtemp2, 64 - esize);
            la_vsrli_d(vreg_d, vtemp2, 64 - esize);
            la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);

            break;
        case 0x3:  /* SADDLV, UADDLV */
            if (size == 3 || (size == 2 && !is_q)) {
                lata_unallocated_encoding(s);
                return;
            }
            /* Init accumulator: widen first element to 64-bit */
            la_vslli_d(vtemp2, vreg_n, 64 - esize);
            if (is_u)
                la_vsrli_d(vtemp2, vtemp2, 64 - esize);
            else
                la_vsrai_d(vtemp2, vtemp2, 64 - esize);
            for (i = 1; i < elements; i++) {
                /* Extract element i via pickev/pickod + shift */
                if (is_q && i >= elements / 2) {
                    la_vpickod_d(vtemp, vreg_n, vreg_n);
                    la_vsrli_d(vtemp, vtemp, esize * (i - elements / 2));
                } else {
                    la_vpickev_d(vtemp, vreg_n, vreg_n);
                    la_vsrli_d(vtemp, vtemp, esize * i);
                }
                /* Widen element to 64-bit */
                la_vslli_d(vtemp, vtemp, 64 - esize);
                if (is_u)
                    la_vsrli_d(vtemp, vtemp, 64 - esize);
                else
                    la_vsrai_d(vtemp, vtemp, 64 - esize);
                /* Accumulate */
                la_vadd_d(vtemp2, vtemp2, vtemp);
            }
            /* Mask result: keep only double-width bits */
            {
                int res_esize = esize * 2;
                la_vslli_d(vtemp2, vtemp2, 64 - res_esize);
                if (is_u)
                    la_vsrli_d(vreg_d, vtemp2, 64 - res_esize);
                else
                    la_vsrai_d(vreg_d, vtemp2, 64 - res_esize);
            }
            la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            break;
        case 0xa:  /* SMAXV, UMAXV */
        case 0x1a: /* SMINV, UMINV */
            if (size == 3 || (size == 2 && !is_q)) {
                lata_unallocated_encoding(s);
                return;
            }
            la_vslli_d(vtemp2, vreg_n, 64 - esize);
            la_vsrli_d(vtemp2, vtemp2, 64 - esize);
            for (i = 1; i < elements; i++) {
                if (is_q && i >= elements / 2) {
                    la_vpickod_d(vtemp, vreg_n, vreg_n);
                    la_vsrli_d(vtemp, vtemp, esize * (i - elements / 2));
                } else {
                    la_vpickev_d(vtemp, vreg_n, vreg_n);
                    la_vsrli_d(vtemp, vtemp, esize * i);
                }
                /* SMINV, UMINV */
                if (is_min) {
                    switch (size) {
                        case 0:
                            if (is_u) {
                                la_vmin_bu(vtemp2, vtemp2, vtemp);
                            } else {
                                la_vmin_b(vtemp2, vtemp2, vtemp);
                            }
                            break;
                        case 1:
                            if (is_u) {
                                la_vmin_hu(vtemp2, vtemp2, vtemp);
                            } else {
                                la_vmin_h(vtemp2, vtemp2, vtemp);
                            }
                            break;
                        case 2:
                            if (is_u) {
                                la_vmin_wu(vtemp2, vtemp2, vtemp);
                            } else {
                                la_vmin_w(vtemp2, vtemp2, vtemp);
                            }
                            break;
                        default:
                            assert(0);
                    }
                }
                /* SMAXV, UMAXV */
                else {
                    switch (size) {
                        case 0:
                            if (is_u) {
                                la_vmax_bu(vtemp2, vtemp2, vtemp);
                            } else {
                                la_vmax_b(vtemp2, vtemp2, vtemp);
                            }
                            break;
                        case 1:
                            if (is_u) {
                                la_vmax_hu(vtemp2, vtemp2, vtemp);
                            } else {
                                la_vmax_h(vtemp2, vtemp2, vtemp);
                            }
                            break;
                        case 2:
                            if (is_u) {
                                la_vmax_wu(vtemp2, vtemp2, vtemp);
                            } else {
                                la_vmax_w(vtemp2, vtemp2, vtemp);
                            }
                            break;
                        default:
                            assert(0);
                    }
                }
            }

            la_vslli_d(vtemp2, vtemp2, 64 - esize);
            la_vsrli_d(vreg_d, vtemp2, 64 - esize);
            la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            break;
        case 0xc: /* FMAXNMV, FMINNMV */
        case 0xf: /* FMAXV, FMINV */
            /* For float across-lanes: size=0 (f32 max), size=2 (f32 min),
             * size=3 (f64). is_min from insn bit 16 distinguishes max/min
             * for f64 where size does not encode the operation type. */
            if (!is_u) {
                lata_unallocated_encoding(s);
                return;
            }
            if (size != 2 && size != 3 && size != 0) {
                lata_unallocated_encoding(s);
                return;
            }
            if (size == 0 || size == 2) {
                /* f32: size bit 1 distinguishes max(0)/min(1) */
                is_min = extract32(size, 1, 1);
                size = 2; /* process as f32 */
            }
            /* For f64 (size==3): is_min from insn bit 16 is already correct */
            if (opcode == 0xf) {
                /* FMAXV/FMINV: regular max/min (NaN-propagating) */
                int lanes = is_q ? (size == 3 ? 2 : 4) : (size == 3 ? 1 : 2);
                la_vori_b(vtemp2, vreg_n, 0);
                if (size == 3) { /* f64 */
                    la_vreplvei_d(vreg_d, vreg_n, 0);
                    IR2_OPND nan_res = ra_alloc_ftemp();
                    IR2_OPND nan_tmp = ra_alloc_ftemp();
                    for (i = 1; i < (is_q ? 2 : 1); ++i) {
                        la_vreplvei_d(vtemp, vtemp2, i);
                        if (is_min) {
                            la_fcmp_cond_d(fcc0_ir2_opnd, vreg_d, vtemp, FCMP_COND_CUN);
                            la_fmin_d(nan_res, vreg_d, vtemp);
                            la_fadd_d(nan_tmp, vreg_d, vtemp);
                            la_fsel(vreg_d, nan_res, nan_tmp, fcc0_ir2_opnd);
                        } else {
                            la_fmax_d(vreg_d, vreg_d, vtemp);
                        }
                    }
                    free_alloc_fpr(nan_res);
                    free_alloc_fpr(nan_tmp);
                } else { /* f32 */
                    la_vreplvei_w(vreg_d, vreg_n, 0);
                    IR2_OPND nan_res = ra_alloc_ftemp();
                    IR2_OPND nan_tmp = ra_alloc_ftemp();
                    for (i = 1; i < lanes; ++i) {
                        la_vreplvei_w(vtemp, vtemp2, i);
                        if (is_min) {
                            la_fcmp_cond_s(fcc0_ir2_opnd, vreg_d, vtemp, FCMP_COND_CUN);
                            la_fmin_s(nan_res, vreg_d, vtemp);
                            la_fadd_s(nan_tmp, vreg_d, vtemp);
                            la_fsel(vreg_d, nan_res, nan_tmp, fcc0_ir2_opnd);
                        } else {
                            la_fmax_s(vreg_d, vreg_d, vtemp);
                        }
                    }
                    free_alloc_fpr(nan_res);
                    free_alloc_fpr(nan_tmp);
                }
                la_vand_v(vreg_d, vreg_d, fsmask_ir2_opnd);
            } else {
                /* case 0xc/0x1c: FMAXNMV/FMINNMV */
                la_vori_b(vtemp2, vreg_n, 0);
                if (size == 3) { /* f64 */
                    la_vreplvei_d(vreg_d, vreg_n, 0);
                    for (i = 1; i < (is_q ? 2 : 1); ++i) {
                        la_vreplvei_d(vtemp, vtemp2, i);
                        if (is_min)
                            la_fmin_d(vtemp, vreg_d, vtemp);
                        else
                            la_fmax_d(vtemp, vreg_d, vtemp);
                        la_vori_b(vreg_d, vtemp, 0);
                    }
                } else { /* f32 */
                    la_vreplvei_w(vreg_d, vreg_n, 0);
                    for (i = 1; i < (is_q ? 4 : 2); ++i) {
                        la_vreplvei_w(vtemp, vtemp2, i);
                        if (is_min)
                            la_fmin_s(vtemp, vreg_d, vtemp);
                        else
                            la_fmax_s(vtemp, vreg_d, vtemp);
                        la_vori_b(vreg_d, vtemp, 0);
                    }
                }
                la_vand_v(vreg_d, vreg_d, fsmask_ir2_opnd);
            }
            break;
        default:
            lata_unallocated_encoding(s);
            return;
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp2);
}

/* DUP (Element, Vector)
 *
 *  31  30   29              21 20    16 15        10  9    5 4    0
 * +---+---+-------------------+--------+-------------+------+------+
 * | 0 | Q | 0 0 1 1 1 0 0 0 0 |  imm5  | 0 0 0 0 0 1 |  Rn  |  Rd  |
 * +---+---+-------------------+--------+-------------+------+------+
 *
 * size: encoded in imm5 (see ARM ARM LowestSetBit())
 */
static void handle_simd_dupe(DisasContext* s, int is_q, int rd, int rn,
    int imm5)
{
    int size = ctz32(imm5);
    int index;

    if (size > 3 || (size == 3 && !is_q)) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);

    index = imm5 >> (size + 1);
    switch (size) {
        case 0:
            la_vreplvei_b(vreg_d, vreg_n, index);
            break;
        case 1:
            la_vreplvei_h(vreg_d, vreg_n, index);
            break;
        case 2:
            la_vreplvei_w(vreg_d, vreg_n, index);
            break;
        case 3:
            la_vreplvei_d(vreg_d, vreg_n, index);
            break;
        default:
            lata_unallocated_encoding(s);
            return;
            break;
    }

    if (!is_q) {
        /* 高64位清零 */
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
}

/* DUP (element, scalar)
 *  31                   21 20    16 15        10  9    5 4    0
 * +-----------------------+--------+-------------+------+------+
 * | 0 1 0 1 1 1 1 0 0 0 0 |  imm5  | 0 0 0 0 0 1 |  Rn  |  Rd  |
 * +-----------------------+--------+-------------+------+------+
 */
static void handle_simd_dupes(DisasContext* s, int rd, int rn,
    int imm5)
{
    int size = ctz32(imm5);
    int index;

    if (size > 3) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    index = imm5 >> (size + 1);

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp;

    if (rd != rn) {
        la_vxor_v(vreg_d, vreg_d, vreg_d);
        switch (size) {
            case 0:
                la_vextrins_b(vreg_d, vreg_n, index);
                break;
            case 1:
                la_vextrins_h(vreg_d, vreg_n, index);
                break;
            case 2:
                la_vextrins_w(vreg_d, vreg_n, index);
                break;
            case 3:
                la_vextrins_d(vreg_d, vreg_n, index);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
                break;
        }
    } else {
        vtemp = ra_alloc_ftemp();

        la_vori_b(vtemp, vreg_n, 0);
        la_vxor_v(vreg_d, vreg_d, vreg_d);
        switch (size) {
            case 0:
                la_vextrins_b(vreg_d, vtemp, index);
                break;
            case 1:
                la_vextrins_h(vreg_d, vtemp, index);
                break;
            case 2:
                la_vextrins_w(vreg_d, vtemp, index);
                break;
            case 3:
                la_vextrins_d(vreg_d, vtemp, index);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
                break;
        }
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    if (rd == rn) {
        free_alloc_fpr(vtemp);
    }
}

/* DUP (General)
 *
 *  31  30   29              21 20    16 15        10  9    5 4    0
 * +---+---+-------------------+--------+-------------+------+------+
 * | 0 | Q | 0 0 1 1 1 0 0 0 0 |  imm5  | 0 0 0 0 1 1 |  Rn  |  Rd  |
 * +---+---+-------------------+--------+-------------+------+------+
 *
 * size: encoded in imm5 (see ARM ARM LowestSetBit())
 */
static void handle_simd_dupg(DisasContext* s, int is_q, int rd, int rn,
    int imm5)
{
    int size = ctz32(imm5);

    if (size > 3 || ((size == 3) && !is_q)) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND reg_n = alloc_gpr_src(rn);

    switch (size) {
        case 0:
            la_vreplgr2vr_b(vreg_d, reg_n);
            break;
        case 1:
            la_vreplgr2vr_h(vreg_d, reg_n);
            break;
        case 2:
            la_vreplgr2vr_w(vreg_d, reg_n);
            break;
        case 3:
            la_vreplgr2vr_d(vreg_d, reg_n);
            break;
        default:
            lata_unallocated_encoding(s);
            return;
            break;
    }

    if (!is_q) {
        /* 高64位清零 */
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_gpr(reg_n);
}

/* INS (Element)
 *
 *  31                   21 20    16 15  14    11  10 9    5 4    0
 * +-----------------------+--------+------------+---+------+------+
 * | 0 1 1 0 1 1 1 0 0 0 0 |  imm5  | 0 |  imm4  | 1 |  Rn  |  Rd  |
 * +-----------------------+--------+------------+---+------+------+
 *
 * size: encoded in imm5 (see ARM ARM LowestSetBit())
 * index: encoded in imm5<4:size+1>
 */
static void handle_simd_inse(DisasContext* s, int rd, int rn,
    int imm4, int imm5)
{
    int size = ctz32(imm5);
    int src_index, dst_index;

    if (size > 3) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_src(rd); /* 其他bit不变，需要源寄存器 */
    IR2_OPND vreg_n = alloc_fpr_src(rn);

    dst_index = extract32(imm5, 1 + size, 5);
    src_index = extract32(imm4, size, 4);
    int index = (dst_index << 4) + src_index;
    switch (size) {
        case 0:
            la_vextrins_b(vreg_d, vreg_n, index);
            break;
        case 1:
            la_vextrins_h(vreg_d, vreg_n, index);
            break;
        case 2:
            la_vextrins_w(vreg_d, vreg_n, index);
            break;
        case 3:
            la_vextrins_d(vreg_d, vreg_n, index);
            break;
        default:
            lata_unallocated_encoding(s);
            return;
            break;
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
}

/* INS (General)
 *
 *  31                   21 20    16 15        10  9    5 4    0
 * +-----------------------+--------+-------------+------+------+
 * | 0 1 0 0 1 1 1 0 0 0 0 |  imm5  | 0 0 0 1 1 1 |  Rn  |  Rd  |
 * +-----------------------+--------+-------------+------+------+
 *
 * size: encoded in imm5 (see ARM ARM LowestSetBit())
 * index: encoded in imm5<4:size+1>
 */
static void handle_simd_insg(DisasContext* s, int rd, int rn, int imm5)
{
    int size = ctz32(imm5);
    int idx;

    if (size > 3) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_src(rd); /* 其他bit不变，需要源寄存器 */
    IR2_OPND reg_n = alloc_gpr_src(rn);

    idx = extract32(imm5, 1 + size, 4 - size);
    switch (size) {
        case 0:
            la_vinsgr2vr_b(vreg_d, reg_n, idx);
            break;
        case 1:
            la_vinsgr2vr_h(vreg_d, reg_n, idx);
            break;
        case 2:
            la_vinsgr2vr_w(vreg_d, reg_n, idx);
            break;
        case 3:
            la_vinsgr2vr_d(vreg_d, reg_n, idx);
            break;
        default:
            lata_unallocated_encoding(s);
            return;
            break;
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_gpr(reg_n);
}

/*
 * UMOV (General)
 * SMOV (General)
 *
 *  31  30   29              21 20    16 15    12   10 9    5 4    0
 * +---+---+-------------------+--------+-------------+------+------+
 * | 0 | Q | 0 0 1 1 1 0 0 0 0 |  imm5  | 0 0 1 U 1 1 |  Rn  |  Rd  |
 * +---+---+-------------------+--------+-------------+------+------+
 *
 * U: unsigned when set
 * size: encoded in imm5 (see ARM ARM LowestSetBit())
 */
static void handle_simd_umov_smov(DisasContext* s, int is_q, int is_signed,
    int rn, int rd, int imm5)
{
    int size = ctz32(imm5);
    int element;

    /* Check for UnallocatedEncodings */
    if (is_signed) {
        if (size > 2 || (size == 2 && !is_q)) {
            lata_unallocated_encoding(s);
            return;
        }
    } else {
        if (size > 3 || (size < 3 && is_q) || (size == 3 && !is_q)) {
            lata_unallocated_encoding(s);
            return;
        }
    }

    if (!fp_access_check(s)) {
        return;
    }

    element = extract32(imm5, 1 + size, 4);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND reg_d = alloc_gpr_dst(rd);

    switch (size) {
        case 0:
            if (is_signed) {
                la_vpickve2gr_b(reg_d, vreg_n, element);
            } else {
                la_vpickve2gr_bu(reg_d, vreg_n, element);
            }
            break;
        case 1:
            if (is_signed) {
                la_vpickve2gr_h(reg_d, vreg_n, element);
            } else {
                la_vpickve2gr_hu(reg_d, vreg_n, element);
            }
            break;
        case 2:
            if (is_signed) {
                la_vpickve2gr_w(reg_d, vreg_n, element);
            } else {
                la_vpickve2gr_wu(reg_d, vreg_n, element);
            }
            break;
        case 3:
            if (is_signed) {
                la_vpickve2gr_d(reg_d, vreg_n, element);
            } else {
                la_vpickve2gr_du(reg_d, vreg_n, element);
            }
            break;
            ;
        default:
            lata_unallocated_encoding(s);
            return;
    }

    if (rd != 31 && arm_la_map[rd] >= 0 && clearGprHigh) {
        set_w_write_flag(rd, !(is_signed && !is_q));
    } else {
        if (is_signed && !is_q) {
            la_bstrpick_d(reg_d, reg_d, 31, 0);
        }
    }

    store_gpr_dst(rd, reg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_gpr(reg_d);
}

/* AdvSIMD copy
 *   31  30  29  28             21 20  16 15  14  11 10  9    5 4    0
 * +---+---+----+-----------------+------+---+------+---+------+------+
 * | 0 | Q | op | 0 1 1 1 0 0 0 0 | imm5 | 0 | imm4 | 1 |  Rn  |  Rd  |
 * +---+---+----+-----------------+------+---+------+---+------+------+
 */
static void disas_simd_copy(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int imm4 = extract32(insn, 11, 4);
    int op = extract32(insn, 29, 1);
    int is_q = extract32(insn, 30, 1);
    int imm5 = extract32(insn, 16, 5);

    if (op) {
        if (is_q) {
            /* INS (element) */
            handle_simd_inse(s, rd, rn, imm4, imm5);
        } else {
            lata_unallocated_encoding(s);
        }
    } else {
        switch (imm4) {
            case 0:
                /* DUP (element - vector) */
                handle_simd_dupe(s, is_q, rd, rn, imm5);
                break;
            case 1:
                /* DUP (general) */
                handle_simd_dupg(s, is_q, rd, rn, imm5);
                break;
            case 3:
                if (is_q) {
                    /* INS (general) */
                    handle_simd_insg(s, rd, rn, imm5);
                } else {
                    lata_unallocated_encoding(s);
                }
                break;
            case 5:
            case 7:
                /* UMOV/SMOV (is_q indicates 32/64; imm4 indicates signedness) */
                handle_simd_umov_smov(s, is_q, (imm4 == 5), rn, rd, imm5);
                break;
            default:
                lata_unallocated_encoding(s);
                break;
        }
    }
}

/* AdvSIMD modified immediate
 *  31  30   29  28                 19 18 16 15   12  11  10  9     5 4    0
 * +---+---+----+---------------------+-----+-------+----+---+-------+------+
 * | 0 | Q | op | 0 1 1 1 1 0 0 0 0 0 | abc | cmode | o2 | 1 | defgh |  Rd  |
 * +---+---+----+---------------------+-----+-------+----+---+-------+------+
 *
 * There are a number of operations that can be carried out here:
 *   MOVI - move (shifted) imm into register
 *   MVNI - move inverted (shifted) imm into register
 *   ORR  - bitwise OR of (shifted) imm with register
 *   BIC  - bitwise clear of (shifted) imm with register
 * With ARMv8.2 we also have:
 *   FMOV half-precision
 */
static void disas_simd_mod_imm(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int cmode = extract32(insn, 12, 4);
    int o2 = extract32(insn, 11, 1);
    uint64_t abcdefgh = extract32(insn, 5, 5) | (extract32(insn, 16, 3) << 5);
    bool is_neg = extract32(insn, 29, 1);
    bool is_q = extract32(insn, 30, 1);
    uint64_t imm = 0;

    if (o2 != 0 || ((cmode == 0xf) && is_neg && !is_q)) {
        /* Check for FMOV (vector, immediate) - half-precision */
        if (!(dc_isar_feature(aa64_fp16, s) && o2 && cmode == 0xf)) {
            lata_unallocated_encoding(s);
            return;
        }
    }

    if (!fp_access_check(s)) {
        return;
    }

    if (cmode == 15 && o2 && !is_neg) {
        /* FMOV (vector, immediate) - half-precision */
        imm = vfp_expand_imm(MO_16, abcdefgh);
        /* now duplicate across the lanes */
        imm = dup_const(MO_16, imm);
    } else {
        imm = asimd_imm_const(abcdefgh, cmode, is_neg);
    }
    IR2_OPND vreg_d;
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND temp = ra_alloc_itemp();
    li_d(temp, (int64_t)imm);
    if (!((cmode & 0x9) == 0x1 || (cmode & 0xd) == 0x9)) {
        /* MOVI or MVNI, with MVNI negation handled above.  */
        vreg_d = alloc_fpr_dst(rd);
        la_vreplgr2vr_d(vreg_d, temp);
    } else {
        // assert(0);
        /* ORR or BIC, with BIC negation to AND handled above.  */
        vreg_d = alloc_fpr_src(rd);
        la_vreplgr2vr_d(vtemp, temp);
        if (is_neg) {
            la_vand_v(vreg_d, vreg_d, vtemp);
        } else {
            la_vor_v(vreg_d, vreg_d, vtemp);
        }
    }

    if (!is_q) {
        /* 高64位清零 */
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }
    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vtemp);
    free_alloc_gpr(temp);
}

/* AdvSIMD scalar copy
 *  31 30  29  28             21 20  16 15  14  11 10  9    5 4    0
 * +-----+----+-----------------+------+---+------+---+------+------+
 * | 0 1 | op | 1 1 1 1 0 0 0 0 | imm5 | 0 | imm4 | 1 |  Rn  |  Rd  |
 * +-----+----+-----------------+------+---+------+---+------+------+
 */
static void disas_simd_scalar_copy(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int imm4 = extract32(insn, 11, 4);
    int imm5 = extract32(insn, 16, 5);
    int op = extract32(insn, 29, 1);

    if (op != 0 || imm4 != 0) {
        lata_unallocated_encoding(s);
        return;
    }

    /* DUP (element, scalar) */
    handle_simd_dupes(s, rd, rn, imm5);
}

/* AdvSIMD scalar pairwise
 *  31 30  29 28       24 23  22 21       17 16    12 11 10 9    5 4    0
 * +-----+---+-----------+------+-----------+--------+-----+------+------+
 * | 0 1 | U | 1 1 1 1 0 | size | 1 1 0 0 0 | opcode | 1 0 |  Rn  |  Rd  |
 * +-----+---+-----------+------+-----------+--------+-----+------+------+
 */
static void disas_simd_scalar_pairwise(DisasContext* s, uint32_t insn)
{
    int u = extract32(insn, 29, 1);
    int size = extract32(insn, 22, 2);
    int opcode = extract32(insn, 12, 5);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);

    /* For some ops (the FP ones), size[1] is part of the encoding.
     * For ADDP strictly it is not but size[1] is always 1 for valid
     * encodings.
     */
    opcode |= (extract32(size, 1, 1) << 5);

    switch (opcode) {
        case 0x3b: /* ADDP */
            if (u || size != 3) {
                lata_unallocated_encoding(s);
                return;
            }
            if (!fp_access_check(s)) {
                return;
            }

            break;
        case 0xc:  /* FMAXNMP */
        case 0xd:  /* FADDP */
        case 0xf:  /* FMAXP */
        case 0x2c: /* FMINNMP */
        case 0x2f: /* FMINP */
            /* FP op, size[0] is 32 or 64 bit*/
            if (!u) {
                if (!dc_isar_feature(aa64_fp16, s)) {
                    lata_unallocated_encoding(s);
                    return;
                } else {
                    size = MO_16;
                }
            } else {
                size = extract32(size, 0, 1) ? MO_64 : MO_32;
            }

            if (!fp_access_check(s)) {
                return;
            }

            break;
        default:
            lata_unallocated_encoding(s);
            return;
    }

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();
    if (size == MO_64) {
        la_vreplvei_d(vtemp, vreg_n, 1);

        switch (opcode) {
            case 0x3b: /* ADDP */
                la_vadd_d(vreg_d, vtemp, vreg_n);
                break;
            case 0xc: /* FMAXNMP */
                la_vfmax_d(vreg_d, vreg_n, vtemp);
                break;
            case 0xd: /* FADDP */
                la_vfadd_d(vreg_d, vtemp, vreg_n);
                break;
            case 0xf: /* FMAXP */
                la_vfmax_d(vreg_d, vreg_n, vtemp);
                break;
            case 0x2c: /* FMINNMP */
                la_vfmin_d(vreg_d, vreg_n, vtemp);
                break;
            case 0x2f: /* FMINP — NaN-propagating */
                {
                    IR2_OPND nan_tmp = ra_alloc_ftemp();
                    la_fcmp_cond_d(fcc0_ir2_opnd, vreg_n, vtemp, FCMP_COND_CUN);
                    la_fmin_d(nan_tmp, vreg_n, vtemp);
                    la_fadd_d(vreg_d, vreg_n, vtemp);
                    la_fsel(vreg_d, nan_tmp, vreg_d, fcc0_ir2_opnd);
                    free_alloc_fpr(nan_tmp);
                }
                break;
            default:
                g_assert_not_reached();
        }
    } else {
        if (size == MO_16) {
            lata_unallocated_encoding(s);
            return;
            switch (opcode) {
                case 0xc: /* FMAXNMP */
                    break;
                case 0xd: /* FADDP */
                    break;
                case 0xf: /* FMAXP */
                    break;
                case 0x2c: /* FMINNMP */
                    break;
                case 0x2f: /* FMINP */
                    break;
                default:
                    g_assert_not_reached();
            }
        } else {
            la_vreplvei_w(vtemp, vreg_n, 1);

            switch (opcode) {
                case 0xc: /* FMAXNMP */
                    la_vfmax_s(vreg_d, vreg_n, vtemp);
                    break;
                case 0xd: /* FADDP */
                    la_vfadd_s(vreg_d, vtemp, vreg_n);
                    break;
                case 0xf: /* FMAXP */
                    la_vfmax_s(vreg_d, vreg_n, vtemp);
                    break;
                case 0x2c: /* FMINNMP */
                    la_vfmin_s(vreg_d, vreg_n, vtemp);
                    break;
                case 0x2f: /* FMINP — NaN-propagating */
                    {
                        IR2_OPND nan_tmp = ra_alloc_ftemp();
                        la_fcmp_cond_s(fcc0_ir2_opnd, vreg_n, vtemp, FCMP_COND_CUN);
                        la_fmin_s(nan_tmp, vreg_n, vtemp);
                        la_fadd_s(vreg_d, vreg_n, vtemp);
                        la_fsel(vreg_d, nan_tmp, vreg_d, fcc0_ir2_opnd);
                        free_alloc_fpr(nan_tmp);
                    }
                    break;
                default:
                    g_assert_not_reached();
            }
            la_vand_v(vreg_d, vreg_d, fsmask_ir2_opnd);
        }
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
}

/* SSHR[RA]/USHR[RA] - Scalar shift right (optional rounding/accumulate) */
static void handle_scalar_simd_shri(DisasContext* s,
    bool is_u, int immh, int immb,
    int opcode, int rn, int rd)
{
    int size = 32 - clz32(immh) - 1;
    int immhb = immh << 3 | immb;
    int shift = 2 * (8 << size) - immhb;
    IR2_OPND vreg_d = alloc_fpr_src(rd); /* src for accumulate ops */
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp2 = ra_alloc_ftemp();

    if (size < 0) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    la_vbsrl_v(vtemp, vreg_n, 0);

    switch (opcode) {
        case 0x02: /* SSRA / USRA (accumulate) */
        case 0x06: /* SRSRA / URSRA (accum + rounding) */
        {
            bool is_rounding = (opcode == 0x06);
            int esize = 8 << size;
            if (shift >= esize) {
                if (is_rounding && is_u) {
                    /* URSRA: unsigned rounding shift >= esize => (x >> (esize-1)) & 1 */
                    la_vsrli_d(vtemp, vtemp, esize - 1);
                } else if (!is_rounding && !is_u) {
                    /* SSRA: signed shift >= esize => all sign bits */
                    la_vsrai_d(vtemp, vtemp, esize - 1);
                } else {
                    /* USRA, SRSRA: shift >= esize => 0 */
                    la_vandi_b(vtemp, vtemp, 0);
                }
            } else if (is_rounding) {
                if (is_u)
                    la_vsrlri_d(vtemp, vtemp, shift);
                else
                    la_vsrari_d(vtemp, vtemp, shift);
            } else {
                if (is_u)
                    la_vsrli_d(vtemp, vtemp, shift);
                else
                    la_vsrai_d(vtemp, vtemp, shift);
            }
            la_vadd_q(vtemp2, vtemp, vreg_d);
            la_vori_b(vreg_d, vtemp2, 0);
        } break;

        case 0x08: /* SRI: result = (vd & ~(ones>>shift)) | (vn >> shift) */
        {
            int esize = 8 << size;
            if (shift == 0) {
                /* SRI with shift=0: mask=0, result = vn */
                la_vori_b(vreg_d, vtemp, 0);
            } else if (shift < esize) {
                /* Shift vn right (SRI always uses logical shift) */
                la_vsrli_d(vtemp, vtemp, shift);
                IR2_OPND vmask = ra_alloc_ftemp();
                IR2_OPND igpr = ra_alloc_itemp();
                la_vxor_v(vmask, vmask, vmask); /* clear mask */
                uint64_t ones = 0xFFFFFFFFFFFFFFFFULL;
                uint64_t mask = ~(ones >> shift); /* keep high shift bits from vd */
                li_d(igpr, mask);
                la_vinsgr2vr_d(vmask, igpr, 0);
                free_alloc_gpr(igpr);
                la_vand_v(vmask, vreg_d, vmask);
                la_vor_v(vreg_d, vtemp, vmask);
                free_alloc_fpr(vmask);
            }
            /* shift >= esize: vn>>esize=0, mask=all-1s → result=vd unchanged */
        } break;

        case 0x00: /* SSHR / USHR */
        case 0x04: /* SRSHR / URSHR (rounding) */
        {
            int esize = 8 << size;
            bool is_rounding = (opcode == 0x04);
            if (shift >= esize) {
                if (is_rounding && is_u) {
                    /* URSHR: unsigned rounding shift >= esize => (x >> (esize-1)) & 1 */
                    la_vsrli_d(vtemp, vtemp, esize - 1);
                } else if (!is_rounding && !is_u) {
                    /* SSHR: signed shift >= esize => all sign bits */
                    la_vsrai_d(vtemp, vtemp, esize - 1);
                } else {
                    /* USHR, SRSHR: shift >= esize => 0 */
                    la_vandi_b(vtemp, vtemp, 0);
                }
            } else if (is_rounding) {
                if (is_u)
                    la_vsrlri_d(vtemp, vtemp, shift);
                else
                    la_vsrari_d(vtemp, vtemp, shift);
            } else {
                if (is_u)
                    la_vsrli_d(vtemp, vtemp, shift);
                else
                    la_vsrai_d(vtemp, vtemp, shift);
            }
            la_vori_b(vreg_d, vtemp, 0);
        } break;

        default:
            g_assert_not_reached();
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp2);
}

/* SHL/SLI - Scalar shift left */
static void handle_scalar_simd_shli(DisasContext* s, bool insert,
    int immh, int immb, int opcode,
    int rn, int rd)
{
    int size = 32 - clz32(immh) - 1;
    int immhb = immh << 3 | immb;
    int shift = immhb - (8 << size);

    if (!extract32(immh, 3, 1)) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_mask = ra_alloc_ftemp();
    IR2_OPND vreg_temp = ra_alloc_ftemp();

    if (!insert) {
        la_vslli_d(vreg_d, vreg_n, shift);
    } else if (shift == 0) {
        /* shift=0: mask>>64 = 0; result = vn */
        la_vori_b(vreg_d, vreg_n, 0);
    } else {
        la_vfcmp_cond_d(vreg_mask, vreg_n, vreg_n, FCMP_COND_SEQ);
        la_vsrli_d(vreg_mask, vreg_mask, 64 - shift);

        la_vand_v(vreg_temp, vreg_d, vreg_mask);
        la_vslli_d(vreg_d, vreg_n, shift);
        la_vor_v(vreg_d, vreg_d, vreg_temp);
    }
    /* 高64位清零 */
    la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_mask);
    free_alloc_fpr(vreg_temp);
}

/* SQSHRN/SQSHRUN - Saturating (signed/unsigned) shift right with
 * (signed/unsigned) narrowing */
static void handle_vec_simd_sqshrn(DisasContext* s, bool is_scalar, bool is_q,
    bool is_u_shift, bool is_u_narrow,
    int immh, int immb, int opcode,
    int rn, int rd)
{
    int immhb = immh << 3 | immb;
    int size = 32 - clz32(immh) - 1;
    int esize = 8 << size;
    int shift = (2 * esize) - immhb;
    bool round = extract32(opcode, 0, 1);

    assert(size < 4);

    if (extract32(immh, 3, 1)) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    /* Scalar: single element narrow; vector code handles element 0 correctly */
    IR2_OPND vreg_d = is_scalar ? alloc_fpr_dst(rd) : alloc_fpr_src(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp2 = ra_alloc_ftemp();
    IR2_OPND vreg;

    if (is_scalar) {
        vreg = vreg_d;
        la_vori_b(vtemp2, vreg_n, 0);
    } else if (is_q) {
        /* SQSHRN2/UQSHRN2 narrow the whole source to 64 bits, then insert it
         * into the destination high half.  The source is not pre-shifted. */
        vreg = vtemp;
        la_vori_b(vtemp2, vreg_n, 0);
    } else {
        vreg = vreg_d;
        la_vori_b(vtemp2, vreg_n, 0);
    }

    if (round) {
        if (is_u_shift) {
            switch (size) {
                case 0: la_vssrlrni_bu_h(vreg, vtemp2, shift); break;
                case 1: la_vssrlrni_hu_w(vreg, vtemp2, shift); break;
                case 2: la_vssrlrni_wu_d(vreg, vtemp2, shift); break;
                default: lata_unallocated_encoding(s); return;
            }
        } else {
            if (!is_u_narrow) {
                switch (size) {
                    case 0: la_vssrarni_b_h(vreg, vtemp2, shift); break;
                    case 1: la_vssrarni_h_w(vreg, vtemp2, shift); break;
                    case 2: la_vssrarni_w_d(vreg, vtemp2, shift); break;
                    default: lata_unallocated_encoding(s); return;
                }
            } else {
                /* SQRSHRUN: signed→unsigned with rounding.
                   Must use arithmetic (signed) rounding shift, not logical. */
                switch (size) {
                    case 0: la_vssrarni_bu_h(vreg, vtemp2, shift); break;
                    case 1: la_vssrarni_hu_w(vreg, vtemp2, shift); break;
                    case 2: la_vssrarni_wu_d(vreg, vtemp2, shift); break;
                    default: lata_unallocated_encoding(s); return;
                }
            }
        }
    } else {
        if (is_u_shift) {
            switch (size) {
                case 0: la_vssrlni_bu_h(vreg, vtemp2, shift); break;
                case 1: la_vssrlni_hu_w(vreg, vtemp2, shift); break;
                case 2: la_vssrlni_wu_d(vreg, vtemp2, shift); break;
                default: lata_unallocated_encoding(s); return;
            }
        } else {
            if (!is_u_narrow) {
                switch (size) {
                    case 0: la_vssrani_b_h(vreg, vtemp2, shift); break;
                    case 1: la_vssrani_h_w(vreg, vtemp2, shift); break;
                    case 2: la_vssrani_w_d(vreg, vtemp2, shift); break;
                    default: assert(0);
                }
            } else {
                /* SQSHRUN: signed→unsigned without rounding.
                   Must use arithmetic (signed) shift, not logical. */
                switch (size) {
                    case 0: la_vssrani_bu_h(vreg, vtemp2, shift); break;
                    case 1: la_vssrani_hu_w(vreg, vtemp2, shift); break;
                    case 2: la_vssrani_wu_d(vreg, vtemp2, shift); break;
                    default: assert(0);
                }
            }
        }
    }

    if (is_q)
        /* XTN2: narrowed result goes to HIGH half, keep original LOW half.
           VPCKEV.D: vd[127:64]=vj[63:0], vd[63:0]=vk[63:0].
           We want vtemp (narrowed) → HIGH, vreg_d (original) → LOW. */
        la_vpickev_d(vreg_d, vtemp, vreg_d);
    else
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp2);
}

/* SQSHLU, UQSHL, SQSHL: saturating left shifts */
static void handle_simd_qshl(DisasContext* s, bool scalar, bool is_q,
    bool src_unsigned, bool dst_unsigned,
    int immh, int immb, int rn, int rd)
{
    /* Immediate saturating shift left: vd = SatShiftLeft(vn, shift)
     * shift = immhb - element_bits where immhb = immh<<3 | immb */
    int size = 32 - clz32(immh) - 1;
    int immhb = (immh << 3) | immb;
    int shift = immhb - (8 << size);
    if (shift <= 0) {
        /* Right shift or no shift: just use regular shift */
        shift = -shift;
        IR2_OPND vreg_d = alloc_fpr_dst(rd);
        IR2_OPND vreg_n = alloc_fpr_src(rn);
        if (src_unsigned) {
            switch (size) {
                case 0: la_vsrli_b(vreg_d, vreg_n, shift); break;
                case 1: la_vsrli_h(vreg_d, vreg_n, shift); break;
                case 2: la_vsrli_w(vreg_d, vreg_n, shift); break;
                case 3: la_vsrli_d(vreg_d, vreg_n, shift); break;
            }
        } else {
            switch (size) {
                case 0: la_vsrai_b(vreg_d, vreg_n, shift); break;
                case 1: la_vsrai_h(vreg_d, vreg_n, shift); break;
                case 2: la_vsrai_w(vreg_d, vreg_n, shift); break;
                case 3: la_vsrai_d(vreg_d, vreg_n, shift); break;
            }
        }
        /* SQSHLU (dst_unsigned, !src_unsigned): negative inputs → 0 */
        if (dst_unsigned && !src_unsigned) {
            IR2_OPND vzero_sq = ra_alloc_ftemp();
            IR2_OPND vsgn_sq = ra_alloc_ftemp();
            la_vxor_v(vzero_sq, vzero_sq, vzero_sq);
            switch (size) {
                case 0: la_vslti_b(vsgn_sq, vreg_n, 0); break;
                case 1: la_vslti_h(vsgn_sq, vreg_n, 0); break;
                case 2: la_vslti_w(vsgn_sq, vreg_n, 0); break;
                case 3: la_vslti_d(vsgn_sq, vreg_n, 0); break;
            }
            la_vbitsel_v(vreg_d, vreg_d, vzero_sq, vsgn_sq);
            free_alloc_fpr(vzero_sq);
            free_alloc_fpr(vsgn_sq);
        }
        if (!is_q) la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
        store_fpr_dst(rd, vreg_d);
        free_alloc_fpr(vreg_d);
        free_alloc_fpr(vreg_n);
    } else {
        /* Left shift with saturation */
        IR2_OPND vreg_d = alloc_fpr_dst(rd);
        IR2_OPND vreg_n_fpr = alloc_fpr_src(rn);
        /* CRITICAL: vreg_d and vreg_n_fpr may alias (same physical register
           when rd==rn). Save original value before vslli overwrites it. */
        IR2_OPND vn_orig = ra_alloc_ftemp();
        la_vori_b(vn_orig, vreg_n_fpr, 0);
        IR2_OPND vtemp = ra_alloc_ftemp(); /* overflow mask */
        IR2_OPND vtmp2 = ra_alloc_ftemp(); /* work temp */

        /* 1. Left shift the operand */
        if (src_unsigned) {
            switch (size) {
                case 0: la_vslli_b(vreg_d, vreg_n_fpr, shift); break;
                case 1: la_vslli_h(vreg_d, vreg_n_fpr, shift); break;
                case 2: la_vslli_w(vreg_d, vreg_n_fpr, shift); break;
                case 3: la_vslli_d(vreg_d, vreg_n_fpr, shift); break;
            }
        } else {
            switch (size) {
                case 0: la_vslli_b(vreg_d, vreg_n_fpr, shift); break;
                case 1: la_vslli_h(vreg_d, vreg_n_fpr, shift); break;
                case 2: la_vslli_w(vreg_d, vreg_n_fpr, shift); break;
                case 3: la_vslli_d(vreg_d, vreg_n_fpr, shift); break;
            }
        }

        /* 2. Shift back to detect overflow: (result >> shift) != original */
        if (src_unsigned) {
            switch (size) {
                case 0: la_vsrli_b(vtemp, vreg_d, shift); break;
                case 1: la_vsrli_h(vtemp, vreg_d, shift); break;
                case 2: la_vsrli_w(vtemp, vreg_d, shift); break;
                case 3: la_vsrli_d(vtemp, vreg_d, shift); break;
            }
        } else {
            /* SQSHLU: signed source, unsigned dest → use logical shift
               for overflow detection (unsigned range check). */
            if (dst_unsigned) {
                switch (size) {
                    case 0: la_vsrli_b(vtemp, vreg_d, shift); break;
                    case 1: la_vsrli_h(vtemp, vreg_d, shift); break;
                    case 2: la_vsrli_w(vtemp, vreg_d, shift); break;
                    case 3: la_vsrli_d(vtemp, vreg_d, shift); break;
                }
            } else {
                switch (size) {
                    case 0: la_vsrai_b(vtemp, vreg_d, shift); break;
                    case 1: la_vsrai_h(vtemp, vreg_d, shift); break;
                    case 2: la_vsrai_w(vtemp, vreg_d, shift); break;
                    case 3: la_vsrai_d(vtemp, vreg_d, shift); break;
                }
            }
        }
        switch (size) {
            case 0: la_vseq_b(vtemp, vtemp, vn_orig); break;
            case 1: la_vseq_h(vtemp, vtemp, vn_orig); break;
            case 2: la_vseq_w(vtemp, vtemp, vn_orig); break;
            case 3: la_vseq_d(vtemp, vtemp, vn_orig); break;
        }
        la_vnori_b(vtemp, vtemp, 0); /* NOT: 0xFF where overflow, 0x00 where OK */

        /* 3. Apply saturation */
        if (dst_unsigned) {
            /* Saturate to UINT_MAX (SQSHLU or UQSHL) */
            IR2_OPND umax = ra_alloc_ftemp();
            la_vxor_v(umax, umax, umax);
            la_vnori_b(umax, umax, 0); /* all-ones = UINT_MAX */
            /* For SQSHLU, compute negative mask before modifying vreg_d */
            if (!src_unsigned) {
                switch (size) {
                    case 0: la_vslti_b(vtmp2, vn_orig, 0); break;
                    case 1: la_vslti_h(vtmp2, vn_orig, 0); break;
                    case 2: la_vslti_w(vtmp2, vn_orig, 0); break;
                    case 3: la_vslti_d(vtmp2, vn_orig, 0); break;
                }
            }
            /* Apply saturation via vbitsel: overflow ? UMAX : shifted.
               Use intermediate temp to avoid vd==vj aliasing with two-step SQSHLU. */
            {
                IR2_OPND vtmp3 = ra_alloc_ftemp();
                la_vbitsel_v(vtmp3, vreg_d, umax, vtemp);
                if (!src_unsigned) {
                    /* SQSHLU: negative inputs → 0, overrides overflow saturation.
                       vbitsel: neg_mask ? 0 : tmp3 */
                    IR2_OPND vzero_sq = ra_alloc_ftemp();
                    la_vxor_v(vzero_sq, vzero_sq, vzero_sq);
                    la_vbitsel_v(vreg_d, vtmp3, vzero_sq, vtmp2);
                    free_alloc_fpr(vzero_sq);
                } else {
                    la_vori_b(vreg_d, vtmp3, 0);
                }
                free_alloc_fpr(vtmp3);
            }
            free_alloc_fpr(umax);
        } else {
            /* Signed saturation to INT_MAX (positive) or INT_MIN (negative) */
            IR2_OPND vmin = ra_alloc_ftemp(); /* INT_MIN */
            IR2_OPND vmax = ra_alloc_ftemp(); /* INT_MAX */
            IR2_OPND vsgn = ra_alloc_ftemp(); /* sign mask */
            IR2_OPND igpr = ra_alloc_itemp();
            if (size == 0) {
                li_d(igpr, 0x8080808080808080LL);
                la_vreplgr2vr_b(vmin, igpr);
            } else if (size == 1) {
                li_d(igpr, 0x8000800080008000LL);
                la_vreplgr2vr_h(vmin, igpr);
            } else if (size == 2) {
                li_d(igpr, 0x8000000080000000LL);
                la_vreplgr2vr_w(vmin, igpr);
            } else {
                li_d(igpr, 0x8000000000000000LL);
                la_vreplgr2vr_d(vmin, igpr);
            }
            free_alloc_gpr(igpr);
            la_vnori_b(vmax, vmin, 0); /* INT_MAX = ~INT_MIN */
            /* sign_mask: negative → -1, positive → 0 */
            switch (size) {
                case 0: la_vslti_b(vsgn, vn_orig, 0); break;
                case 1: la_vslti_h(vsgn, vn_orig, 0); break;
                case 2: la_vslti_w(vsgn, vn_orig, 0); break;
                case 3: la_vslti_d(vsgn, vn_orig, 0); break;
            }
            /* sat_val = sign_mask ? INT_MAX(sat_mx) : INT_MIN(sat_mn)
               Wait: vbitsel(vmax, vmax, vmin, vsgn):
               vsgn=-1(neg): selects vmin=INT_MIN; vsgn=0(pos): selects vmax=INT_MAX */
            la_vbitsel_v(vmax, vmax, vmin, vsgn);
            free_alloc_fpr(vmin);
            free_alloc_fpr(vsgn);
            /* Apply saturation: overflow ? sat_val(vmax) : left_shift(vreg_d) */
            la_vbitsel_v(vreg_d, vreg_d, vmax, vtemp);
            free_alloc_fpr(vmax);
        }

        if (!is_q) la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
        store_fpr_dst(rd, vreg_d);
        free_alloc_fpr(vreg_d);
        free_alloc_fpr(vreg_n_fpr);
        free_alloc_fpr(vn_orig);
        free_alloc_fpr(vtemp);
        free_alloc_fpr(vtmp2);
    }
}

/* Common vector code for handling integer to FP conversion */
static void handle_simd_intfp_conv(DisasContext* s, int rd, int rn,
    int elements, int is_signed,
    int fracbits, int size)
{
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);

    if (size == MO_64) {

        if (is_signed) {
            la_vffint_d_l(vreg_d, vreg_n);
        } else {
            la_vffint_d_lu(vreg_d, vreg_n);
        }
        if (fracbits) {
            IR2_OPND igpr = ra_alloc_itemp();
            IR2_OPND vscale = ra_alloc_ftemp();
            union {
                double d;
                uint64_t u;
            } sd;
            if (fracbits > 0)
                sd.u = fp64_pow2_bits(-fracbits);
            else
                sd.u = fp64_pow2_bits(-fracbits);
            li_d(igpr, sd.u);
            la_vreplgr2vr_d(vscale, igpr);
            la_vfmul_d(vreg_d, vreg_d, vscale);
            free_alloc_fpr(vscale);
            free_alloc_gpr(igpr);
        }
    } else {

        switch (size) {
            case MO_32:
                if (is_signed) {
                    la_vffint_s_w(vreg_d, vreg_n);
                } else {
                    la_vffint_s_wu(vreg_d, vreg_n);
                }
                if (fracbits) {
                    /* Scale by 2^(-fracbits) */
                    IR2_OPND igpr = ra_alloc_itemp();
                    IR2_OPND vscale = ra_alloc_ftemp();
                    union {
                        float f;
                        uint32_t u;
                    } sf;
                    if (fracbits > 0)
                        sf.u = fp32_pow2_bits(-fracbits);
                    else
                        sf.u = fp32_pow2_bits(-fracbits);
                    li_w(igpr, sf.u);
                    la_vreplgr2vr_w(vscale, igpr);
                    la_vfmul_s(vreg_d, vreg_d, vscale);
                    free_alloc_fpr(vscale);
                    free_alloc_gpr(igpr);
                }
                break;
            case MO_16: {
                /* f16: first convert int→f32, then narrow to f16 */
                IR2_OPND vlo_w = ra_alloc_ftemp();
                IR2_OPND vhi_w = ra_alloc_ftemp();
                IR2_OPND vlo_f = ra_alloc_ftemp();
                IR2_OPND vhi_f = ra_alloc_ftemp();
                if (is_signed) {
                    la_vsllwil_w_h(vlo_w, vreg_n, 0);
                    la_vexth_w_h(vhi_w, vreg_n);
                } else {
                    la_vsllwil_wu_hu(vlo_w, vreg_n, 0);
                    la_vexth_wu_hu(vhi_w, vreg_n);
                }
                la_vffint_s_w(vlo_f, vlo_w);
                if (elements > 4) {
                    la_vffint_s_w(vhi_f, vhi_w);
                }
                if (fracbits) {
                    IR2_OPND igpr = ra_alloc_itemp();
                    IR2_OPND vscale = ra_alloc_ftemp();
                    union {
                        float f;
                        uint32_t u;
                    } sf;
                    if (fracbits > 0)
                        sf.u = fp32_pow2_bits(-fracbits);
                    else
                        sf.u = fp32_pow2_bits(-fracbits);
                    li_w(igpr, sf.u);
                    la_vreplgr2vr_w(vscale, igpr);
                    la_vfmul_s(vlo_f, vlo_f, vscale);
                    if (elements > 4) {
                        la_vfmul_s(vhi_f, vhi_f, vscale);
                    }
                    free_alloc_fpr(vscale);
                    free_alloc_gpr(igpr);
                }
                la_vfcvt_h_s(vreg_d, vhi_f, vlo_f);
                free_alloc_fpr(vlo_w);
                free_alloc_fpr(vhi_w);
                free_alloc_fpr(vlo_f);
                free_alloc_fpr(vhi_f);
                break;
            }
            default:
                g_assert_not_reached();
        }
    }

    if (elements * (8 << size) < 128) {
        /* 高64位清零 */
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }
    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
}

/* UCVTF/SCVTF - Integer to FP conversion */
static void handle_simd_shift_intfp_conv(DisasContext* s, bool is_scalar,
    bool is_q, bool is_u,
    int immh, int immb, int opcode,
    int rn, int rd)
{
    int size, elements, fracbits;
    int immhb = immh << 3 | immb;

    if (immh & 8) {
        size = MO_64;
        if (!is_scalar && !is_q) {
            lata_unallocated_encoding(s);
            return;
        }
    } else if (immh & 4) {
        size = MO_32;
    } else if (immh & 2) {
        size = MO_16;
        if (!dc_isar_feature(aa64_fp16, s)) {
            lata_unallocated_encoding(s);
            return;
        }
    } else {
        /* immh == 0 would be a failure of the decode logic */
        g_assert(immh == 1);
        lata_unallocated_encoding(s);
        return;
    }

    if (is_scalar) {
        elements = 1;
    } else {
        elements = (8 << is_q) >> size;
    }
    fracbits = (16 << size) - immhb;

    if (!fp_access_check(s)) {
        return;
    }

    handle_simd_intfp_conv(s, rd, rn, elements, !is_u, fracbits, size);
}

/* FCVTZS, FVCVTZU - FP to fixedpoint conversion */
static void handle_simd_shift_fpint_conv(DisasContext* s, bool is_scalar,
    bool is_q, bool is_u,
    int immh, int immb, int rn, int rd)
{
    /* FCVTZS/FCVTZU: float→integer, round toward zero */
    int size;
    int immhb = immh << 3 | immb;
    int fracbits;
    if (immh & 8)
        size = MO_64;
    else if (immh & 4)
        size = MO_32;
    else if (immh & 2)
        size = MO_16;
    else {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) return;
    fracbits = (16 << size) - immhb;

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();

    if (size == MO_16) {
        /* f16→i16: vfcvtl_s_h (f16→f32), vftintrz_w_s (f32→i32),
         * vssrani_h_w (i32→i16, saturating narrow). */
        IR2_OPND vtemp_f32 = ra_alloc_ftemp();
        la_vfcvtl_s_h(vtemp_f32, vreg_n);
        la_vand_v(vtemp_f32, vtemp_f32, fsmask_ir2_opnd);
        if (fracbits) {
            IR2_OPND vscale = ra_alloc_ftemp();
            IR2_OPND igpr = ra_alloc_itemp();
            union {
                float f;
                uint32_t u;
            } sf = { .u = fp32_pow2_bits(fracbits) };
            li_w(igpr, sf.u);
            la_vreplgr2vr_w(vscale, igpr);
            la_vfmul_s(vtemp_f32, vtemp_f32, vscale);
            free_alloc_fpr(vscale);
            free_alloc_gpr(igpr);
        }
        if (is_u)
            la_vftintrz_wu_s(vtemp_f32, vtemp_f32);
        else
            la_vftintrz_w_s(vtemp_f32, vtemp_f32);
        if (is_u)
            la_vssrani_hu_w(vreg_d, vtemp_f32, 0);
        else
            la_vssrani_h_w(vreg_d, vtemp_f32, 0);
        free_alloc_fpr(vtemp_f32);
    } else if (size == MO_32) {
        if (fracbits) {
            IR2_OPND vscale = ra_alloc_ftemp();
            IR2_OPND igpr = ra_alloc_itemp();
            union {
                float f;
                uint32_t u;
            } sf = { .u = fp32_pow2_bits(fracbits) };
            li_w(igpr, sf.u);
            la_vreplgr2vr_w(vscale, igpr);
            la_vfmul_s(vtemp, vreg_n, vscale);
            free_alloc_fpr(vscale);
            free_alloc_gpr(igpr);
        } else {
            la_vor_v(vtemp, vreg_n, vreg_n);
        }
        if (is_u)
            la_vftintrz_wu_s(vtemp, vtemp);
        else
            la_vftintrz_w_s(vtemp, vtemp);
        la_vor_v(vreg_d, vtemp, vtemp);
    } else { /* MO_64 */
        if (fracbits) {
            IR2_OPND vscale = ra_alloc_ftemp();
            IR2_OPND igpr = ra_alloc_itemp();
            union {
                double d;
                uint64_t u;
            } sd = { .u = fp64_pow2_bits(fracbits) };
            li_d(igpr, sd.u);
            la_vreplgr2vr_d(vscale, igpr);
            la_vfmul_d(vtemp, vreg_n, vscale);
            free_alloc_fpr(vscale);
            free_alloc_gpr(igpr);
        } else {
            la_vor_v(vtemp, vreg_n, vreg_n);
        }
        if (is_u)
            la_vftintrz_lu_d(vtemp, vtemp);
        else
            la_vftintrz_l_d(vtemp, vtemp);
        la_vor_v(vreg_d, vtemp, vtemp);
    }

    if (!is_q && !is_scalar) {
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }
    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
}

/* AdvSIMD scalar shift by immediate
 *  31 30  29 28         23 22  19 18  16 15    11  10 9    5 4    0
 * +-----+---+-------------+------+------+--------+---+------+------+
 * | 0 1 | U | 1 1 1 1 1 0 | immh | immb | opcode | 1 |  Rn  |  Rd  |
 * +-----+---+-------------+------+------+--------+---+------+------+
 *
 * This is the scalar version so it works on a fixed sized registers
 */
static void disas_simd_scalar_shift_imm(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int opcode = extract32(insn, 11, 5);
    int immb = extract32(insn, 16, 3);
    int immh = extract32(insn, 19, 4);
    bool is_u = extract32(insn, 29, 1);

    if (immh == 0) {
        lata_unallocated_encoding(s);
        return;
    }

    switch (opcode) {
        case 0x08: /* SRI */
            if (!is_u) {
                lata_unallocated_encoding(s);
                return;
            }
            /* fall through */
        case 0x00: /* SSHR / USHR */
        case 0x02: /* SSRA / USRA */
        case 0x04: /* SRSHR / URSHR */
        case 0x06: /* SRSRA / URSRA */
            handle_scalar_simd_shri(s, is_u, immh, immb, opcode, rn, rd);
            break;
        case 0x0a: /* SHL / SLI */
            handle_scalar_simd_shli(s, is_u, immh, immb, opcode, rn, rd);
            break;
        case 0x1c: /* SCVTF, UCVTF */
            handle_simd_shift_intfp_conv(s, true, false, is_u, immh, immb,
                opcode, rn, rd);
            break;
        case 0x10: /* SQSHRUN, SQSHRUN2 */
        case 0x11: /* SQRSHRUN, SQRSHRUN2 */
            if (!is_u) {
                lata_unallocated_encoding(s);
                return;
            }
            handle_vec_simd_sqshrn(s, true, false, false, true,
                immh, immb, opcode, rn, rd);
            break;
        case 0x12: /* SQSHRN, SQSHRN2, UQSHRN */
        case 0x13: /* SQRSHRN, SQRSHRN2, UQRSHRN, UQRSHRN2 */
            handle_vec_simd_sqshrn(s, true, false, is_u, is_u,
                immh, immb, opcode, rn, rd);
            break;
        case 0xc: /* SQSHLU */
            if (!is_u) {
                lata_unallocated_encoding(s);
                return;
            }
            handle_simd_qshl(s, true, false, false, true, immh, immb, rn, rd);
            break;
        case 0xe: /* SQSHL, UQSHL */
            handle_simd_qshl(s, true, false, is_u, is_u, immh, immb, rn, rd);
            break;
        case 0x1f: /* FCVTZS, FCVTZU */
            handle_simd_shift_fpint_conv(s, true, false, is_u, immh, immb, rn, rd);
            break;
        default:
            lata_unallocated_encoding(s);
            break;
    }
}

/* AdvSIMD scalar three different
 *  31 30  29 28       24 23  22  21 20  16 15    12 11 10 9    5 4    0
 * +-----+---+-----------+------+---+------+--------+-----+------+------+
 * | 0 1 | U | 1 1 1 1 0 | size | 1 |  Rm  | opcode | 0 0 |  Rn  |  Rd  |
 * +-----+---+-----------+------+---+------+--------+-----+------+------+
 */
static void disas_simd_scalar_three_reg_diff(DisasContext* s, uint32_t insn)
{
    /* Scalar three-reg different: SQDMLAL, SQDMLSL, SQDMULL (scalar).
     * Opcode at bits[15:12] (4 bits), bit21=1, bit10=0.
     * n.b. standard ADD/SUB widening ops (SADDL, etc.) have bit21=0
     * and are handled by the new decoder in TCG; not yet implemented here. */
    bool is_u = extract32(insn, 29, 1);
    int size = extract32(insn, 22, 2);
    int opcode = extract32(insn, 12, 4);
    int rm = extract32(insn, 16, 5);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);

    if (is_u || opcode < 0x9 || opcode > 0xd || size == 0 || size == 3) {
        lata_unallocated_encoding(s);
        return;
    }
    if (!fp_access_check(s)) return;

    IR2_OPND vd = alloc_fpr_dst(rd);
    IR2_OPND vn = alloc_fpr_src(rn);
    IR2_OPND vm = alloc_fpr_src(rm);
    IR2_OPND dbl = ra_alloc_ftemp(); /* doubled product */

    if (size == 2) {
        /* 32-bit * 32-bit → 64-bit, using vmulwev_d_w + vsadd_d */
        la_vmulwev_d_w(dbl, vn, vm);
        la_vsadd_d(dbl, dbl, dbl); /* double, saturating */
    } else {
        /* 16-bit * 16-bit → 32-bit, using vmulwev_w_h + vsadd_w */
        la_vmulwev_w_h(dbl, vn, vm);
        la_vsadd_w(dbl, dbl, dbl); /* double, saturating */
    }

    switch (opcode) {
        case 0xd: /* SQDMULL — doubled product is the result, copy to vd */
            la_vori_b(vd, dbl, 0);
            break;
        case 0xb: /* SQDMLSL: rd = sat(rd - doubled_product) */
        {
            IR2_OPND v_rd = alloc_fpr_src(rd);
            if (size == 2)
                la_vssub_d(vd, v_rd, dbl);
            else
                la_vssub_w(vd, v_rd, dbl);
            free_alloc_fpr(v_rd);
        } break;
        case 0x9: /* SQDMLAL: rd = sat(rd + doubled_product) */
        {
            IR2_OPND v_rd = alloc_fpr_src(rd);
            if (size == 2)
                la_vsadd_d(vd, v_rd, dbl);
            else
                la_vsadd_w(vd, v_rd, dbl);
            free_alloc_fpr(v_rd);
        } break;
    }

    la_vinsgr2vr_d(vd, zero_ir2_opnd, 1);
    store_fpr_dst(rd, vd);
    free_alloc_fpr(vd);
    free_alloc_fpr(vn);
    free_alloc_fpr(vm);
    free_alloc_fpr(dbl);
}

static void handle_3same_64(DisasContext* s, int opcode, bool u,
    int rd, int rn, int rm)
{
    /* Handle 64x64->64 opcodes which are shared between the scalar
     * and vector 3-same groups. We cover every opcode where size == 3
     * is valid in either the three-reg-same (integer, not pairwise)
     * or scalar-three-reg-same groups.
     */
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vreg_temp = ra_alloc_ftemp();
    IR2_OPND vreg_temp1 = ra_alloc_ftemp();
    IR2_OPND temp = ra_alloc_itemp();
    IR2_OPND vleft = ra_alloc_ftemp();
    IR2_OPND vright = ra_alloc_ftemp();

    IR2_OPND label = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND exit = ir2_opnd_new_type(IR2_OPND_LABEL);

    switch (opcode) {
        case 0x1: /* SQADD */
            if (u) {
                la_vsadd_du(vreg_temp1, vreg_n, vreg_m);
            } else {
                la_vsadd_d(vreg_temp1, vreg_n, vreg_m);
            }
            break;
        case 0x5: /* SQSUB */
            if (u) {
                la_vssub_du(vreg_temp1, vreg_n, vreg_m);
            } else {
                la_vssub_d(vreg_temp1, vreg_n, vreg_m);
            }
            la_vinsgr2vr_d(vreg_temp1, zero_ir2_opnd, 1);

            la_vsub_d(vreg_temp, vreg_n, vreg_m);
            la_vinsgr2vr_d(vreg_temp, zero_ir2_opnd, 1);

            la_vseq_d(vreg_temp, vreg_temp1, vreg_temp);
            la_vsetanyeqz_b(fcc1_ir2_opnd, vreg_temp);
            la_bcnez(fcc1_ir2_opnd, label);
            la_b(exit);

            la_label(label);
            li_d(temp, 1);
            la_st_w(temp, env_ir2_opnd, env_offset_QC());

            la_label(exit);

            la_vori_b(vreg_d, vreg_temp1, 0);

            break;
        case 0x6: /* CMGT, CMHI */
            lata_unallocated_encoding(s);
            return;
            break;
        case 0x7: /* CMGE, CMHS */
            lata_unallocated_encoding(s);
            return;
            break;
        case 0x11: /* CMTST, CMEQ */
            lata_unallocated_encoding(s);
            return;
            break;
        case 0x8: /* SSHL, USHL */
            /* 取元素中shift */
            la_vslli_d(vleft, vreg_m, 56);
            la_vsrli_d(vleft, vleft, 56);

            /* 正数放vleft左移，负数取反后放vright右移，vreg_temp存放符号位*/
            la_vslti_b(vreg_temp, vleft, 0);
            la_vand_v(vright, vreg_temp, vleft);
            la_vsub_b(vleft, vleft, vright);
            la_vsigncov_b(vright, vreg_temp, vright);

            /* ARM
             * 移位量不做模运算，这里需要特殊处理，左移大于等于元素长度对应清零，右移大于等于元素长度shift-1*/
            /* vslti的立即数限制5位，进行特殊处理，右移缩小2倍与16比较 */
            la_vsll_d(vreg_d, vreg_n, vleft);
            if (!u) {
                la_vsra_d(vreg_d, vreg_d, vright);
            } else {
                la_vsrl_d(vreg_d, vreg_d, vright);
            }
            la_vsrli_b(vreg_temp, vleft, 2);
            la_vslti_du(vleft, vreg_temp, 16);
            la_vsrli_b(vright, vright, 2);
            la_vslti_du(vright, vright, 16);

            // la_vsll_d(vreg_temp, vreg_n, vleft);
            la_vand_v(vreg_temp, vreg_d, vleft);

            /* 正常右移 */
            la_vand_v(vreg_temp, vreg_temp, vright);
            /* 满位右移 */
            la_vnori_b(vright, vright, 0);
            if (!u) {
                la_vsrai_d(vleft, vreg_n, 63);
            } else {
                la_vandi_b(vleft, vreg_n, 0);
            }
            la_vand_v(vleft, vright, vleft);
            la_vadd_d(vreg_d, vreg_temp, vleft);

            la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            break;
        case 0xa: /* SRSHL, URSHL — 64-bit rounding shift (non-saturating) */
        {
            /* 1. Truncate shift to int8_t and sign-extend. */
            la_vslli_d(vreg_m, vreg_m, 56);
            la_vsrai_d(vreg_m, vreg_m, 56);

            /* 2. vreg_temp1 = sign_mask (shift < 0). */
            la_vslti_d(vreg_temp1, vreg_m, 0);

            /* 3. vreg_temp = neg_shift = -shift. */
            la_vneg_d(vreg_temp, vreg_m);

            /* 4. Save operand — rd may alias rn. */
            IR2_OPND vn64_saved = ra_alloc_ftemp();
            la_vori_b(vn64_saved, vreg_n, 0);

            /* 5. Right-shift path (rounding). */
            if (u)
                la_vsrlr_d(vreg_d, vn64_saved, vreg_temp);
            else
                la_vsrar_d(vreg_d, vn64_saved, vreg_temp);

            /* 5.1 large_right = neg_shift >= 64.
             *     LSX vsrar/vsrlr masks shift to &63. */
            la_vldi(vright, 0xC00 | 64);
            la_vslt_du(vright, vreg_temp, vright);
            la_vnori_b(vright, vright, 0);

            /* 5.2 Zero right_result when neg_shift >= 64. */
            la_vxor_v(vreg_temp, vreg_temp, vreg_temp);
            la_vbitsel_v(vreg_d, vreg_d, vreg_temp, vright);

            /* 5.3 [unsigned] neg_shift == 64: override with MSB. */
            if (u) {
                la_vldi(vright, 0xC00 | ((-64) & 0x3FF));
                la_vseq_d(vright, vreg_m, vright);
                la_vsrli_d(vreg_temp, vn64_saved, 63);
                la_vbitsel_v(vreg_d, vreg_d, vreg_temp, vright);
            }

            /* 6. Save rresult before building left-shift path. */
            la_vori_b(vreg_temp, vreg_d, 0);

            /* 7. Left-shift path. */
            la_vsll_d(vleft, vn64_saved, vreg_m);

            /* 7.1 large_left = shift >= 64.
             *     LSX vsll masks shift to &63. */
            la_vldi(vright, 0xC00 | 64);
            la_vslt_du(vright, vreg_m, vright);
            la_vnori_b(vright, vright, 0);

            /* Only non-negative shifts can produce large_left overflow. */
            la_vnori_b(vreg_d, vreg_temp1, 0);
            la_vand_v(vright, vright, vreg_d);

            /* 7.2 Zero left_result when shift >= 64. */
            la_vxor_v(vreg_d, vreg_d, vreg_d);
            la_vbitsel_v(vleft, vleft, vreg_d, vright);

            free_alloc_fpr(vn64_saved);

            /* 8. Final select: sign_mask ? rresult : lresult. */
            la_vbitsel_v(vreg_d, vleft, vreg_temp, vreg_temp1);
            break;
        }
        case 0x9: /* SQSHL, UQSHL — scalar saturating shift */
        case 0xb: /* SQRSHL, UQRSHL — scalar saturating rounding shift */
        {
            bool rnd = (opcode == 0x0b);
            /*
             * ARM semantics:
             *   shift < 0: right shift by -shift
             *   shift >= 0: left shift, saturating on overflow
             *   shift <= -esize: unsigned -> 0, signed -> sign mask
             *   shift >= esize: saturate if operand != 0
             */

            /* 1. Truncate shift to int8_t and sign-extend. */
            la_vslli_d(vreg_m, vreg_m, 56);
            la_vsrai_d(vreg_m, vreg_m, 56);

            /* 2. shift_sign = shift < 0, neg_shift = -shift. */
            la_vslti_d(vreg_temp1, vreg_m, 0); /* shift_sign */
            la_vneg_d(vreg_temp, vreg_m);      /* neg_shift */

            /* rd may alias rn; keep operand for overflow/sign checks. */
            IR2_OPND vn64_saved = ra_alloc_ftemp();
            la_vori_b(vn64_saved, vreg_n, 0);

            /* 3. Right-shift path. */
            if (rnd && u)
                la_vsrlr_d(vreg_d, vn64_saved, vreg_temp); /* UQRSHL: logical rounding */
            else if (rnd)
                la_vsrar_d(vreg_d, vn64_saved, vreg_temp); /* SQRSHL: arithmetic rounding */
            else if (u)
                la_vsrl_d(vreg_d, vn64_saved, vreg_temp);
            else
                la_vsra_d(vreg_d, vn64_saved, vreg_temp);

            /* 3.1 Fix shift <= -64.
             *     SQSHL: sign_mask for signed, 0 for unsigned.
             *     SQRSHL: rounding right shift by >=64 always produces 0,
             *     not sign_mask (the MSB rounding bit cancels the sign extension). */
            la_vldi(vright, 0xC00 | 64);
            la_vslt_du(vright, vreg_temp, vright); /* negsh < 64 */
            la_vnori_b(vright, vright, 0);         /* NOT: negsh >= 64 */
            if (u) {
                la_vxor_v(vreg_temp, vreg_temp, vreg_temp); /* zero */
                la_vbitsel_v(vreg_d, vreg_d, vreg_temp, vright);
            } else if (rnd) {
                /* SQRSHL: large_right gives 0, not sign_mask. */
                la_vxor_v(vreg_temp, vreg_temp, vreg_temp);
                la_vbitsel_v(vreg_d, vreg_d, vreg_temp, vright);
            } else {
                /* SQSHL: large_right gives sign_mask. */
                la_vslti_d(vreg_temp, vn64_saved, 0);
                la_vbitsel_v(vreg_d, vreg_d, vreg_temp, vright);
            }

            /* 3.2 [UQRSHL] shift == -64: override with MSB.
             *     ARM rounding logical right shift by 64 = operand >> 63. */
            if (u && rnd) {
                la_vldi(vright, 0xC00 | ((-64) & 0x3FF));
                la_vseq_d(vright, vreg_m, vright);
                la_vsrli_d(vreg_temp, vn64_saved, 63);
                la_vbitsel_v(vreg_d, vreg_d, vreg_temp, vright);
            }

            /* Save rresult before building the left-shift path. */
            la_vori_b(vreg_temp, vreg_d, 0);

            /* 4. Left-shift path. */
            la_vsll_d(vleft, vn64_saved, vreg_m);

            /* 4.1 overflow = shift >= esize. */
            la_vldi(vright, 0xC00 | 64);
            la_vslt_du(vright, vreg_m, vright);
            la_vnori_b(vright, vright, 0);

            /* Only non-negative shifts can overflow the left-shift path. */
            la_vnori_b(vreg_d, vreg_temp1, 0);
            la_vand_v(vright, vright, vreg_d);

            /* 4.2 overflow |= (lresult >> shift) != operand. */
            {
                IR2_OPND z = ra_alloc_ftemp(); /* +1 = 5 */
                la_vxor_v(z, z, z);
                la_vseq_d(vreg_d, vn64_saved, z);
                la_vnori_b(vreg_d, vreg_d, 0);
                la_vand_v(vright, vright, vreg_d);
                if (rnd && u)
                    la_vsrl_d(z, vleft, vreg_m); /* UQRSHL: unsigned back-shift */
                else if (rnd)
                    la_vsra_d(z, vleft, vreg_m); /* SQRSHL: signed back-shift */
                else if (u)
                    la_vsrl_d(z, vleft, vreg_m);
                else
                    la_vsra_d(z, vleft, vreg_m);
                la_vseq_d(z, z, vn64_saved);
                la_vnor_v(z, z, z);
                la_vor_v(vright, z, vright);
                free_alloc_fpr(z); /* back to 4 */
            }

            /* 5. Select saturated value where overflow is set. */
            if (u) {
                free_alloc_fpr(vn64_saved);
                IR2_OPND um = ra_alloc_ftemp(); /* 5 */
                la_vxor_v(um, um, um);
                la_vnori_b(um, um, 0);
                la_vbitsel_v(vleft, vleft, um, vright);
                free_alloc_fpr(um);
            } else {
                /* Signed saturation: choose INT_MIN for negative operand,
                   otherwise INT_MAX. */
                la_vslti_d(vreg_d, vn64_saved, 0);   /* sign_mask in vreg_d */
                free_alloc_fpr(vn64_saved);
                IR2_OPND vmn = ra_alloc_ftemp(); /* 4 (reuses freed slot) */
                li_d(temp, 0x8000000000000000LL);
                la_vreplgr2vr_d(vmn, temp);
                IR2_OPND vmx = ra_alloc_ftemp();     /* 5 */
                la_vnori_b(vmx, vmn, 0);             /* INT_MAX */
                la_vbitsel_v(vmx, vmx, vmn, vreg_d); /* vmx=sat_val */
                free_alloc_fpr(vmn);
                la_vbitsel_v(vleft, vleft, vmx, vright);
                free_alloc_fpr(vmx);
            }

            /* 6. Final select: shift < 0 ? rresult : lresult. */
            la_vbitsel_v(vreg_d, vleft, vreg_temp, vreg_temp1);
            /* vn64_saved freed earlier */
        } break;
        case 0x10: /* ADD, SUB */
            if (u) {
                la_vsub_d(vreg_d, vreg_n, vreg_m);
            } else {
                la_vadd_d(vreg_d, vreg_n, vreg_m);
            }
            la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            break;
        default:
            g_assert_not_reached();
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);

    free_alloc_fpr(vreg_temp);
    free_alloc_fpr(vreg_temp1);
    free_alloc_fpr(vleft);
    free_alloc_fpr(vright);
    free_alloc_gpr(temp);
}

static void handle_3same_float(DisasContext* s, int size, int elements,
    int fpopcode, int rd, int rn, int rm)
{
    // IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp1 = ra_alloc_ftemp();
    IR2_OPND vtemp2 = ra_alloc_ftemp();
    IR2_OPND vtemp3 = ra_alloc_ftemp();

    IR2_OPND vreg_d;
    if (fpopcode == 0x39 || fpopcode == 0x19) {
        vreg_d = alloc_fpr_src(rd);
    } else {
        vreg_d = alloc_fpr_dst(rd);
    }
    if (size) {
        /* Double */
        switch (fpopcode) {
            case 0x39: /* FMLS */
                la_vxor_v(vtemp, vtemp, vtemp);
                la_vfsub_d(vtemp, vtemp, vreg_n);
                la_vfmadd_d(vreg_d, vtemp, vreg_m, vreg_d);
                break;
            case 0x19: /* FMLA */
                la_vfmadd_d(vreg_d, vreg_n, vreg_m, vreg_d);
                break;
            case 0x18: /* FMAXNM */
                la_vfmax_d(vreg_d, vreg_n, vreg_m);
                break;
            case 0x1a: /* FADD */
                la_vfadd_d(vreg_d, vreg_n, vreg_m);
                break;
            case 0x1b: /* FMULX */
                la_vfmul_d(vreg_d, vreg_n, vreg_m);
                break;
            case 0x1c: /* FCMEQ */
                la_vfcmp_cond_d(vreg_d, vreg_n, vreg_m, FCMP_COND_SEQ);
                break;
            case 0x1e: /* FMAX */
                la_vfmax_d(vtemp, vreg_n, vreg_m);
                la_vfcmp_cond_d(vtemp1, vreg_n, vreg_m, FCMP_COND_CUN);
                la_vfcmp_cond_d(vtemp2, vreg_n, vreg_n, FCMP_COND_CUN);
                la_vbitsel_v(vtemp3, vreg_m, vreg_n, vtemp2);
                la_vbitsel_v(vreg_d, vtemp, vtemp3, vtemp1);
                break;
            case 0x1f: /* FRECPS: 2.0 - vn * vm */
            {
                la_vfmul_d(vreg_d, vreg_n, vreg_m);
                IR2_OPND _it = ra_alloc_itemp(), _vc = ra_alloc_ftemp();
                li_d(_it, 0x4000000000000000ULL);
                la_movgr2fr_d(_vc, _it);
                la_vfsub_d(vreg_d, _vc, vreg_d);
                free_alloc_fpr(_vc);
                free_alloc_gpr(_it);
            } break;
            case 0x38: /* FMINNM */
                la_vfmin_d(vreg_d, vreg_n, vreg_m);
                break;
            case 0x3a: /* FSUB */
                la_vfsub_d(vreg_d, vreg_n, vreg_m);
                break;
            case 0x3e: /* FMIN */
                la_vfmin_d(vtemp, vreg_n, vreg_m);
                la_vfcmp_cond_d(vtemp1, vreg_n, vreg_m, FCMP_COND_CUN);
                la_vfcmp_cond_d(vtemp2, vreg_n, vreg_n, FCMP_COND_CUN);
                la_vbitsel_v(vtemp3, vreg_m, vreg_n, vtemp2);
                la_vbitsel_v(vreg_d, vtemp, vtemp3, vtemp1);
                break;
            case 0x3f: /* FRSQRTS: (3.0 - vn * vm) / 2.0 */
            {
                la_vfmul_d(vreg_d, vreg_n, vreg_m);
                IR2_OPND _it2 = ra_alloc_itemp(), _vc2 = ra_alloc_ftemp();
                li_d(_it2, 0x4008000000000000ULL);
                la_movgr2fr_d(_vc2, _it2);
                la_vfsub_d(vreg_d, _vc2, vreg_d);
                li_d(_it2, 0x3fe0000000000000ULL);
                la_movgr2fr_d(_vc2, _it2);
                la_vfmul_d(vreg_d, vreg_d, _vc2);
                free_alloc_fpr(_vc2);
                free_alloc_gpr(_it2);
            } break;
            case 0x5b: /* FMUL */
                la_vfmul_d(vreg_d, vreg_n, vreg_m);
                break;
            case 0x5c: /* FCMGE */
                la_vfcmp_cond_d(vreg_d, vreg_m, vreg_n, FCMP_COND_SLE);
                break;
            case 0x5d: /* FACGE: |a| >= |b| */
            {          /* Mask sign bits for element-wise abs, then compare */
                IR2_OPND _mask = ra_alloc_ftemp(), _igpr = ra_alloc_itemp();
                li_d(_igpr, 0x7FFFFFFFFFFFFFFFULL);
                la_vreplgr2vr_d(_mask, _igpr);
                la_vand_v(vtemp, vreg_n, _mask);    /* |vn| */
                la_vand_v(vtemp1, vreg_m, _mask);   /* |vm| */
                free_alloc_fpr(_mask);
                free_alloc_gpr(_igpr);
                la_vfcmp_cond_d(vreg_d, vtemp1, vtemp, FCMP_COND_CLE);
            } break;
            case 0x5f: /* FDIV */
                la_vfdiv_d(vreg_d, vreg_n, vreg_m);
                break;
            case 0x7a: /* FABD */
                la_vfsub_d(vreg_d, vreg_n, vreg_m);
                la_vreplvei_d(vtemp, vreg_d, 1);
                la_fabs_d(vreg_d, vreg_d);
                la_fabs_d(vtemp, vtemp);
                la_vextrins_d(vreg_d, vtemp, 1 << 4);
                break;
            case 0x7c: /* FCMGT */
                la_vfcmp_cond_d(vreg_d, vreg_m, vreg_n, FCMP_COND_SLT);
                break;
            case 0x7d: /* FACGT: |a| > |b| */
            {          /* Mask sign bits for element-wise abs, then compare */
                IR2_OPND _mask = ra_alloc_ftemp(), _igpr = ra_alloc_itemp();
                li_d(_igpr, 0x7FFFFFFFFFFFFFFFULL);
                la_vreplgr2vr_d(_mask, _igpr);
                la_vand_v(vtemp, vreg_n, _mask);    /* |vn| */
                la_vand_v(vtemp1, vreg_m, _mask);   /* |vm| */
                free_alloc_fpr(_mask);
                free_alloc_gpr(_igpr);
                la_vfcmp_cond_d(vreg_d, vtemp1, vtemp, FCMP_COND_CLT);
            } break;
                break;
            default:
                g_assert_not_reached();
        }
    } else {
        /* Single */
        switch (fpopcode) {
            case 0x39: /* FMLS */
                la_vxor_v(vtemp, vtemp, vtemp);
                la_vfsub_s(vtemp, vtemp, vreg_n);
                la_vfmadd_s(vreg_d, vtemp, vreg_m, vreg_d);
                break;
            case 0x19: /* FMLA */
                la_vfmadd_s(vreg_d, vreg_n, vreg_m, vreg_d);
                sanitize_fpcr_dn(vreg_d, false);
                break;
            case 0x1a: /* FADD */
                la_vfadd_s(vreg_d, vreg_n, vreg_m);
                sanitize_fpcr_dn(vreg_d, false);
                break;
            case 0x1b: /* FMULX */
                la_vfmul_s(vreg_d, vreg_n, vreg_m);
                break;
            case 0x1c: /* FCMEQ */
                la_vfcmp_cond_s(vreg_d, vreg_n, vreg_m, FCMP_COND_SEQ);
                break;
            case 0x1e: /* FMAX */
                la_vfmax_s(vtemp, vreg_n, vreg_m);
                la_vfcmp_cond_s(vtemp1, vreg_n, vreg_m, FCMP_COND_CUN);
                la_vfcmp_cond_s(vtemp2, vreg_n, vreg_n, FCMP_COND_CUN);
                la_vbitsel_v(vtemp3, vreg_m, vreg_n, vtemp2);
                la_vbitsel_v(vreg_d, vtemp, vtemp3, vtemp1);
                break;
            case 0x1f: /* FRECPS: 2.0 - vn * vm */
                la_vfmul_s(vtemp, vreg_n, vreg_m);
                {
                    IR2_OPND itemp_2 = ra_alloc_itemp();
                    IR2_OPND vtwo = ra_alloc_ftemp();
                    li_d(itemp_2, 0x40000000); /* 2.0f */
                    la_vreplgr2vr_w(vtwo, itemp_2);
                    la_vfsub_s(vreg_d, vtwo, vtemp);
                    free_alloc_fpr(vtwo);
                    free_alloc_gpr(itemp_2);
                }
                break;
            case 0x18: /* FMAXNM */
                la_vfmax_s(vreg_d, vreg_n, vreg_m);
                break;
            case 0x38: /* FMINNM */
                la_vfmin_s(vreg_d, vreg_n, vreg_m);
                break;
            case 0x3a: /* FSUB */
                la_vfsub_s(vreg_d, vreg_n, vreg_m);
                break;
            case 0x3e: /* FMIN */
                la_vfmin_s(vtemp, vreg_n, vreg_m);
                la_vfcmp_cond_s(vtemp1, vreg_n, vreg_m, FCMP_COND_CUN);
                la_vfcmp_cond_s(vtemp2, vreg_n, vreg_n, FCMP_COND_CUN);
                la_vbitsel_v(vtemp3, vreg_m, vreg_n, vtemp2);
                la_vbitsel_v(vreg_d, vtemp, vtemp3, vtemp1);
                break;
            case 0x3f: /* FRSQRTS: (3.0 - vn * vm) / 2.0 */
                la_vfmul_s(vtemp, vreg_n, vreg_m);
                {
                    IR2_OPND itemp_c = ra_alloc_itemp();
                    IR2_OPND vconst = ra_alloc_ftemp();
                    li_d(itemp_c, 0x40400000); /* 3.0f */
                    la_vreplgr2vr_w(vconst, itemp_c);
                    la_vfsub_s(vtemp, vconst, vtemp);
                    li_d(itemp_c, 0x3f000000); /* 0.5f */
                    la_vreplgr2vr_w(vconst, itemp_c);
                    la_vfmul_s(vreg_d, vtemp, vconst);
                    free_alloc_fpr(vconst);
                    free_alloc_gpr(itemp_c);
                }
                break;
            case 0x5b: /* FMUL */
                la_vfmul_s(vreg_d, vreg_n, vreg_m);
                break;
            case 0x5c: /* FCMGE */
                la_vfcmp_cond_s(vreg_d, vreg_m, vreg_n, FCMP_COND_SLE);
                break;
            case 0x5d: /* FACGE */
                /* Copy sources first to avoid aliasing issues */
                la_vori_b(vtemp2, vreg_n, 0);
                la_vori_b(vtemp3, vreg_m, 0);
                for (int i = 0; i < elements; ++i) {
                    la_vreplvei_w(vtemp, vtemp2, i);
                    la_fabs_s(vtemp, vtemp);
                    la_vextrins_w(vreg_d, vtemp, i << 4);
                }
                for (int i = 0; i < elements; ++i) {
                    la_vreplvei_w(vtemp1, vtemp3, i);
                    la_fabs_s(vtemp1, vtemp1);
                    la_vextrins_w(vtemp, vtemp1, i << 4);
                }
                la_vfcmp_cond_s(vreg_d, vtemp, vreg_d, FCMP_COND_CLE);
                break;
            case 0x5f: /* FDIV */
                la_vfdiv_s(vreg_d, vreg_n, vreg_m);
                break;
            case 0x7a: /* FABD */
                la_vfsub_s(vtemp1, vreg_n, vreg_m);
                for (int i = 0; i < elements; ++i) {
                    la_vreplvei_w(vtemp, vtemp1, i);
                    la_fabs_s(vtemp, vtemp);
                    la_vextrins_w(vreg_d, vtemp, i << 4);
                }
                break;
            case 0x7c: /* FCMGT */
                la_vfcmp_cond_s(vreg_d, vreg_m, vreg_n, FCMP_COND_SLT);
                break;
            case 0x7d: /* FACGT */
                la_vori_b(vtemp2, vreg_n, 0);
                la_vori_b(vtemp3, vreg_m, 0);
                for (int i = 0; i < elements; ++i) {
                    la_vreplvei_w(vtemp, vtemp2, i);
                    la_fabs_s(vtemp, vtemp);
                    la_vextrins_w(vreg_d, vtemp, i << 4);
                }
                for (int i = 0; i < elements; ++i) {
                    la_vreplvei_w(vtemp1, vtemp3, i);
                    la_fabs_s(vtemp1, vtemp1);
                    la_vextrins_w(vtemp, vtemp1, i << 4);
                }
                la_vfcmp_cond_s(vreg_d, vtemp, vreg_d, FCMP_COND_CLT);
                break;
            default:
                g_assert_not_reached();
        }

        if (elements == 2) {
            /* 高64位清零 */
            la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
        }
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp1);
    free_alloc_fpr(vtemp2);
    free_alloc_fpr(vtemp3);
}

static void handle_3same_float_scalar(DisasContext* s, int size, int fpopcode,
    int rd, int rn, int rm)
{
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);

    if (size) {
        /* Double */

        switch (fpopcode) {
            case 0x1b: /* FMULX */
                la_vfmul_d(vreg_d, vreg_n, vreg_m);
                break;
            case 0x1c: /* FCMEQ */
                lata_unallocated_encoding(s);
                return;
                break;
            case 0x1f: /* FRECPS: 2.0 - vn * vm */
            {
                la_fmul_d(vreg_d, vreg_n, vreg_m);
                IR2_OPND _it = ra_alloc_itemp(), _vc = ra_alloc_ftemp();
                li_d(_it, 0x4000000000000000ULL);   /* 2.0 */
                la_movgr2fr_d(_vc, _it);
                la_fsub_d(vreg_d, _vc, vreg_d);
                free_alloc_fpr(_vc);
                free_alloc_gpr(_it);
            } break;
            case 0x3f: /* FRSQRTS: (3.0 - vn * vm) / 2.0 */
            {
                la_fmul_d(vreg_d, vreg_n, vreg_m);
                IR2_OPND _it2 = ra_alloc_itemp(), _vc2 = ra_alloc_ftemp();
                li_d(_it2, 0x4008000000000000ULL);  /* 3.0 */
                la_movgr2fr_d(_vc2, _it2);
                la_fsub_d(vreg_d, _vc2, vreg_d);
                li_d(_it2, 0x3FE0000000000000ULL);  /* 0.5 */
                la_movgr2fr_d(_vc2, _it2);
                la_fmul_d(vreg_d, vreg_d, _vc2);
                free_alloc_fpr(_vc2);
                free_alloc_gpr(_it2);
            } break;
            case 0x5c: /* FCMGE */
                la_vfcmp_cond_d(vreg_d, vreg_m, vreg_n, FCMP_COND_SLE);
                break;
            case 0x5d: /* FACGE */
            {
                IR2_OPND vt = ra_alloc_ftemp();
                IR2_OPND vn_abs = ra_alloc_ftemp();
                la_fabs_d(vn_abs, vreg_n);
                la_fabs_d(vt, vreg_m);
                la_vfcmp_cond_d(vreg_d, vt, vn_abs, FCMP_COND_CLE);
                free_alloc_fpr(vt);
                free_alloc_fpr(vn_abs);
            } break;
            case 0x7a: /* FABD */
                la_fsub_d(vreg_d, vreg_n, vreg_m);
                la_fabs_d(vreg_d, vreg_d);
                break;
            case 0x7c: /* FCMGT */
                la_vfcmp_cond_d(vreg_d, vreg_m, vreg_n, FCMP_COND_SLT);
                break;
            case 0x7d: /* FACGT */
            {
                IR2_OPND vt = ra_alloc_ftemp();
                IR2_OPND vn_abs = ra_alloc_ftemp();
                la_fabs_d(vn_abs, vreg_n);
                la_fabs_d(vt, vreg_m);
                la_vfcmp_cond_d(vreg_d, vt, vn_abs, FCMP_COND_CLT);
                free_alloc_fpr(vt);
                free_alloc_fpr(vn_abs);
            } break;
            default:
                g_assert_not_reached();
        }
        /* 高64位清零 */
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    } else {
        /* Single */

        switch (fpopcode) {
            case 0x1b: /* FMULX */
                la_vfmul_s(vreg_d, vreg_n, vreg_m);
                break;
            case 0x1c: /* FCMEQ */
                lata_unallocated_encoding(s);
                return;
                break;
            case 0x1f: /* FRECPS: 2.0 - vn * vm */
            {
                la_fmul_s(vreg_d, vreg_n, vreg_m);
                IR2_OPND _it = ra_alloc_itemp(), _vc = ra_alloc_ftemp();
                li_d(_it, 0x40000000);
                la_movgr2fr_w(_vc, _it);
                la_fsub_s(vreg_d, _vc, vreg_d);
                free_alloc_fpr(_vc);
                free_alloc_gpr(_it);
            } break;
                return;
                break;
            case 0x3f: /* FRSQRTS: (3.0 - vn * vm) / 2.0 */
            {
                la_fmul_s(vreg_d, vreg_n, vreg_m);
                IR2_OPND _it2 = ra_alloc_itemp(), _vc2 = ra_alloc_ftemp();
                li_d(_it2, 0x40400000);
                la_movgr2fr_w(_vc2, _it2);
                la_fsub_s(vreg_d, _vc2, vreg_d);
                li_d(_it2, 0x3f000000);
                la_movgr2fr_w(_vc2, _it2);
                la_fmul_s(vreg_d, vreg_d, _vc2);
                free_alloc_fpr(_vc2);
                free_alloc_gpr(_it2);
            } break;
                return;
                break;
            case 0x5c: /* FCMGE */
                la_vfcmp_cond_s(vreg_d, vreg_m, vreg_n, FCMP_COND_SLE);
                break;
            case 0x5d: /* FACGE */
            {
                IR2_OPND vt = ra_alloc_ftemp();
                IR2_OPND vn_abs = ra_alloc_ftemp();
                la_fabs_s(vn_abs, vreg_n);
                la_fabs_s(vt, vreg_m);
                la_vfcmp_cond_s(vreg_d, vt, vn_abs, FCMP_COND_CLE);
                free_alloc_fpr(vt);
                free_alloc_fpr(vn_abs);
            } break;
            case 0x7a: /* FABD */
                la_fsub_s(vreg_d, vreg_n, vreg_m);
                la_fabs_s(vreg_d, vreg_d);
                break;
            case 0x7c: /* FCMGT */
                la_vfcmp_cond_s(vreg_d, vreg_m, vreg_n, FCMP_COND_SLT);
                break;
            case 0x7d: /* FACGT */
            {
                IR2_OPND vt = ra_alloc_ftemp();
                IR2_OPND vn_abs = ra_alloc_ftemp();
                la_fabs_s(vn_abs, vreg_n);
                la_fabs_s(vt, vreg_m);
                la_vfcmp_cond_s(vreg_d, vt, vn_abs, FCMP_COND_CLT);
                free_alloc_fpr(vt);
                free_alloc_fpr(vn_abs);
            } break;
                break;
            default:
                g_assert_not_reached();
        }

        bool high_clean = fpr_clear_high_if_live(vreg_d, rd, 2);
        store_scalar_fpr_dst(rd, vreg_d, 2, high_clean);
    }

    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
}

/* AdvSIMD scalar three same
 *  31 30  29 28       24 23  22  21 20  16 15    11  10 9    5 4    0
 * +-----+---+-----------+------+---+------+--------+---+------+------+
 * | 0 1 | U | 1 1 1 1 0 | size | 1 |  Rm  | opcode | 1 |  Rn  |  Rd  |
 * +-----+---+-----------+------+---+------+--------+---+------+------+
 */
static void disas_simd_scalar_three_reg_same(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int opcode = extract32(insn, 11, 5);
    int rm = extract32(insn, 16, 5);
    int size = extract32(insn, 22, 2);
    bool u = extract32(insn, 29, 1);

    if (opcode >= 0x18) {
        /* Floating point: U, size[1] and opcode indicate operation */
        int fpopcode = opcode | (extract32(size, 1, 1) << 5) | (u << 6);
        switch (fpopcode) {
            case 0x1b: /* FMULX */
            case 0x1f: /* FRECPS */
            case 0x3f: /* FRSQRTS */
            case 0x5d: /* FACGE */
            case 0x7d: /* FACGT */
            case 0x1c: /* FCMEQ */
            case 0x5c: /* FCMGE */
            case 0x7c: /* FCMGT */
            case 0x7a: /* FABD */
                break;
            default:
                lata_unallocated_encoding(s);
                return;
        }

        if (!fp_access_check(s)) {
            return;
        }

        handle_3same_float_scalar(s, extract32(size, 0, 1), fpopcode, rd, rn, rm);
        return;
    }

    switch (opcode) {
        case 0x1: /* SQADD, UQADD */
        case 0x5: /* SQSUB, UQSUB */
        case 0x9: /* SQSHL, UQSHL */
        case 0xb: /* SQRSHL, UQRSHL */
            break;
        case 0x8:  /* SSHL, USHL */
        case 0xa:  /* SRSHL, URSHL */
        case 0x6:  /* CMGT, CMHI */
        case 0x7:  /* CMGE, CMHS */
        case 0x11: /* CMTST, CMEQ */
        case 0x10: /* ADD, SUB (vector) */
            if (size != 3) {
                lata_unallocated_encoding(s);
                return;
            }
            break;
        case 0x16: /* SQDMULH, SQRDMULH (vector) */
            if (size != 1 && size != 2) {
                lata_unallocated_encoding(s);
                return;
            }
            break;
        default:
            lata_unallocated_encoding(s);
            return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    if (size == 3) {
        handle_3same_64(s, opcode, u, rd, rn, rm);
    } else if (opcode == 0x09 || opcode == 0x0b) {
        /* Scalar SQSHL/SQRSHL for size<3: same algorithm, per-element shifts */
        bool rnd = (opcode == 0x0b);
        if (!fp_access_check(s)) return;
        IR2_OPND vd = alloc_fpr_dst(rd);
        IR2_OPND vn = alloc_fpr_src(rn);
        IR2_OPND vm = alloc_fpr_src(rm);
        IR2_OPND t1 = ra_alloc_ftemp(), t2 = ra_alloc_ftemp();
        IR2_OPND t3 = ra_alloc_ftemp(), t4 = ra_alloc_ftemp();
        /* Truncate shift, sign, neg */
        int esize = 8 << size;
        if (size == 1) {
            la_vslli_h(vm, vm, 8);
            la_vsrai_h(vm, vm, 8);
        } else if (size == 2) {
            la_vslli_w(vm, vm, 24);
            la_vsrai_w(vm, vm, 24);
        }
        if (size == 0)
            la_vslti_b(t1, vm, 0);
        else if (size == 1)
            la_vslti_h(t1, vm, 0);
        else
            la_vslti_w(t1, vm, 0);
        if (size == 0)
            la_vneg_b(t2, vm);
        else if (size == 1)
            la_vneg_h(t2, vm);
        else
            la_vneg_w(t2, vm);
        /* CRITICAL: right shift below writes to vd (may alias vn).
           Save vn before the first write. Also needed for left shift later. */
        IR2_OPND vn_scalar_saved = ra_alloc_ftemp();
        la_vori_b(vn_scalar_saved, vn, 0);
        /* Right shift */
        if (rnd && u) {
            /* UQRSHL: unsigned rounding right shift = vsrlr */
            if (size == 0)
                la_vsrlr_b(vd, vn_scalar_saved, t2);
            else if (size == 1)
                la_vsrlr_h(vd, vn_scalar_saved, t2);
            else
                la_vsrlr_w(vd, vn_scalar_saved, t2);
        } else if (rnd) {
            /* SQRSHL: signed rounding right shift = vsrar */
            if (size == 0)
                la_vsrar_b(vd, vn_scalar_saved, t2);
            else if (size == 1)
                la_vsrar_h(vd, vn_scalar_saved, t2);
            else
                la_vsrar_w(vd, vn_scalar_saved, t2);
        } else if (u) {
            if (size == 0)
                la_vsrl_b(vd, vn_scalar_saved, t2);
            else if (size == 1)
                la_vsrl_h(vd, vn_scalar_saved, t2);
            else
                la_vsrl_w(vd, vn_scalar_saved, t2);
        } else {
            if (size == 0)
                la_vsra_b(vd, vn_scalar_saved, t2);
            else if (size == 1)
                la_vsra_h(vd, vn_scalar_saved, t2);
            else
                la_vsra_w(vd, vn_scalar_saved, t2);
        }
        /* Large right shift: shift <= -esize.
           For size>=2, vslti_* immediate is 5-bit signed (-16 to +15),
           and -(esize-1) = -31 or -63 does NOT fit. Use vldi+vslt instead. */
        {
            if (size == 0)
                la_vslti_b(t3, vm, -(esize - 1));
            else if (size == 1)
                la_vslti_h(t3, vm, -(esize - 1));
            else {
                la_vldi(t3, 0x800 | ((-(esize - 1)) & 0x3FF));
                if (size == 2)
                    la_vslt_w(t3, vm, t3);
                else
                    la_vslt_d(t3, vm, t3);
            }
        }
        if (u) {
            la_vxor_v(t2, t2, t2);
            la_vbitsel_v(vd, vd, t2, t3);
            /* UQRSHL: shift == -esize → MSB override */
            if (rnd) {
                if (size == 0)
                    la_vseqi_b(t3, vm, -8);
                else if (size == 1)
                    la_vseqi_h(t3, vm, -16);
                else {
                    la_vldi(t3, 0x800 | ((-esize) & 0x3FF));
                    if (size == 2)
                        la_vseq_w(t3, vm, t3);
                    else
                        la_vseq_d(t3, vm, t3);
                }
                la_vxor_v(t2, t2, t2);
                if (size == 0)
                    la_vsrli_b(t2, vn_scalar_saved, 7);
                else if (size == 1)
                    la_vsrli_h(t2, vn_scalar_saved, 15);
                else if (size == 2)
                    la_vsrli_w(t2, vn_scalar_saved, 31);
                else
                    la_vsrli_d(t2, vn_scalar_saved, 63);
                la_vbitsel_v(vd, vd, t2, t3);
            }
        } else if (rnd) {
            /* SQRSHL: large_right gives 0, not sign_mask. */
            la_vxor_v(t2, t2, t2);
            la_vbitsel_v(vd, vd, t2, t3);
        } else {
            /* SQSHL: large_right gives sign_mask. */
            if (size == 0)
                la_vslti_b(t2, vn_scalar_saved, 0);
            else if (size == 1)
                la_vslti_h(t2, vn_scalar_saved, 0);
            else
                la_vslti_w(t2, vn_scalar_saved, 0);
            la_vbitsel_v(vd, vd, t2, t3);
        }
        /* Save rresult in t2 */
        la_vori_b(t2, vd, 0);
        /* Left shift */
        {
            if (size == 0)
                la_vsll_b(vd, vn_scalar_saved, vm);
            else if (size == 1)
                la_vsll_h(vd, vn_scalar_saved, vm);
            else
                la_vsll_w(vd, vn_scalar_saved, vm);
        }
        /* Overflow: shift >= esize && shift >= 0.
         * la_vslti_*u has 5-bit immediate limit (max 31).
         * For esize>=32, use divide-by-32 + compare approach. */
        if (size == 2) {
            /* esize=32: vslti_wu max imm=31. vslti_bu compares BYTES not words.
               Use vldi(0xC00=32-bit value) + vslt_wu for correct WORD mask. */
            la_vldi(t3, 0x800 | (esize & 0x3FF));
            la_vslt_wu(t3, vm, t3);  /* t3 = (vm < 32) ? -1 : 0 */
            la_vnori_b(t3, t3, 0);   /* vm >= 32 → overflow */
        } else if (size == 0) {
            la_vslti_bu(t3, vm, esize);
            la_vnori_b(t3, t3, 0);
        } else { /* size==1 */
            la_vslti_hu(t3, vm, esize);
            la_vnori_b(t3, t3, 0);
        }
        la_vnori_b(t4, t1, 0);
        la_vand_v(t3, t3, t4); /* shift>=0 */
        /* operand!=0 */
        {
            la_vxor_v(t4, t4, t4);
            if (size == 0)
                la_vseq_b(t4, vn_scalar_saved, t4);
            else if (size == 1)
                la_vseq_h(t4, vn_scalar_saved, t4);
            else
                la_vseq_w(t4, vn_scalar_saved, t4);
            la_vnori_b(t4, t4, 0);
            la_vand_v(t3, t3, t4);
        }
        /* Overflow: (lresult >> shift) != operand.
           For unsigned rounding, use logical shift (vsrl), not arithmetic (vsra). */
        {
            if (rnd) {
                if (u) {
                    if (size == 0)
                        la_vsrl_b(t4, vd, vm);
                    else if (size == 1)
                        la_vsrl_h(t4, vd, vm);
                    else
                        la_vsrl_w(t4, vd, vm);
                } else {
                    if (size == 0)
                        la_vsra_b(t4, vd, vm);
                    else if (size == 1)
                        la_vsra_h(t4, vd, vm);
                    else
                        la_vsra_w(t4, vd, vm);
                }
            } else if (u) {
                if (size == 0)
                    la_vsrl_b(t4, vd, vm);
                else if (size == 1)
                    la_vsrl_h(t4, vd, vm);
                else
                    la_vsrl_w(t4, vd, vm);
            } else {
                if (size == 0)
                    la_vsra_b(t4, vd, vm);
                else if (size == 1)
                    la_vsra_h(t4, vd, vm);
                else
                    la_vsra_w(t4, vd, vm);
            }
            if (size == 0)
                la_vseq_b(t4, t4, vn_scalar_saved);
            else if (size == 1)
                la_vseq_h(t4, t4, vn_scalar_saved);
            else
                la_vseq_w(t4, t4, vn_scalar_saved);
            la_vnor_v(t4, t4, t4);
            la_vor_v(t3, t4, t3);
        }
        /* Saturation. t4 no longer needed, free it to make room.
           FTEMP pool has only 6 slots (v9-v14). Peak live ftemps reaches 7
           (t1+t2+t3+vn_scalar_saved+sat_mn+sat_mx+sat_sg) if we allocate all
           sat temps at once. Compute sign_mask early, free vn_scalar_saved
           before allocating sat_mn/sat_mx to keep peak at 6. */
        free_alloc_fpr(t4);
        if (u) {
            free_alloc_fpr(vn_scalar_saved);
            IR2_OPND umax = ra_alloc_ftemp(); /* 4 */
            la_vxor_v(umax, umax, umax);
            la_vnori_b(umax, umax, 0); /* all-ones = UINT_MAX */
            la_vbitsel_v(vd, vd, umax, t3);
            free_alloc_fpr(umax);
        } else {
            /* Compute sign_mask NOW before freeing vn_scalar_saved.
               This keeps peak ftemp usage at 6 instead of 7. */
            IR2_OPND sat_sg = ra_alloc_ftemp(); /* 4: sign_mask */
            if (size == 0)
                la_vslti_b(sat_sg, vn_scalar_saved, 0);
            else if (size == 1)
                la_vslti_h(sat_sg, vn_scalar_saved, 0);
            else
                la_vslti_w(sat_sg, vn_scalar_saved, 0);
            free_alloc_fpr(vn_scalar_saved); /* no longer needed */

            IR2_OPND sat_mn = ra_alloc_ftemp(); /* 4 (reuses freed slot) */
            IR2_OPND sat_mx = ra_alloc_ftemp(); /* 5 */
            IR2_OPND igpr = ra_alloc_itemp();
            if (size == 0) {
                li_d(igpr, 0x8080808080808080LL);
                la_vreplgr2vr_b(sat_mn, igpr);
            } else if (size == 1) {
                li_d(igpr, 0x8000800080008000LL);
                la_vreplgr2vr_h(sat_mn, igpr);
            } else {
                li_d(igpr, 0x8000000080000000LL);
                la_vreplgr2vr_w(sat_mn, igpr);
            }
            free_alloc_gpr(igpr);
            la_vnori_b(sat_mx, sat_mn, 0); /* INT_MAX = ~INT_MIN */
            /* vbitsel: sat_sg ? INT_MIN(sat_mn) : INT_MAX(sat_mx) */
            la_vbitsel_v(sat_mx, sat_mx, sat_mn, sat_sg);
            free_alloc_fpr(sat_mn);
            free_alloc_fpr(sat_sg);
            /* Apply to lresult where overflow mask (t3) is set */
            la_vbitsel_v(vd, vd, sat_mx, t3);
            free_alloc_fpr(sat_mx);
        }
        /* Final select: t1(shift_sign) ? t2(rresult) : vd(lresult) */
        la_vbitsel_v(vd, vd, t2, t1);
        la_vinsgr2vr_d(vd, zero_ir2_opnd, 1);
        store_fpr_dst(rd, vd);
        free_alloc_fpr(vd);
        free_alloc_fpr(vn);
        free_alloc_fpr(vm);
        free_alloc_fpr(t1);
        free_alloc_fpr(t2);
        free_alloc_fpr(t3); /* t4 + vn_scalar_saved freed earlier */
        return;
    } else if (opcode == 0x16) {
        /* SQDMULH (u=0) / SQRDMULH (u=1) scalar */
        IR2_OPND vd = alloc_fpr_dst(rd);
        IR2_OPND vn = alloc_fpr_src(rn);
        IR2_OPND vm = alloc_fpr_src(rm);
        IR2_OPND vtemp = ra_alloc_ftemp();
        IR2_OPND vtemp1 = ra_alloc_ftemp();
        IR2_OPND vzero = ra_alloc_ftemp();

        la_vxor_v(vzero, vzero, vzero);

        if (u) {
            /* SQRDMULH: rounding narrow */
            switch (size) {
                case 1:
                    la_vilvl_h(vtemp, vzero, vn);
                    la_vilvl_h(vtemp1, vzero, vm);
                    la_vmulwev_w_h(vd, vtemp, vtemp1);
                    la_vsadd_w(vd, vd, vd);
                    la_vssrarni_h_w(vd, vd, 16);
                    break;
                case 2:
                    la_vilvl_w(vtemp, vzero, vn);
                    la_vilvl_w(vtemp1, vzero, vm);
                    la_vmulwev_d_w(vd, vtemp, vtemp1);
                    la_vsadd_d(vd, vd, vd);
                    la_vssrarni_w_d(vd, vd, 32);
                    break;
                default:
                    assert(0);
            }
        } else {
            /* SQDMULH: truncating narrow */
            switch (size) {
                case 1:
                    la_vilvl_h(vtemp, vzero, vn);
                    la_vilvl_h(vtemp1, vzero, vm);
                    la_vmulwev_w_h(vd, vtemp, vtemp1);
                    la_vsadd_w(vd, vd, vd);
                    la_vssrani_h_w(vd, vd, 16);
                    break;
                case 2:
                    la_vilvl_w(vtemp, vzero, vn);
                    la_vilvl_w(vtemp1, vzero, vm);
                    la_vmulwev_d_w(vd, vtemp, vtemp1);
                    la_vsadd_d(vd, vd, vd);
                    la_vssrani_w_d(vd, vd, 32);
                    break;
                default:
                    assert(0);
            }
        }
        la_vinsgr2vr_d(vd, zero_ir2_opnd, 1);
        store_fpr_dst(rd, vd);
        free_alloc_fpr(vd);
        free_alloc_fpr(vn);
        free_alloc_fpr(vm);
        free_alloc_fpr(vtemp);
        free_alloc_fpr(vtemp1);
        free_alloc_fpr(vzero);
        return;
    } else if (opcode == 0x1 || opcode == 0x5 || opcode == 0x6 || opcode == 0x7
        || opcode == 0x8 || opcode == 0xa || opcode == 0x10 || opcode == 0x11) {
        /* Scalar integer ops: SQADD/SQSUB/CMGT/CMGE/SSHL/SRSHL/ADD/CMTST
         * LSX provides saturating and regular vector ops; scalar uses element 0. */
        IR2_OPND vd = alloc_fpr_dst(rd);
        IR2_OPND vn = alloc_fpr_src(rn);
        IR2_OPND vm = alloc_fpr_src(rm);
        switch (opcode) {
            case 0x1: /* SQADD/UQADD */
                if (u) {
                    if (size == 0)
                        la_vsadd_bu(vd, vn, vm);
                    else if (size == 1)
                        la_vsadd_hu(vd, vn, vm);
                    else
                        la_vsadd_wu(vd, vn, vm);
                } else {
                    if (size == 0)
                        la_vsadd_b(vd, vn, vm);
                    else if (size == 1)
                        la_vsadd_h(vd, vn, vm);
                    else
                        la_vsadd_w(vd, vn, vm);
                }
                break;
            case 0x5: /* SQSUB/UQSUB */
                if (u) {
                    if (size == 0)
                        la_vssub_bu(vd, vn, vm);
                    else if (size == 1)
                        la_vssub_hu(vd, vn, vm);
                    else
                        la_vssub_wu(vd, vn, vm);
                } else {
                    if (size == 0)
                        la_vssub_b(vd, vn, vm);
                    else if (size == 1)
                        la_vssub_h(vd, vn, vm);
                    else
                        la_vssub_w(vd, vn, vm);
                }
                break;
            case 0x6: /* CMGT/CMHI */
                if (u) {
                    if (size == 0)
                        la_vslt_bu(vd, vm, vn);
                    else if (size == 1)
                        la_vslt_hu(vd, vm, vn);
                    else
                        la_vslt_wu(vd, vm, vn);
                } else {
                    if (size == 0)
                        la_vslt_b(vd, vm, vn);
                    else if (size == 1)
                        la_vslt_h(vd, vm, vn);
                    else
                        la_vslt_w(vd, vm, vn);
                }
                break;
            case 0x7: /* CMGE/CMHS */
                if (u) {
                    if (size == 0)
                        la_vsle_bu(vd, vm, vn);
                    else if (size == 1)
                        la_vsle_hu(vd, vm, vn);
                    else
                        la_vsle_wu(vd, vm, vn);
                } else {
                    if (size == 0)
                        la_vsle_b(vd, vm, vn);
                    else if (size == 1)
                        la_vsle_h(vd, vm, vn);
                    else
                        la_vsle_w(vd, vm, vn);
                }
                break;
            case 0x8: /* SSHL/USHL */
                if (u) {
                    if (size == 0)
                        la_vsll_b(vd, vn, vm);
                    else if (size == 1)
                        la_vsll_h(vd, vn, vm);
                    else
                        la_vsll_w(vd, vn, vm);
                } else {
                    if (size == 0)
                        la_vsll_b(vd, vn, vm);
                    else if (size == 1)
                        la_vsll_h(vd, vn, vm);
                    else
                        la_vsll_w(vd, vn, vm);
                }
                break;
            case 0xa: /* SRSHL/URSHL */
                if (u) {
                    if (size == 0)
                        la_vsrlr_b(vd, vn, vm);
                    else if (size == 1)
                        la_vsrlr_h(vd, vn, vm);
                    else
                        la_vsrlr_w(vd, vn, vm);
                } else {
                    if (size == 0)
                        la_vsrar_b(vd, vn, vm);
                    else if (size == 1)
                        la_vsrar_h(vd, vn, vm);
                    else
                        la_vsrar_w(vd, vn, vm);
                }
                break;
            case 0x10: /* ADD/SUB */
                if (u) {
                    if (size == 0)
                        la_vsub_b(vd, vn, vm);
                    else if (size == 1)
                        la_vsub_h(vd, vn, vm);
                    else
                        la_vsub_w(vd, vn, vm);
                } else {
                    if (size == 0)
                        la_vadd_b(vd, vn, vm);
                    else if (size == 1)
                        la_vadd_h(vd, vn, vm);
                    else
                        la_vadd_w(vd, vn, vm);
                }
                break;
            case 0x11: /* CMTST/CMEQ */
                if (u) {
                    if (size == 0)
                        la_vseq_b(vd, vn, vm);
                    else if (size == 1)
                        la_vseq_h(vd, vn, vm);
                    else
                        la_vseq_w(vd, vn, vm);
                } else {
                    IR2_OPND vt = ra_alloc_ftemp();
                    if (size == 0)
                        la_vand_v(vt, vn, vm);
                    else if (size == 1)
                        la_vand_v(vt, vn, vm);
                    else
                        la_vand_v(vt, vn, vm);
                    IR2_OPND zero = ra_alloc_ftemp();
                    la_vxor_v(zero, zero, zero);
                    if (size == 0)
                        la_vseq_b(vd, vt, zero);
                    else if (size == 1)
                        la_vseq_h(vd, vt, zero);
                    else
                        la_vseq_w(vd, vt, zero);
                    la_vnor_v(vd, vd, vd); /* invert: non-zero if bits overlap */
                    free_alloc_fpr(zero);
                    free_alloc_fpr(vt);
                }
                break;
        }
        la_vinsgr2vr_d(vd, zero_ir2_opnd, 1);
        store_fpr_dst(rd, vd);
        free_alloc_fpr(vd);
        free_alloc_fpr(vn);
        free_alloc_fpr(vm);
        return;
    } else {
        lata_unallocated_encoding(s);
        return;
    }
}

/* AdvSIMD scalar three same FP16
 *  31 30  29 28       24 23  22 21 20  16 15 14 13    11 10  9  5 4  0
 * +-----+---+-----------+---+-----+------+-----+--------+---+----+----+
 * | 0 1 | U | 1 1 1 1 0 | a | 1 0 |  Rm  | 0 0 | opcode | 1 | Rn | Rd |
 * +-----+---+-----------+---+-----+------+-----+--------+---+----+----+
 * v: 0101 1110 0100 0000 0000 0100 0000 0000 => 5e400400
 * m: 1101 1111 0110 0000 1100 0100 0000 0000 => df60c400
 */
static void disas_simd_scalar_three_reg_same_fp16(DisasContext* s,
    uint32_t insn) { lata_unallocated_encoding(s); }

/* AdvSIMD scalar three same extra
 *  31 30  29 28       24 23  22  21 20  16  15 14    11  10 9  5 4  0
 * +-----+---+-----------+------+---+------+---+--------+---+----+----+
 * | 0 1 | U | 1 1 1 1 0 | size | 0 |  Rm  | 1 | opcode | 1 | Rn | Rd |
 * +-----+---+-----------+------+---+------+---+--------+---+----+----+
 */
static void disas_simd_scalar_three_reg_same_extra(DisasContext* s,
    uint32_t insn)
{
    int u = extract32(insn, 29, 1);
    int opcode = extract32(insn, 12, 5);
    int rm = extract32(insn, 16, 5);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);
    /* opcode is in bits 12-16 with a fixed '1' at bit 10 in the encoding */
    if (!fp_access_check(s)) return;
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    switch (opcode) {
        case 0x08: /* SRSHL, URSHL — rounding shift */
        case 0x09: /* SQSHL, UQSHL — saturating shift */
        case 0x0B: /* SQRSHL, UQRSHL — saturating rounding shift */
        {
            bool is_rounding = (opcode != 0x09);
            IR2_OPND negsh = ra_alloc_ftemp();
            IR2_OPND rres = ra_alloc_ftemp();
            IR2_OPND lres = ra_alloc_ftemp();
            IR2_OPND ovfl = ra_alloc_ftemp();
            IR2_OPND sgn = ra_alloc_ftemp(); /* shift_sign */
            la_vslli_d(vreg_m, vreg_m, 56);
            la_vsrai_d(vreg_m, vreg_m, 56);
            la_vslti_d(sgn, vreg_m, 0); /* shift_sign */
            la_vneg_d(negsh, vreg_m);   /* neg_shift = -shift */
            if (is_rounding)
                la_vsrar_d(rres, vreg_n, negsh);
            else if (u)
                la_vsrl_d(rres, vreg_n, negsh);
            else
                la_vsra_d(rres, vreg_n, negsh);
            {
                /* shift <= -64 equivalent to neg_shift >= 64.
                   vslti_d cannot encode -63. Use negsh (already = -vm). */
                IR2_OPND vt64 = ra_alloc_ftemp();
                la_vldi(vt64, 0xC00 | 64);
                la_vslt_du(ovfl, negsh, vt64); /* negsh < 64 */
                la_vnori_b(ovfl, ovfl, 0);     /* NOT: negsh >= 64 */
                free_alloc_fpr(vt64);
            }
            if (u) {
                IR2_OPND z = ra_alloc_ftemp();
                la_vxor_v(z, z, z);
                la_vbitsel_v(rres, rres, z, ovfl);
                free_alloc_fpr(z);
            } else {
                IR2_OPND ts = ra_alloc_ftemp();
                la_vslti_d(ts, vreg_n, 0);
                la_vbitsel_v(rres, rres, ts, ovfl);
                free_alloc_fpr(ts);
            }
            /* Left shift */
            la_vsll_d(lres, vreg_n, vreg_m);
            /* Large left shift mask */
            la_vslti_du(ovfl, vreg_m, 64);
            la_vnori_b(ovfl, ovfl, 0);
            la_vnori_b(negsh, sgn, 0); /* negsh = (shift >= 0) */
            la_vand_v(ovfl, ovfl, negsh);
            free_alloc_fpr(negsh);
            /* operand != 0 */
            {
                IR2_OPND z = ra_alloc_ftemp();
                la_vxor_v(z, z, z);
                la_vseq_d(z, vreg_n, z);
                la_vnori_b(z, z, 0);
                la_vand_v(ovfl, ovfl, z);
                /* Overflow: (lres >> shift) != operand.
                   For unsigned rounding, use logical (vsrl), not arithmetic (vsra). */
                if (is_rounding && u)
                    la_vsrl_d(z, lres, vreg_m);
                else if (is_rounding)
                    la_vsra_d(z, lres, vreg_m);
                else if (u)
                    la_vsrl_d(z, lres, vreg_m);
                else
                    la_vsra_d(z, lres, vreg_m);
                la_vseq_d(z, z, vreg_n);
                la_vnor_v(z, z, z);
                la_vor_v(ovfl, z, ovfl);
                free_alloc_fpr(z);
            }
            /* Saturation: save rres to vreg_d, free rres for sat regs */
            la_vori_b(vreg_d, rres, 0);
            free_alloc_fpr(rres);
            if (u) {
                IR2_OPND umax = ra_alloc_ftemp();
                la_vxor_v(umax, umax, umax);
                la_vnori_b(umax, umax, 0);
                la_vbitsel_v(lres, lres, umax, ovfl);
                free_alloc_fpr(umax);
            } else {
                IR2_OPND vmin = ra_alloc_ftemp();
                IR2_OPND vmax = ra_alloc_ftemp();
                IR2_OPND vsgn = ra_alloc_ftemp();
                IR2_OPND igpr = ra_alloc_itemp();
                li_d(igpr, 0x8000000000000000LL);
                la_vreplgr2vr_d(vmin, igpr);
                free_alloc_gpr(igpr);
                la_vnori_b(vmax, vmin, 0);
                la_vslti_d(vsgn, vreg_n, 0);
                la_vbitsel_v(vmax, vmax, vmin, vsgn);
                la_vbitsel_v(lres, lres, vmax, ovfl);
                free_alloc_fpr(vmin);
                free_alloc_fpr(vmax);
                free_alloc_fpr(vsgn);
            }
            /* Final select: sgn ? lres : vreg_d(rres) */
            la_vbitsel_v(vreg_d, lres, vreg_d, sgn);
            free_alloc_fpr(lres);
            free_alloc_fpr(ovfl);
            free_alloc_fpr(sgn);
            break;
        }
        default:
            lata_unallocated_encoding(s);
            break;
    }
    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
}

static void handle_2misc_64(DisasContext* s, int opcode, bool u,
    IR2_OPND* vreg_d, IR2_OPND* vreg_n)
{
    IR2_OPND vtemp = ra_alloc_ftemp();

    switch (opcode) {
        case 0x4: /* CLS, CLZ */
            if (u) {
                la_vclz_d(*vreg_d, *vreg_n);
            } else {
                /* CLS: count leading sign bits = leading_sign_bits - 1 */
                IR2_OPND vclo_v = ra_alloc_ftemp();
                IR2_OPND vclz_v = ra_alloc_ftemp();
                IR2_OPND vsgn_v = ra_alloc_ftemp();
                IR2_OPND vone_v = ra_alloc_ftemp();
                la_vclo_d(vclo_v, *vreg_n);
                la_vclz_d(vclz_v, *vreg_n);
                la_vslti_d(vsgn_v, *vreg_n, 0);
                la_vbitsel_v(*vreg_d, vclz_v, vclo_v, vsgn_v);
                la_vxor_v(vone_v, vone_v, vone_v);   /* all zeros */
                la_vnori_b(vone_v, vone_v, 0);        /* all ones = -1 */
                la_vadd_d(*vreg_d, *vreg_d, vone_v); /* subtract 1 */
                free_alloc_fpr(vclo_v);
                free_alloc_fpr(vclz_v);
                free_alloc_fpr(vsgn_v);
                free_alloc_fpr(vone_v);
            }
            break;
        case 0x5: /* NOT */
            break;
        case 0x7: /* SQABS, SQNEG */
        {
            IR2_OPND zero = ra_alloc_ftemp();
            la_vxor_v(zero, zero, zero);
            if (u) {
                /* SQNEG: vd = vssub(0, vn) */
                la_vssub_d(*vreg_d, zero, *vreg_n);
            } else {
                /* SQABS: vd = vmax(vn, vssub(0, vn)) */
                IR2_OPND vneg = ra_alloc_ftemp();
                la_vssub_d(vneg, zero, *vreg_n);
                la_vmax_d(*vreg_d, *vreg_n, vneg);
                free_alloc_fpr(vneg);
            }
            free_alloc_fpr(zero);
        }
        break;
        case 0xa: /* CMLT */
        do_cmop:
            break;
        case 0x8: /* CMGT, CMGE */
            goto do_cmop;
        case 0x9: /* CMEQ, CMLE */
            goto do_cmop;
        case 0xb: /* ABS, NEG */
            if (u) {
                la_vneg_d(*vreg_d, *vreg_n);
            } else {
                IR2_OPND vzero_abs = ra_alloc_ftemp();
                la_vandi_b(vzero_abs, vzero_abs, 0);
                la_vabsd_d(*vreg_d, *vreg_n, vzero_abs);
                free_alloc_fpr(vzero_abs);
            }
            break;
        case 0x2f: /* FABS */
            la_vreplvei_d(vtemp, *vreg_n, 1);
            la_fabs_d(*vreg_d, *vreg_n);
            la_fabs_d(vtemp, vtemp);
            la_vextrins_d(*vreg_d, vtemp, 1 << 4);
            break;
        case 0x6f: /* FNEG */
            la_vreplvei_d(vtemp, *vreg_n, 1);
            la_fneg_d(*vreg_d, *vreg_n);
            la_fneg_d(vtemp, vtemp);
            la_vextrins_d(*vreg_d, vtemp, 1 << 4);
            break;
        case 0x7f: /* FSQRT */
            la_vfsqrt_d(*vreg_d, *vreg_n);
            break;
        case 0x1a:
        case 0x3a: /* FCVTNS (raw/transformed) */
            la_vftintrne_l_d(*vreg_d, *vreg_n);
            break;
        case 0x1b: /* FCVTMS */
            la_vftintrm_l_d(*vreg_d, *vreg_n);
            break;
        case 0x3b: /* FCVTZS */
            la_vftintrz_l_d(*vreg_d, *vreg_n);
            break;
        case 0x1c: /* FCVTAS: ties away from zero = sign*floor(|x|+0.5) */
        {
            IR2_OPND src = ra_alloc_ftemp();
            IR2_OPND abs_x = ra_alloc_ftemp();
            IR2_OPND half_v = ra_alloc_ftemp();
            IR2_OPND neg_res = ra_alloc_ftemp();
            IR2_OPND sign_mask = ra_alloc_ftemp();
            IR2_OPND zero = ra_alloc_ftemp();
            IR2_OPND itemp_tmp = ra_alloc_itemp();

            la_vori_b(src, *vreg_n, 0);
            li_d(itemp_tmp, 0x7fffffffffffffffULL);
            la_vreplgr2vr_d(abs_x, itemp_tmp);
            la_vand_v(abs_x, abs_x, src);
            li_d(itemp_tmp, 0x3fe0000000000000ULL); /* 0.5 in f64 */
            la_vreplgr2vr_d(half_v, itemp_tmp);
            la_vfadd_d(half_v, abs_x, half_v);
            la_vftintrm_l_d(*vreg_d, half_v);

            la_vxor_v(zero, zero, zero);
            la_vsub_d(neg_res, zero, *vreg_d);
            la_vsrai_d(sign_mask, src, 63);
            la_vbitsel_v(*vreg_d, *vreg_d, neg_res, sign_mask);

            free_alloc_fpr(src);
            free_alloc_fpr(abs_x);
            free_alloc_fpr(half_v);
            free_alloc_fpr(neg_res);
            free_alloc_fpr(sign_mask);
            free_alloc_fpr(zero);
            free_alloc_gpr(itemp_tmp);
        } break;
        case 0x1d:
        case 0x3d: /* FCVTPS (raw/transformed) */
            la_vftintrp_l_d(*vreg_d, *vreg_n);
            break;
        case 0x3f: /* FCVTZS (legacy transformed form) */
            la_vftintrz_l_d(*vreg_d, *vreg_n);
            break;
        case 0x7b: /* FCVTZU */
            la_vftintrz_lu_d(*vreg_d, *vreg_n);
            break;
        case 0x5a:
        case 0x7a: /* FCVTNU */
        case 0x5b:
        case 0x5d:
        case 0x7d: /* FCVTPU */
            /* unsigned non-trunc: use signed conversion + clamp to 0 */
            {
                IR2_OPND zero = ra_alloc_ftemp();
                la_vxor_v(zero, zero, zero);
                if ((opcode & 0x1f) == 0x1a)
                    la_vftintrne_l_d(*vreg_d, *vreg_n);
                else if ((opcode & 0x1f) == 0x1b)
                    la_vftintrm_l_d(*vreg_d, *vreg_n);
                else
                    la_vftintrp_l_d(*vreg_d, *vreg_n); /* 0x1d → FCVTPU */
                la_vmax_du(*vreg_d, *vreg_d, zero);
                free_alloc_fpr(zero);
            }
            break;
        case 0x5c: /* FCVTAU: unsigned ties away, clamp negative/NaN to zero */
        {
            IR2_OPND src = ra_alloc_ftemp();
            IR2_OPND vhalf = ra_alloc_ftemp();
            IR2_OPND zero = ra_alloc_ftemp();
            IR2_OPND nonneg = ra_alloc_ftemp();
            IR2_OPND itemp_tmp = ra_alloc_itemp();

            la_vori_b(src, *vreg_n, 0);
            la_vxor_v(zero, zero, zero);
            li_d(itemp_tmp, 0x3fe0000000000000ULL);
            la_vreplgr2vr_d(vhalf, itemp_tmp);
            la_vfadd_d(vhalf, src, vhalf);
            la_vftintrm_l_d(*vreg_d, vhalf);
            la_vfcmp_cond_d(nonneg, zero, src, FCMP_COND_CLE);
            la_vbitsel_v(*vreg_d, zero, *vreg_d, nonneg);
            free_alloc_fpr(src);
            free_alloc_fpr(vhalf);
            free_alloc_fpr(zero);
            free_alloc_fpr(nonneg);
            free_alloc_gpr(itemp_tmp);
        } break;
        /* FCVTZU at 0x5f/0x7f: handled by FSQRT case (value error, TBD) */
        case 0x18: /* FRINTN */
            la_vfrintrne_d(*vreg_d, *vreg_n);
            break;
        case 0x19: /* FRINTM */
            la_vfrintrm_d(*vreg_d, *vreg_n);
            break;
        case 0x38: /* FRINTP */
            la_vfrintrp_d(*vreg_d, *vreg_n);
            break;
        case 0x39: /* FRINTZ */
            la_vfrintrz_d(*vreg_d, *vreg_n);
            break;
        case 0x58: /* FRINTA: ties away from zero */
        {
            /* FRINTA(x) = sign(x) * floor(|x| + 0.5) via integer bit ops */
            IR2_OPND sign_bits = ra_alloc_ftemp();
            IR2_OPND vhalf = ra_alloc_ftemp();

            /* sign_bits = Vn & 0x8000000000000000 */
            IR2_OPND itemp_tmp = ra_alloc_itemp();
            la_addi_d(itemp_tmp, zero_ir2_opnd, 1);
            la_slli_d(itemp_tmp, itemp_tmp, 63);
            la_vreplgr2vr_d(sign_bits, itemp_tmp);
            la_vand_v(sign_bits, sign_bits, *vreg_n);

            /* abs_val = Vn & 0x7FFFFFFFFFFFFFFF (clear sign bit), reuse vtemp */
            la_vreplgr2vr_d(vtemp, itemp_tmp);
            la_vandn_v(vtemp, vtemp, *vreg_n);

            /* Load 0.5 constant for f64 = 0x3FE0000000000000 */
            li_d(itemp_tmp, 0x3FE0000000000000ULL);
            la_vreplgr2vr_d(vhalf, itemp_tmp);
            free_alloc_gpr(itemp_tmp);

            /* vreg_d = floor(|Vn| + 0.5) */
            la_vfadd_d(*vreg_d, vtemp, vhalf);
            la_vfrintrm_d(*vreg_d, *vreg_d);

            /* Apply sign bits */
            la_vor_v(*vreg_d, *vreg_d, sign_bits);

            free_alloc_fpr(sign_bits);
            free_alloc_fpr(vhalf);
            break;
        }
        case 0x79: /* FRINTI */
            la_vfrint_d(*vreg_d, *vreg_n);
            break;
        case 0x59: /* FRINTX */
            la_vfrint_d(*vreg_d, *vreg_n);
            break;
        case 0x1e: /* FRINT32Z */
        case 0x5e: /* FRINT32X */
            break;
        case 0x1f: /* FRINT64Z */
        case 0x5f: /* FRINT64X */
            break;
        default:
            g_assert_not_reached();
    }

    free_alloc_fpr(vtemp);
}

static void handle_2misc_fcmp_zero(DisasContext* s, int opcode,
    bool is_scalar, bool is_u, bool is_q,
    int size, int rn, int rd)
{
    bool is_double = (size == MO_64);

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();
    la_vxor_v(vtemp, vtemp, vtemp);
    if (is_double) {

        switch (opcode) {
            case 0x2e: /* FCMLT (zero) */
                la_vfcmp_cond_d(vreg_d, vreg_n, vtemp, FCMP_COND_SLT);
                break;
            case 0x2c: /* FCMGT (zero) */
                la_vfcmp_cond_d(vreg_d, vtemp, vreg_n, FCMP_COND_SLT);
                break;
            case 0x2d: /* FCMEQ (zero) */
                la_vfcmp_cond_d(vreg_d, vreg_n, vtemp, FCMP_COND_SEQ);
                break;
            case 0x6d: /* FCMLE (zero) */
                la_vfcmp_cond_d(vreg_d, vreg_n, vtemp, FCMP_COND_SLE);
                break;
            case 0x6c: /* FCMGE (zero) */
                la_vfcmp_cond_d(vreg_d, vtemp, vreg_n, FCMP_COND_SLE);
                break;
            default:
                g_assert_not_reached();
        }
    } else {

        if (size == MO_16) {
            lata_unallocated_encoding(s);
            return;
            switch (opcode) {
                case 0x2e: /* FCMLT (zero) */
                    break;
                case 0x2c: /* FCMGT (zero) */
                    break;
                case 0x2d: /* FCMEQ (zero) */
                    break;
                case 0x6d: /* FCMLE (zero) */
                    break;
                case 0x6c: /* FCMGE (zero) */
                    break;
                default:
                    g_assert_not_reached();
            }
        } else {
            switch (opcode) {
                case 0x2e: /* FCMLT (zero) */
                    la_vfcmp_cond_s(vreg_d, vreg_n, vtemp, FCMP_COND_SLT);
                    break;
                case 0x2c: /* FCMGT (zero) */
                    la_vfcmp_cond_s(vreg_d, vtemp, vreg_n, FCMP_COND_SLT);
                    break;
                case 0x2d: /* FCMEQ (zero) */
                    la_vfcmp_cond_s(vreg_d, vreg_n, vtemp, FCMP_COND_SEQ);
                    break;
                case 0x6d: /* FCMLE (zero) */
                    la_vfcmp_cond_s(vreg_d, vreg_n, vtemp, FCMP_COND_SLE);
                    break;
                case 0x6c: /* FCMGE (zero) */
                    la_vfcmp_cond_s(vreg_d, vtemp, vreg_n, FCMP_COND_SLE);
                    break;
                default:
                    g_assert_not_reached();
            }
        }
    }
    /* 高64位清零 */
    if (!is_q) {
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }

    if (is_scalar) {
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
        if (!is_double) {
            la_vinsgr2vr_w(vreg_d, zero_ir2_opnd, 1);
            if (size == MO_16) {
                la_vinsgr2vr_h(vreg_d, zero_ir2_opnd, 1);
            }
        }
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
}

static void gen_urecpe_u32_estimate(IR2_OPND out, IR2_OPND src,
    IR2_OPND tmp1, IR2_OPND tmp2)
{
    IR2_OPND saturate = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND done = ir2_opnd_new_type(IR2_OPND_LABEL);

    la_srli_w(tmp1, src, 31);
    la_beqz(tmp1, saturate);

    la_srli_w(tmp1, src, 23);
    la_andi(tmp1, tmp1, 0x1ff);
    la_slli_w(tmp2, tmp1, 1);
    la_ori(tmp2, tmp2, 1);

    li_wu(tmp1, 1u << 19);
    la_div_wu(tmp1, tmp1, tmp2);
    la_addi_w(tmp1, tmp1, 1);
    la_srli_w(out, tmp1, 1);
    la_slli_w(out, out, 23);
    la_b(done);

    la_label(saturate);
    li_wu(out, UINT32_MAX);

    la_label(done);
}

static void gen_ursqrte_u32_estimate(IR2_OPND out, IR2_OPND src,
    IR2_OPND a, IR2_OPND b, IR2_OPND tmp, IR2_OPND limit)
{
    IR2_OPND saturate = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND input_ge_256 = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND setup_loop = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND search_loop = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND loop_done = ir2_opnd_new_type(IR2_OPND_LABEL);
    IR2_OPND done = ir2_opnd_new_type(IR2_OPND_LABEL);

    la_srli_w(tmp, src, 30);
    la_beqz(tmp, saturate);

    la_srli_w(a, src, 23);
    la_andi(a, a, 0x1ff);
    li_wu(tmp, 256);
    la_bgeu(a, tmp, input_ge_256);
    la_slli_w(a, a, 1);
    la_ori(a, a, 1);
    la_b(setup_loop);

    la_label(input_ge_256);
    la_srli_w(a, a, 1);
    la_slli_w(a, a, 1);
    la_addi_w(a, a, 1);
    la_slli_w(a, a, 1);

    la_label(setup_loop);
    li_wu(b, 512);
    li_wu(limit, 1u << 28);

    la_label(search_loop);
    la_addi_w(tmp, b, 1);
    la_mul_d(tmp, tmp, tmp);
    la_mul_d(tmp, tmp, a);
    la_bgeu(tmp, limit, loop_done);
    la_addi_w(b, b, 1);
    la_b(search_loop);

    la_label(loop_done);
    la_addi_w(out, b, 1);
    la_srli_w(out, out, 1);
    la_slli_w(out, out, 23);
    la_b(done);

    la_label(saturate);
    li_wu(out, UINT32_MAX);

    la_label(done);
}

static void handle_2misc_reciprocal(DisasContext* s, int opcode,
    bool is_scalar, bool is_u, bool is_q,
    int size, int rn, int rd)
{
    /* Reciprocal estimate: URECPE (unsigned int), FRECPE (float), FRSQRTE (float sqrt) */
    if (opcode == 0x3c && !is_u) {
        IR2_OPND vreg_n = alloc_fpr_src(rn);
        IR2_OPND vreg_d;
        IR2_OPND val = ra_alloc_itemp();
        IR2_OPND tmp1 = ra_alloc_itemp();
        IR2_OPND tmp2 = ra_alloc_itemp();

        la_addi_d(sp_ir2_opnd, sp_ir2_opnd, -16);
        vector_store(vreg_n, sp_ir2_opnd, 0, t0_ir2_opnd);
        vreg_d = alloc_fpr_dst(rd);

        for (int i = 0; i < (is_q ? 4 : 2); i++) {
            la_ld_wu(val, sp_ir2_opnd, i * 4);
            gen_urecpe_u32_estimate(val, val, tmp1, tmp2);
            la_vinsgr2vr_w(vreg_d, val, i);
        }
        if (!is_q) {
            la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
        }
        la_addi_d(sp_ir2_opnd, sp_ir2_opnd, 16);
        store_fpr_dst(rd, vreg_d);
        free_alloc_fpr(vreg_d);
        free_alloc_fpr(vreg_n);
        free_alloc_gpr(val);
        free_alloc_gpr(tmp1);
        free_alloc_gpr(tmp2);
        return;
    }
    if (opcode == 0x7c && is_u) {
        IR2_OPND vreg_n = alloc_fpr_src(rn);
        IR2_OPND vreg_d;
        IR2_OPND val = ra_alloc_itemp();
        IR2_OPND a = ra_alloc_itemp();
        IR2_OPND b = ra_alloc_itemp();
        IR2_OPND tmp = ra_alloc_itemp();
        IR2_OPND limit = ra_alloc_itemp();

        la_addi_d(sp_ir2_opnd, sp_ir2_opnd, -16);
        vector_store(vreg_n, sp_ir2_opnd, 0, t0_ir2_opnd);
        vreg_d = alloc_fpr_dst(rd);

        for (int i = 0; i < (is_q ? 4 : 2); i++) {
            la_ld_wu(val, sp_ir2_opnd, i * 4);
            gen_ursqrte_u32_estimate(val, val, a, b, tmp, limit);
            la_vinsgr2vr_w(vreg_d, val, i);
        }
        if (!is_q) {
            la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
        }
        la_addi_d(sp_ir2_opnd, sp_ir2_opnd, 16);
        store_fpr_dst(rd, vreg_d);
        free_alloc_fpr(vreg_d);
        free_alloc_fpr(vreg_n);
        free_alloc_gpr(val);
        free_alloc_gpr(a);
        free_alloc_gpr(b);
        free_alloc_gpr(tmp);
        free_alloc_gpr(limit);
        return;
    }
    /* FRECPE (opcode 0x1d) and FRSQRTE (opcode 0x7d) */
    {
        IR2_OPND vreg_d = alloc_fpr_dst(rd);
        IR2_OPND vreg_n = alloc_fpr_src(rn);
        if (opcode == 0x1d || opcode == 0x3d) { /* FRECPE */
            if (size == 3)
                la_vfrecip_d(vreg_d, vreg_n);
            else
                la_vfrecip_s(vreg_d, vreg_n);
        } else if (opcode == 0x3f) { /* FRECPX: new_exp = max_exp - old_exp, preserve sign */
            IR2_OPND tg = ra_alloc_itemp(), tg2 = ra_alloc_itemp();
            IR2_OPND tsign = ra_alloc_itemp();
            IR2_OPND vresult = ra_alloc_ftemp();
            if (size == 3) {
                la_movfr2gr_d(tg, vreg_n);
                /* Preserve sign bit */
                la_bstrpick_d(tsign, tg, 63, 63);
                la_slli_d(tsign, tsign, 63);
                /* Extract exponent */
                la_bstrpick_d(tg, tg, 62, 52);
                li_d(tg2, 0x7FF);
                la_sub_d(tg, tg2, tg);
                la_slli_d(tg, tg, 52);
                la_or(tg, tg, tsign);
                la_movgr2fr_d(vresult, tg);
                /* NaN detection: unordered comparison with self */
                IR2_OPND vnan = ra_alloc_ftemp();
                la_vfcmp_cond_d(vnan, vreg_n, vreg_n, FCMP_COND_CUN);
                la_vbitsel_v(vreg_d, vresult, vreg_n, vnan);
                free_alloc_fpr(vnan);
            } else {
                la_movfr2gr_s(tg, vreg_n);
                /* Preserve sign bit */
                la_bstrpick_w(tsign, tg, 31, 31);
                la_slli_w(tsign, tsign, 31);
                /* Extract exponent */
                la_bstrpick_w(tg, tg, 30, 23);
                li_d(tg2, 0xFF);
                la_sub_w(tg, tg2, tg);
                la_slli_w(tg, tg, 23);
                la_or(tg, tg, tsign);
                la_movgr2fr_w(vresult, tg);
                /* NaN detection */
                IR2_OPND vnan = ra_alloc_ftemp();
                la_vfcmp_cond_s(vnan, vreg_n, vreg_n, FCMP_COND_CUN);
                la_vbitsel_v(vreg_d, vresult, vreg_n, vnan);
                free_alloc_fpr(vnan);
            }
            free_alloc_gpr(tg);
            free_alloc_gpr(tg2);
            free_alloc_gpr(tsign);
            free_alloc_fpr(vresult);
        } else if (opcode == 0x7d) { /* FRSQRTE (scalar & vector) */
            if (size == 3)
                la_vfrsqrt_d(vreg_d, vreg_n);
            else
                la_vfrsqrt_s(vreg_d, vreg_n);
        } else {
            free_alloc_fpr(vreg_d);
            free_alloc_fpr(vreg_n);
            lata_unallocated_encoding(s);
            return;
        }
        if (!is_q) la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
        store_fpr_dst(rd, vreg_d);
        free_alloc_fpr(vreg_d);
        free_alloc_fpr(vreg_n);
        return;
    }
}

static void handle_fcvt(DisasContext* s, int opcode, bool is_u, int size,
    int rn, int rd)
{
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);

    /* ARM scalar FCVT operations: float→int with explicit rounding mode.
     * TCG uses softfloat helpers (vfp_tosls/touls/tosqd/touqd) which take
     * the rounding mode via fpstatus.  LSX provides per-rounding-mode
     * instructions for signed conversions, but only truncation variants
     * (vftintrz.*u.*) and FPCR-controlled variants for unsigned. */
    if (size == MO_64) {
        /* f64 → s64 / u64 */
        switch (opcode) {
            case 0x1a: /* FCVTNS — nearest even, signed */
                la_vftintrne_l_d(vreg_d, vreg_n);
                break;
            case 0x1b: /* FCVTMS — toward -inf, signed */
                la_vftintrm_l_d(vreg_d, vreg_n);
                break;
            case 0x3a: /* FCVTPS — toward +inf, signed */
                la_vftintrp_l_d(vreg_d, vreg_n);
                break;
            case 0x3b: /* FCVTZS — trunc, signed */
                la_vftintrz_l_d(vreg_d, vreg_n);
                break;
            case 0x7b: /* FCVTZU — trunc, unsigned */
                la_vftintrz_lu_d(vreg_d, vreg_n);
                break;
            case 0x1c: /* FCVTAS — trunc(x + copysign(0.5, x)) */
                {
                    IR2_OPND vhalf = ra_alloc_ftemp();
                    IR2_OPND igpr = ra_alloc_itemp();
                    IR2_OPND igpr2 = ra_alloc_itemp();
                    la_movfr2gr_d(igpr, vreg_n);
                    la_srli_d(igpr, igpr, 63);
                    la_slli_d(igpr, igpr, 63);
                    li_d(igpr2, 0x3FE0000000000000ULL);
                    la_or(igpr, igpr, igpr2);
                    la_movgr2fr_d(vhalf, igpr);
                    la_fadd_d(vreg_d, vreg_n, vhalf);
                    la_ftintrz_l_d(vreg_d, vreg_d);
                    free_alloc_fpr(vhalf);
                    free_alloc_gpr(igpr);
                    free_alloc_gpr(igpr2);
                }
                break;
            case 0x5c: /* FCVTAU — trunc(x + 0.5) */
                {
                    IR2_OPND vhalf = ra_alloc_ftemp();
                    IR2_OPND igpr = ra_alloc_itemp();
                    li_d(igpr, 0x3FE0000000000000ULL);
                    la_movgr2fr_d(vhalf, igpr);
                    la_fadd_d(vreg_d, vreg_n, vhalf);
                    la_ftintrz_l_d(vreg_d, vreg_d);
                    free_alloc_fpr(vhalf);
                    free_alloc_gpr(igpr);
                }
                break;
            case 0x5a: /* FCVTNU */
            case 0x5b: /* FCVTMU */
            case 0x7a: /* FCVTPU */
                /* Unsigned non-trunc: LSX lacks vftintrne/rm/rp.wu.s etc.
                 * Needs signed+adjust or set-FCSR+convert approach. */
                lata_unallocated_encoding(s);
                return;
            default:
                lata_unallocated_encoding(s);
                return;
        }
    } else {
        /* f32 → s32 / u32 */
        switch (opcode) {
            case 0x1a: /* FCVTNS — nearest even, signed */
                la_vftintrne_w_s(vreg_d, vreg_n);
                break;
            case 0x1b: /* FCVTMS — toward -inf, signed */
                la_vftintrm_w_s(vreg_d, vreg_n);
                break;
            case 0x3a: /* FCVTPS — toward +inf, signed */
                la_vftintrp_w_s(vreg_d, vreg_n);
                break;
            case 0x3b: /* FCVTZS — trunc, signed */
                la_vftintrz_w_s(vreg_d, vreg_n);
                break;
            case 0x7b: /* FCVTZU — trunc, unsigned */
                la_vftintrz_wu_s(vreg_d, vreg_n);
                break;
            case 0x1c: /* FCVTAS — trunc(x + copysign(0.5, x)) */
                {
                    IR2_OPND vhalf = ra_alloc_ftemp();
                    IR2_OPND igpr = ra_alloc_itemp();
                    IR2_OPND igpr2 = ra_alloc_itemp();
                    la_movfr2gr_s(igpr, vreg_n);
                    la_srli_w(igpr, igpr, 31);
                    la_slli_w(igpr, igpr, 31);
                    li_w(igpr2, 0x3F000000);
                    la_or(igpr, igpr, igpr2);
                    la_movgr2fr_w(vhalf, igpr);
                    la_fadd_s(vreg_d, vreg_n, vhalf);
                    la_ftintrz_w_s(vreg_d, vreg_d);
                    free_alloc_fpr(vhalf);
                    free_alloc_gpr(igpr);
                    free_alloc_gpr(igpr2);
                }
                break;
            case 0x5c: /* FCVTAU — trunc(x + 0.5) */
                {
                    IR2_OPND vhalf = ra_alloc_ftemp();
                    IR2_OPND igpr = ra_alloc_itemp();
                    li_w(igpr, 0x3F000000);
                    la_movgr2fr_w(vhalf, igpr);
                    la_fadd_s(vreg_d, vreg_n, vhalf);
                    la_ftintrz_w_s(vreg_d, vreg_d);
                    free_alloc_fpr(vhalf);
                    free_alloc_gpr(igpr);
                }
                break;
            case 0x5a: /* FCVTNU */
            case 0x5b: /* FCVTMU */
            case 0x7a: /* FCVTPU */
                /* Unsigned non-trunc: LSX lacks vftintrne/rm/rp.wu.s etc. */
                lata_unallocated_encoding(s);
                return;
            default:
                lata_unallocated_encoding(s);
                return;
        }
    }

    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
}

static int fcvt_rmode_from_opcode(int opcode)
{
    switch (opcode) {
        case 0x1a: case 0x5a: return FPROUNDING_TIEEVEN;
        case 0x1b: case 0x5b: return FPROUNDING_NEGINF;
        case 0x1c: case 0x5c: return FPROUNDING_TIEAWAY;
        case 0x3a: case 0x7a: return FPROUNDING_POSINF;
        case 0x3b: case 0x7b: return FPROUNDING_ZERO;
        default: return -1;
    }
}

static bool gen_simd_fcvt_fpint_helper(DisasContext* s, int opcode,
    bool is_q, int size, int rn, int rd)
{
    int rmode = fcvt_rmode_from_opcode(opcode);
    bool is_unsigned = opcode >= 0x5a;
    int elements;
    IR2_OPND helper;
    IR2_OPND off;

    if (rmode < 0 || (size != MO_32 && size != MO_64)) {
        return false;
    }
    if (size == MO_64 && !is_q) {
        lata_unallocated_encoding(s);
        return true;
    }

    elements = size == MO_64 ? 2 : (is_q ? 4 : 2);
    helper = ra_alloc_itemp();
    off = ra_alloc_itemp();

    if (arm_la_fmap[rn] >= 0) {
        vector_store_to_env(rn, ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[rn]));
    }

    li_d(off, s->base->pc_next);
    la_st_d(off, env_ir2_opnd, env_offset_pc());
    lata_gen_call_helper_prologue(tcg_ctx);

    li_d(off, env_offset_RMODE());
    li_d(a0_ir2_opnd, arm_rmode_to_sf(rmode));
    la_stx_w(a0_ir2_opnd, env_ir2_opnd, off);

    li_d(off, env_offset_fpstatus());
    la_add_d(a2_ir2_opnd, env_ir2_opnd, off);
    li_d(a1_ir2_opnd, 0);

    if (size == MO_64) {
        for (int i = 0; i < elements; i++) {
            li_d(off, env_offset_fpr(rn) + i * 8);
            la_ldx_d(a0_ir2_opnd, env_ir2_opnd, off);
            li_d(a1_ir2_opnd, 0);
            li_d(off, env_offset_fpstatus());
            la_add_d(a2_ir2_opnd, env_ir2_opnd, off);
            li_d(helper, (uint64_t)(is_unsigned ? helper_vfp_touqd : helper_vfp_tosqd));
            la_jirl(ra_ir2_opnd, helper, 0);
            li_d(off, env_offset_fpr(rd) + i * 8);
            la_stx_d(a0_ir2_opnd, env_ir2_opnd, off);
        }
    } else {
        for (int i = 0; i < elements; i++) {
            li_d(off, env_offset_fpr(rn) + i * 4);
            la_ldx_wu(a0_ir2_opnd, env_ir2_opnd, off);
            li_d(a1_ir2_opnd, 0);
            li_d(off, env_offset_fpstatus());
            la_add_d(a2_ir2_opnd, env_ir2_opnd, off);
            li_d(helper, (uint64_t)(is_unsigned ? helper_vfp_touls : helper_vfp_tosls));
            la_jirl(ra_ir2_opnd, helper, 0);
            li_d(off, env_offset_fpr(rd) + i * 4);
            la_stx_w(a0_ir2_opnd, env_ir2_opnd, off);
        }
        if (!is_q) {
            li_d(off, env_offset_fpr(rd) + 8);
            la_stx_d(zero_ir2_opnd, env_ir2_opnd, off);
        }
    }

    li_d(a6_ir2_opnd, env_offset_FPSCR());
    la_ldx_d(a7_ir2_opnd, env_ir2_opnd, a6_ir2_opnd);
    la_bstrpick_d(a7_ir2_opnd, a7_ir2_opnd, 23, 22);
    li_d(a6_ir2_opnd, env_offset_RMODE());
    la_stx_w(a7_ir2_opnd, env_ir2_opnd, a6_ir2_opnd);

    lata_gen_call_helper_epilogue(tcg_ctx);
    if (arm_la_fmap[rd] >= 0) {
        vector_load(ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[rd]),
                    env_ir2_opnd, env_offset_fpr(rd), off);
    }
    free_alloc_gpr(helper);
    free_alloc_gpr(off);
    return true;
}

static void handle_2misc_narrow(DisasContext* s, bool scalar, int opcode,
    bool u, bool is_q, int size, int rn, int rd)
{
    /* Handle 2-reg-misc ops which are narrowing (so each 2*size element
     * in the source becomes a size element in the destination).
     */
    IR2_OPND vreg_d = alloc_fpr_src(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp1 = ra_alloc_ftemp();
    IR2_OPND vmask = ra_alloc_ftemp();
    la_vandi_b(vtemp, vtemp, 0);

    switch (opcode) {
        case 0x12: /* XTN,XTN2, SQXTUN,SQXTUN2 */
        {
            if (u) {
                /* SQXTUN / SQXTUN2: signed→unsigned saturating narrow.
                   Use vssrani_bu_* which handles clamp+saturate+pack in one step. */
                la_vori_b(vmask, vreg_n, 0);
                /* vssrani_bu_*: signed→unsigned saturated narrow, single instruction */
                switch (size) {
                    case 0: la_vssrani_bu_h(vtemp1, vmask, 0); break;
                    case 1: la_vssrani_hu_w(vtemp1, vmask, 0); break;
                    case 2: la_vssrani_wu_d(vtemp1, vmask, 0); break;
                    default: lata_unallocated_encoding(s); return;
                }
                if (is_q) {
                    /* SQXTUN2: merge narrow result (vtemp1 low 64 bits) into upper half,
                       preserve original lower half */
                    la_vpickev_d(vreg_d, vtemp1, vreg_d);
                } else {
                    la_vori_b(vreg_d, vtemp1, 0);
                    la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
                }
            } else {
                switch (size) {
                    case 0: la_vpickev_b(vtemp, vtemp, vreg_n); break;
                    case 1: la_vpickev_h(vtemp, vtemp, vreg_n); break;
                    case 2: la_vpickev_w(vtemp, vtemp, vreg_n); break;
                    case 3: la_vpickev_d(vtemp, vtemp, vreg_n); break;
                    default: lata_unallocated_encoding(s); return;
                }
                if (is_q) {
                    la_vpickev_d(vreg_d, vtemp, vreg_d);
                } else {
                    la_vori_b(vreg_d, vtemp, 0);
                }
            }
            break;
        }
        case 0x14: /* SQXTN,SQXTN2, UQXTN,UQXTN2 */
        {
            la_vori_b(vmask, vreg_n, 0);

            /* Saturating narrow using vssrani/vssrlni (single instruction:
               saturate + pack), matching dynarmic La64 backend approach. */
            if (u) {
                /* UQXTN: unsigned→unsigned saturated narrow */
                switch (size) {
                    case 0: la_vssrlni_bu_h(vtemp1, vmask, 0); break;
                    case 1: la_vssrlni_hu_w(vtemp1, vmask, 0); break;
                    case 2: la_vssrlni_wu_d(vtemp1, vmask, 0); break;
                    default: lata_unallocated_encoding(s); return;
                }
            } else {
                /* SQXTN: signed→signed saturated narrow */
                switch (size) {
                    case 0: la_vssrani_b_h(vtemp1, vmask, 0); break;
                    case 1: la_vssrani_h_w(vtemp1, vmask, 0); break;
                    case 2: la_vssrani_w_d(vtemp1, vmask, 0); break;
                    default: lata_unallocated_encoding(s); return;
                }
            }

            if (is_q) {
                /* SQXTN2/UQXTN2: merge narrow result into upper half */
                la_vpickev_d(vreg_d, vtemp1, vreg_d);
            } else {
                /* Q=0: narrow result → lower 64 bits, clear upper 64 bits */
                la_vori_b(vreg_d, vtemp1, 0);
                la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            }
            break;
        }
        case 0x16: /* FCVTN, FCVTN2 */
            /* 32 bit to 16 bit or 64 bit to 32 bit float conversion */
            if (size == 2) {
                if (is_q) {
                    la_vori_b(vtemp, vreg_d, 0);
                    la_vfcvt_s_d(vreg_d, vreg_n, vreg_n);
                    la_vextrins_d(vreg_d, vtemp, 0);
                } else {
                    la_vfcvt_s_d(vreg_d, vreg_n, vreg_n);
                    la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
                }
            } else {
                if (is_q) {
                    la_vori_b(vtemp, vreg_d, 0);
                    la_vfcvt_h_s(vreg_d, vreg_n, vreg_n);
                    la_vextrins_d(vreg_d, vtemp, 0);
                } else {
                    la_vfcvt_h_s(vreg_d, vreg_n, vreg_n);
                    la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
                }
            }
            break;
        case 0x36: /* BFCVTN, BFCVTN2 */
        {
            assert(0);
        } break;
        case 0x56: /* FCVTXN, FCVTXN2 */
            /* 64 bit to 32 bit float conversion with round-to-odd.
             * Use fcvt_s_d (nearest-even, differs only for non-exact values). */
            if (size == 2) {
                if (is_q) {
                    la_vori_b(vtemp, vreg_d, 0);
                    la_vfcvt_s_d(vreg_d, vreg_n, vreg_n);
                    la_vextrins_d(vreg_d, vtemp, 0);
                } else {
                    la_vfcvt_s_d(vreg_d, vreg_n, vreg_n);
                }
            } else {
                la_fcvt_s_d(vreg_d, vreg_n);
            }
            break;
        default:
            g_assert_not_reached();
    }

    if (!is_q) {
        /* 高64位清零 */
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }
    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp1);
    free_alloc_fpr(vmask);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
}

/* Remaining saturating accumulating ops */
static void handle_2misc_satacc(DisasContext* s, bool is_scalar, bool is_u,
    bool is_q, int size, int rn, int rd)
{
    /* SUQADD (u=0): SignedSat(SInt(vd) + UInt(vn))
     * USQADD (u=1): UnsignedSat(UInt(vd) + SInt(vn))
     * Widen -> add -> saturating narrow approach. */
    if (size == 3) {
        /* 64-bit mixed signedness needs explicit bounds checks.  LSX signed
         * and unsigned saturated adds do not match SUQADD/USQADD semantics. */
        IR2_OPND vd = is_scalar ? alloc_fpr_dst(rd) : alloc_fpr_src(rd);
        IR2_OPND vn = alloc_fpr_src(rn);
        IR2_OPND tmp = ra_alloc_ftemp();
        IR2_OPND mask = ra_alloc_ftemp();
        if (!is_u) {
            /* SUQADD: signed accumulator plus unsigned operand, saturated to
             * signed range.  Since the operand is non-negative, only positive
             * overflow is possible: vn > INT64_MAX - vd. */
            IR2_OPND int64_max = ra_alloc_ftemp();
            la_vxor_v(int64_max, int64_max, int64_max);
            la_vsubi_du(int64_max, int64_max, 1);
            la_vbitclri_d(int64_max, int64_max, 63);
            la_vsub_d(tmp, int64_max, vd);
            la_vslt_du(mask, tmp, vn);
            la_vadd_d(tmp, vd, vn);
            la_vbitsel_v(vd, tmp, int64_max, mask);
            free_alloc_fpr(int64_max);
        } else {
            /* USQADD: unsigned accumulator plus signed operand, saturated to
             * unsigned range.  Positive operands saturate upward; negative
             * operands subtract their absolute value and saturate at zero. */
            IR2_OPND neg_op = ra_alloc_ftemp();
            IR2_OPND neg_res = ra_alloc_ftemp();
            la_vsrai_d(mask, vn, 63);
            la_vnori_b(neg_op, vn, 0);
            la_vaddi_du(neg_op, neg_op, 1);
            la_vsadd_du(tmp, vd, vn);
            la_vssub_du(neg_res, vd, neg_op);
            la_vbitsel_v(vd, tmp, neg_res, mask);
            free_alloc_fpr(neg_op);
            free_alloc_fpr(neg_res);
        }
        if (is_scalar) {
            la_vinsgr2vr_d(vd, zero_ir2_opnd, 1);
            store_fpr_dst(rd, vd);
        }
        free_alloc_fpr(tmp);
        free_alloc_fpr(mask);
        free_alloc_fpr(vd);
        free_alloc_fpr(vn);
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_src(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp1 = ra_alloc_ftemp();

    if (is_scalar) {
        /* Scalar SUQADD/USQADD: single lane widen-add-narrow */
        if (!is_u) {
            switch (size) {
                case 0:
                    la_vsllwil_h_b(vtemp, vreg_d, 0);
                    la_vsllwil_hu_bu(vtemp1, vreg_n, 0);
                    la_vsadd_h(vtemp, vtemp, vtemp1);
                    la_vssrani_b_h(vreg_d, vtemp, 0);
                    break;
                case 1:
                    la_vsllwil_w_h(vtemp, vreg_d, 0);
                    la_vsllwil_wu_hu(vtemp1, vreg_n, 0);
                    la_vsadd_w(vtemp, vtemp, vtemp1);
                    la_vssrani_h_w(vreg_d, vtemp, 0);
                    break;
                case 2:
                    la_vsllwil_d_w(vtemp, vreg_d, 0);
                    la_vsllwil_du_wu(vtemp1, vreg_n, 0);
                    la_vsadd_d(vtemp, vtemp, vtemp1);
                    la_vssrani_w_d(vreg_d, vtemp, 0);
                    break;
            }
        } else {
            switch (size) {
                case 0:
                    la_vsllwil_hu_bu(vtemp, vreg_d, 0);
                    la_vsllwil_h_b(vtemp1, vreg_n, 0);
                    la_vsadd_h(vtemp, vtemp, vtemp1);
                    la_vssrani_bu_h(vreg_d, vtemp, 0);
                    break;
                case 1:
                    la_vsllwil_wu_hu(vtemp, vreg_d, 0);
                    la_vsllwil_w_h(vtemp1, vreg_n, 0);
                    la_vsadd_w(vtemp, vtemp, vtemp1);
                    la_vssrani_hu_w(vreg_d, vtemp, 0);
                    break;
                case 2:
                    la_vsllwil_du_wu(vtemp, vreg_d, 0);
                    la_vsllwil_d_w(vtemp1, vreg_n, 0);
                    la_vsadd_d(vtemp, vtemp, vtemp1);
                    la_vssrani_wu_d(vreg_d, vtemp, 0);
                    break;
            }
        }
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    } else if (is_q) {
        /* Vector Q=1: process low 64 bits and high 64 bits separately */
        IR2_OPND low_res = ra_alloc_ftemp();
        IR2_OPND high_res = ra_alloc_ftemp();
        if (!is_u) {
            /* SUQADD: vd signed, vn unsigned */
            switch (size) {
                case 0:
                    la_vsllwil_h_b(low_res, vreg_d, 0);
                    la_vsllwil_hu_bu(vtemp, vreg_n, 0);
                    la_vsadd_h(low_res, low_res, vtemp);
                    la_vbsrl_v(vtemp, vreg_d, 8);
                    la_vsllwil_h_b(high_res, vtemp, 0);
                    la_vbsrl_v(vtemp, vreg_n, 8);
                    la_vsllwil_hu_bu(vtemp, vtemp, 0);
                    la_vsadd_h(high_res, high_res, vtemp);
                    la_vssrarni_b_h(high_res, low_res, 0);
                    break;
                case 1:
                    la_vsllwil_w_h(low_res, vreg_d, 0);
                    la_vsllwil_wu_hu(vtemp, vreg_n, 0);
                    la_vsadd_w(low_res, low_res, vtemp);
                    la_vbsrl_v(vtemp, vreg_d, 8);
                    la_vsllwil_w_h(high_res, vtemp, 0);
                    la_vbsrl_v(vtemp, vreg_n, 8);
                    la_vsllwil_wu_hu(vtemp, vtemp, 0);
                    la_vsadd_w(high_res, high_res, vtemp);
                    la_vssrarni_h_w(high_res, low_res, 0);
                    break;
                case 2:
                    la_vsllwil_d_w(low_res, vreg_d, 0);
                    la_vsllwil_du_wu(vtemp, vreg_n, 0);
                    la_vsadd_d(low_res, low_res, vtemp);
                    la_vbsrl_v(vtemp, vreg_d, 8);
                    la_vsllwil_d_w(high_res, vtemp, 0);
                    la_vbsrl_v(vtemp, vreg_n, 8);
                    la_vsllwil_du_wu(vtemp, vtemp, 0);
                    la_vsadd_d(high_res, high_res, vtemp);
                    la_vssrarni_w_d(high_res, low_res, 0);
                    break;
            }
        } else {
            /* USQADD: vd unsigned, vn signed */
            switch (size) {
                case 0:
                    la_vsllwil_hu_bu(low_res, vreg_d, 0);
                    la_vsllwil_h_b(vtemp, vreg_n, 0);
                    la_vsadd_h(low_res, low_res, vtemp);
                    la_vbsrl_v(vtemp, vreg_d, 8);
                    la_vsllwil_hu_bu(high_res, vtemp, 0);
                    la_vbsrl_v(vtemp, vreg_n, 8);
                    la_vsllwil_h_b(vtemp, vtemp, 0);
                    la_vsadd_h(high_res, high_res, vtemp);
                    la_vssrarni_bu_h(high_res, low_res, 0);
                    break;
                case 1:
                    la_vsllwil_wu_hu(low_res, vreg_d, 0);
                    la_vsllwil_w_h(vtemp, vreg_n, 0);
                    la_vsadd_w(low_res, low_res, vtemp);
                    la_vbsrl_v(vtemp, vreg_d, 8);
                    la_vsllwil_wu_hu(high_res, vtemp, 0);
                    la_vbsrl_v(vtemp, vreg_n, 8);
                    la_vsllwil_w_h(vtemp, vtemp, 0);
                    la_vsadd_w(high_res, high_res, vtemp);
                    la_vssrarni_hu_w(high_res, low_res, 0);
                    break;
                case 2:
                    la_vsllwil_du_wu(low_res, vreg_d, 0);
                    la_vsllwil_d_w(vtemp, vreg_n, 0);
                    la_vsadd_d(low_res, low_res, vtemp);
                    la_vbsrl_v(vtemp, vreg_d, 8);
                    la_vsllwil_du_wu(high_res, vtemp, 0);
                    la_vbsrl_v(vtemp, vreg_n, 8);
                    la_vsllwil_d_w(vtemp, vtemp, 0);
                    la_vsadd_d(high_res, high_res, vtemp);
                    la_vssrarni_wu_d(high_res, low_res, 0);
                    break;
            }
        }
        la_vori_b(vreg_d, high_res, 0);
        free_alloc_fpr(low_res);
        free_alloc_fpr(high_res);
    } else {
        /* Q=0: single widening */
        if (!is_u) {
            switch (size) {
                case 0:
                    la_vsllwil_h_b(vtemp, vreg_d, 0);
                    la_vsllwil_hu_bu(vtemp1, vreg_n, 0);
                    la_vsadd_h(vtemp, vtemp, vtemp1);
                    la_vssrani_b_h(vreg_d, vtemp, 0);
                    break;
                case 1:
                    la_vsllwil_w_h(vtemp, vreg_d, 0);
                    la_vsllwil_wu_hu(vtemp1, vreg_n, 0);
                    la_vsadd_w(vtemp, vtemp, vtemp1);
                    la_vssrani_h_w(vreg_d, vtemp, 0);
                    break;
                case 2:
                    la_vsllwil_d_w(vtemp, vreg_d, 0);
                    la_vsllwil_du_wu(vtemp1, vreg_n, 0);
                    la_vsadd_d(vtemp, vtemp, vtemp1);
                    la_vssrani_w_d(vreg_d, vtemp, 0);
                    break;
            }
        } else {
            switch (size) {
                case 0:
                    la_vsllwil_hu_bu(vtemp, vreg_d, 0);
                    la_vsllwil_h_b(vtemp1, vreg_n, 0);
                    la_vsadd_h(vtemp, vtemp, vtemp1);
                    la_vssrani_bu_h(vreg_d, vtemp, 0);
                    break;
                case 1:
                    la_vsllwil_wu_hu(vtemp, vreg_d, 0);
                    la_vsllwil_w_h(vtemp1, vreg_n, 0);
                    la_vsadd_w(vtemp, vtemp, vtemp1);
                    la_vssrani_hu_w(vreg_d, vtemp, 0);
                    break;
                case 2:
                    la_vsllwil_du_wu(vtemp, vreg_d, 0);
                    la_vsllwil_d_w(vtemp1, vreg_n, 0);
                    la_vsadd_d(vtemp, vtemp, vtemp1);
                    la_vssrani_wu_d(vreg_d, vtemp, 0);
                    break;
            }
        }
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp1);
}

/* AdvSIMD scalar two reg misc
 *  31 30  29 28       24 23  22 21       17 16    12 11 10 9    5 4    0
 * +-----+---+-----------+------+-----------+--------+-----+------+------+
 * | 0 1 | U | 1 1 1 1 0 | size | 1 0 0 0 0 | opcode | 1 0 |  Rn  |  Rd  |
 * +-----+---+-----------+------+-----------+--------+-----+------+------+
 */
static void disas_simd_scalar_two_reg_misc(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int opcode = extract32(insn, 12, 5);
    int size = extract32(insn, 22, 2);
    bool u = extract32(insn, 29, 1);
    switch (opcode) {
        case 0x3: /* USQADD / SUQADD*/
            if (!fp_access_check(s)) {
                return;
            }
            handle_2misc_satacc(s, true, u, false, size, rn, rd);
            return;
        case 0x7: /* SQABS / SQNEG */
        {
            if (!fp_access_check(s)) {
                return;
            }
            IR2_OPND vreg_d = alloc_fpr_dst(rd);
            IR2_OPND vreg_n = alloc_fpr_src(rn);
            IR2_OPND vzero = ra_alloc_ftemp();
            la_vxor_v(vzero, vzero, vzero);
            if (u) {
                /* SQNEG: scalar saturating negate = vssub(0, vn) */
                switch (size) {
                    case 0: la_vssub_b(vreg_d, vzero, vreg_n); break;
                    case 1: la_vssub_h(vreg_d, vzero, vreg_n); break;
                    case 2: la_vssub_w(vreg_d, vzero, vreg_n); break;
                    case 3: la_vssub_d(vreg_d, vzero, vreg_n); break;
                }
            } else {
                /* SQABS: scalar saturating abs = vmax(vn, vssub(0, vn)) */
                IR2_OPND vneg = ra_alloc_ftemp();
                switch (size) {
                    case 0: la_vssub_b(vneg, vzero, vreg_n); break;
                    case 1: la_vssub_h(vneg, vzero, vreg_n); break;
                    case 2: la_vssub_w(vneg, vzero, vreg_n); break;
                    case 3: la_vssub_d(vneg, vzero, vreg_n); break;
                }
                switch (size) {
                    case 0: la_vmax_b(vreg_d, vreg_n, vneg); break;
                    case 1: la_vmax_h(vreg_d, vreg_n, vneg); break;
                    case 2: la_vmax_w(vreg_d, vreg_n, vneg); break;
                    case 3: la_vmax_d(vreg_d, vreg_n, vneg); break;
                }
                free_alloc_fpr(vneg);
            }
            free_alloc_fpr(vzero);
            store_fpr_dst(rd, vreg_d);
            free_alloc_fpr(vreg_d);
            free_alloc_fpr(vreg_n);
        }
            return;
        case 0xa: /* CMLT */
            if (u) {
                lata_unallocated_encoding(s);
                return;
            }
            /* fall through */
        case 0x8: /* CMGT, CMGE */
        case 0x9: /* CMEQ, CMLE */
        case 0xb: /* ABS, NEG */
            if (size != 3) {
                lata_unallocated_encoding(s);
                return;
            }
            if (!fp_access_check(s)) {
                return;
            }
            {
                IR2_OPND vreg_d = alloc_fpr_dst(rd);
                IR2_OPND vreg_n = alloc_fpr_src(rn);
                if (u) {
                    la_vneg_d(vreg_d, vreg_n);
                } else {
                    IR2_OPND vzero = ra_alloc_ftemp();
                    la_vxor_v(vzero, vzero, vzero);
                    la_vabsd_d(vreg_d, vreg_n, vzero);
                    free_alloc_fpr(vzero);
                }
                store_fpr_dst(rd, vreg_d);
                free_alloc_fpr(vreg_d);
                free_alloc_fpr(vreg_n);
            }
            return;
            break;
        case 0x12: /* SQXTUN */
            if (!u) {
                lata_unallocated_encoding(s);
                return;
            }
            /* fall through */
        case 0x14: /* SQXTN, UQXTN */
            if (size == 3) {
                lata_unallocated_encoding(s);
                return;
            }
            if (!fp_access_check(s)) {
                return;
            }
            handle_2misc_narrow(s, true, opcode, u, false, size, rn, rd);
            return;
        case 0xc ... 0xf:
        case 0x16 ... 0x1d:
        case 0x1f:
            /* Floating point: U, size[1] and opcode indicate operation;
             * size[0] indicates single or double precision.
             */
            opcode |= (extract32(size, 1, 1) << 5) | (u << 6);
            size = extract32(size, 0, 1) ? 3 : 2;
            switch (opcode) {
                case 0x2c: /* FCMGT (zero) */
                case 0x2d: /* FCMEQ (zero) */
                case 0x2e: /* FCMLT (zero) */
                case 0x6c: /* FCMGE (zero) */
                case 0x6d: /* FCMLE (zero) */
                    handle_2misc_fcmp_zero(s, opcode, true, u, true, size, rn, rd);
                    return;
                case 0x1d: /* SCVTF */
                case 0x5d: /* UCVTF */
                {
                    bool is_signed = (opcode == 0x1d);
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_simd_intfp_conv(s, rd, rn, 1, is_signed, 0, size);
                    return;
                }
                case 0x3d: /* FRECPE */
                case 0x3f: /* FRECPX */
                case 0x7d: /* FRSQRTE */
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_2misc_reciprocal(s, opcode, true, u, true, size, rn, rd);
                    return;
                case 0x1a: /* FCVTNS */
                case 0x1b: /* FCVTMS */
                case 0x3a: /* FCVTPS */
                case 0x3b: /* FCVTZS */
                case 0x5a: /* FCVTNU */
                case 0x5b: /* FCVTMU */
                case 0x7a: /* FCVTPU */
                case 0x7b: /* FCVTZU */
                case 0x1c: /* FCVTAS */
                case 0x5c: /* FCVTAU */
                    if ((opcode == 0x1c || opcode == 0x5c) && size == MO_64 &&
                        gen_simd_fcvt_fpint_helper(s, opcode, true, size, rn, rd)) {
                        return;
                    }
                    handle_fcvt(s, opcode, u, size, rn, rd);
                    return;
                case 0x56: /* FCVTXN, FCVTXN2 */
                    if (size == 2) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_2misc_narrow(s, true, opcode, u, false, size - 1, rn, rd);
                    return;
                default:
                    lata_unallocated_encoding(s);
                    return;
            }
            break;
        default:
            lata_unallocated_encoding(s);
            return;
    }

    if (!fp_access_check(s)) {
        return;
    }
}

/* SSHR[RA]/USHR[RA] - Vector shift right (optional rounding/accumulate) */
static void handle_vec_simd_shri(DisasContext* s, bool is_q, bool is_u,
    int immh, int immb, int opcode, int rn, int rd)
{
    int size = 32 - clz32(immh) - 1;
    int immhb = immh << 3 | immb;
    int shift = 2 * (8 << size) - immhb;
    IR2_OPND vreg_d = alloc_fpr_src(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp1 = ra_alloc_ftemp();

    if (extract32(immh, 3, 1) && !is_q) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    la_vbsrl_v(vtemp, vreg_n, 0);
    /* 高位清零 */
    if (!is_q) {
        la_vinsgr2vr_d(vtemp, zero_ir2_opnd, 1);
    }

    switch (opcode) {
        case 0x02: /* SSRA / USRA (accumulate) */
            if (is_u) {
                /* Shift count the same size as element size produces zero.  */
                if (shift == 8 << size) {
                    break;
                }
                switch (size) {
                    case 0:
                        la_vsrli_b(vtemp1, vtemp, shift);
                        la_vadd_b(vreg_d, vtemp1, vreg_d);
                        break;
                    case 1:
                        la_vsrli_h(vtemp1, vtemp, shift);
                        la_vadd_h(vreg_d, vtemp1, vreg_d);
                        break;
                    case 2:
                        la_vsrli_w(vtemp1, vtemp, shift);
                        la_vadd_w(vreg_d, vtemp1, vreg_d);
                        break;
                    case 3:
                        la_vsrli_d(vtemp1, vtemp, shift);
                        la_vadd_d(vreg_d, vtemp1, vreg_d);
                        break;
                    default:
                        lata_unallocated_encoding(s);
                        return;
                }
            } else {
                /* Shift count the same size as element size produces all sign.  */
                if (shift == 8 << size) {
                    shift -= 1;
                }
                switch (size) {
                    case 0:
                        la_vsrai_b(vtemp1, vtemp, shift);
                        la_vadd_b(vreg_d, vtemp1, vreg_d);
                        break;
                    case 1:
                        la_vsrai_h(vtemp1, vtemp, shift);
                        la_vadd_h(vreg_d, vtemp1, vreg_d);
                        break;
                    case 2:
                        la_vsrai_w(vtemp1, vtemp, shift);
                        la_vadd_w(vreg_d, vtemp1, vreg_d);
                        break;
                    case 3:
                        la_vsrai_d(vtemp1, vtemp, shift);
                        la_vadd_d(vreg_d, vtemp1, vreg_d);
                        break;
                    default:
                        lata_unallocated_encoding(s);
                        return;
                }
            }
            break;

        case 0x08: /* SRI: result = (vd & mask) | (vn >> shift)
                      mask = ~(ones(esize) >> shift) per lane */
        {
            int esize = 8 << size;
            if (shift == 0) {
                /* shift==0: mask=0, result = vn */
                la_vori_b(vreg_d, vtemp, 0);
            } else if (shift < esize) {
                switch (size) {
                    case 0: la_vsrli_b(vtemp, vtemp, shift); break;
                    case 1: la_vsrli_h(vtemp, vtemp, shift); break;
                    case 2: la_vsrli_w(vtemp, vtemp, shift); break;
                    case 3: la_vsrli_d(vtemp, vtemp, shift); break;
                }
                /* mask = (ones(esize) << (esize - shift)) & ones(esize) per lane */
                IR2_OPND vmask = ra_alloc_ftemp();
                IR2_OPND igpr = ra_alloc_itemp();
                if (esize == 64) {
                    uint64_t lane_val = ~0ULL << (64 - shift);
                    li_d(igpr, lane_val);
                    la_vreplgr2vr_d(vmask, igpr);
                } else {
                    uint64_t lane_mask = ((1ULL << esize) - 1) << (esize - shift);
                    li_w(igpr, (uint32_t)lane_mask);
                    if (esize == 8)
                        la_vreplgr2vr_b(vmask, igpr);
                    else if (esize == 16)
                        la_vreplgr2vr_h(vmask, igpr);
                    else
                        la_vreplgr2vr_w(vmask, igpr);
                }
                free_alloc_gpr(igpr);
                la_vand_v(vmask, vreg_d, vmask);
                la_vor_v(vreg_d, vtemp, vmask);
                free_alloc_fpr(vmask);
            }
            /* shift >= esize: result = vd (no change) */
            break;
        }

        case 0x00: /* SSHR / USHR */
            if (is_u) {
                /* Shift count the same size as element size produces zero.  */
                if (shift == 8 << size) {
                    la_vandi_b(vreg_d, vtemp, 0);
                    break;
                }
                switch (size) {
                    case 0:
                        la_vsrli_b(vreg_d, vtemp, shift);
                        break;
                    case 1:
                        la_vsrli_h(vreg_d, vtemp, shift);
                        break;
                    case 2:
                        la_vsrli_w(vreg_d, vtemp, shift);
                        break;
                    case 3:
                        la_vsrli_d(vreg_d, vtemp, shift);
                        break;
                    default:
                        assert(0);
                }
            } else {
                /* Shift count the same size as element size produces all sign.  */
                if (shift == 8 << size) {
                    shift -= 1;
                }
                switch (size) {
                    case 0:
                        la_vsrai_b(vreg_d, vtemp, shift);
                        break;
                    case 1:
                        la_vsrai_h(vreg_d, vtemp, shift);
                        break;
                    case 2:
                        la_vsrai_w(vreg_d, vtemp, shift);
                        break;
                    case 3:
                        la_vsrai_d(vreg_d, vtemp, shift);
                        break;
                    default:
                        assert(0);
                }
            }
            break;

        case 0x04: /* SRSHR / URSHR (rounding) */
            /* Shift count equal to element size:
               signed SRSHR => always 0 (rounding cannot affect result).
               unsigned URSHR => (x >> (esize-1)) & 1. */
            if (shift == 8 << size) {
                if (is_u) {
                    /* URSHR with shift==esize: result = (x >> (esize-1)) & 1,
                       which is just x >> (esize-1) since the result is 0 or 1. */
                    switch (size) {
                        case 0: la_vsrli_b(vreg_d, vtemp, 7); break;
                        case 1: la_vsrli_h(vreg_d, vtemp, 15); break;
                        case 2: la_vsrli_w(vreg_d, vtemp, 31); break;
                        case 3: la_vsrli_d(vreg_d, vtemp, 63); break;
                    }
                } else {
                    la_vandi_b(vreg_d, vtemp, 0);
                }
                break;
            }
            if (is_u) {
                switch (size) {
                    case 0:
                        la_vsrlri_b(vreg_d, vtemp, shift);
                        break;
                    case 1:
                        la_vsrlri_h(vreg_d, vtemp, shift);
                        break;
                    case 2:
                        la_vsrlri_w(vreg_d, vtemp, shift);
                        break;
                    case 3:
                        la_vsrlri_d(vreg_d, vtemp, shift);
                        break;
                    default:
                        assert(0);
                }
            } else {
                switch (size) {
                    case 0:
                        la_vsrari_b(vreg_d, vtemp, shift);
                        break;
                    case 1:
                        la_vsrari_h(vreg_d, vtemp, shift);
                        break;
                    case 2:
                        la_vsrari_w(vreg_d, vtemp, shift);
                        break;
                    case 3:
                        la_vsrari_d(vreg_d, vtemp, shift);
                        break;
                    default:
                        assert(0);
                }
            }
            break;

        case 0x06: /* SRSRA / URSRA (accum + rounding) */
            /* Shift count equal to element size:
               unsigned => add (x >> (esize-1)) & 1 to dest.
               signed => always 0, no-op. */
            if (shift == 8 << size) {
                if (is_u) {
                    switch (size) {
                        case 0: la_vsrli_b(vtemp1, vtemp, 7);
                                la_vadd_b(vreg_d, vreg_d, vtemp1); break;
                        case 1: la_vsrli_h(vtemp1, vtemp, 15);
                                la_vadd_h(vreg_d, vreg_d, vtemp1); break;
                        case 2: la_vsrli_w(vtemp1, vtemp, 31);
                                la_vadd_w(vreg_d, vreg_d, vtemp1); break;
                        case 3: la_vsrli_d(vtemp1, vtemp, 63);
                                la_vadd_d(vreg_d, vreg_d, vtemp1); break;
                    }
                }
                break;
            }
            if (is_u) {
                switch (size) {
                    case 0:
                        la_vsrlri_b(vtemp1, vtemp, shift);
                        la_vadd_b(vreg_d, vtemp1, vreg_d);
                        break;
                    case 1:
                        la_vsrlri_h(vtemp1, vtemp, shift);
                        la_vadd_h(vreg_d, vtemp1, vreg_d);
                        break;
                    case 2:
                        la_vsrlri_w(vtemp1, vtemp, shift);
                        la_vadd_w(vreg_d, vtemp1, vreg_d);
                        break;
                    case 3:
                        la_vsrlri_d(vtemp1, vtemp, shift);
                        la_vadd_d(vreg_d, vtemp1, vreg_d);
                        break;
                    default: assert(0);
                }
            } else {
                switch (size) {
                    case 0:
                        la_vsrari_b(vtemp1, vtemp, shift);
                        la_vadd_b(vreg_d, vtemp1, vreg_d);
                        break;
                    case 1:
                        la_vsrari_h(vtemp1, vtemp, shift);
                        la_vadd_h(vreg_d, vtemp1, vreg_d);
                        break;
                    case 2:
                        la_vsrari_w(vtemp1, vtemp, shift);
                        la_vadd_w(vreg_d, vtemp1, vreg_d);
                        break;
                    case 3:
                        la_vsrari_d(vtemp1, vtemp, shift);
                        la_vadd_d(vreg_d, vtemp1, vreg_d);
                        break;
                    default: assert(0);
                }
            }
            break;

        default:
            g_assert_not_reached();
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp1);
}

/* SHL/SLI - Vector shift left */
static void handle_vec_simd_shli(DisasContext* s, bool is_q, bool insert,
    int immh, int immb, int opcode, int rn, int rd)
{
    int size = 32 - clz32(immh) - 1;
    int immhb = immh << 3 | immb;
    int shift = immhb - (8 << size);

    /* Range of size is limited by decode: immh is a non-zero 4 bit field */
    assert(size >= 0 && size <= 3);

    if (extract32(immh, 3, 1) && !is_q) {
        lata_unallocated_encoding(s);
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_mask = ra_alloc_ftemp();
    IR2_OPND vreg_temp = ra_alloc_ftemp();

    if (!insert) {
        switch (size) {
            case 0:
                la_vslli_b(vreg_d, vreg_n, shift);
                break;
            case 1:
                la_vslli_h(vreg_d, vreg_n, shift);
                break;
            case 2:
                la_vslli_w(vreg_d, vreg_n, shift);
                break;
            case 3:
                la_vslli_d(vreg_d, vreg_n, shift);
                break;
            default:
                break;
        }
    } else {
        int esize = 8 << size;
        if (shift == 0) {
            /* shift=0: mask>>esize = 0; vd = vn */
            la_vori_b(vreg_d, vreg_n, 0);
        } else {
            la_vfcmp_cond_d(vreg_mask, vreg_n, vreg_n, FCMP_COND_SEQ);
            switch (size) {
                case 0:
                    la_vsrli_b(vreg_mask, vreg_mask, esize - shift);
                    la_vand_v(vreg_temp, vreg_d, vreg_mask);
                    la_vslli_b(vreg_d, vreg_n, shift);
                    break;
                case 1:
                    la_vsrli_h(vreg_mask, vreg_mask, esize - shift);
                    la_vand_v(vreg_temp, vreg_d, vreg_mask);
                    la_vslli_h(vreg_d, vreg_n, shift);
                    break;
                case 2:
                    la_vsrli_w(vreg_mask, vreg_mask, esize - shift);
                    la_vand_v(vreg_temp, vreg_d, vreg_mask);
                    la_vslli_w(vreg_d, vreg_n, shift);
                    break;
                case 3:
                    la_vsrli_d(vreg_mask, vreg_mask, esize - shift);
                    la_vand_v(vreg_temp, vreg_d, vreg_mask);
                    la_vslli_d(vreg_d, vreg_n, shift);
                    break;
                default:
                    break;
            }
            la_vor_v(vreg_d, vreg_d, vreg_temp);
        }
    }

    if (!is_q) {
        /* 高64位清零 */
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }
    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_mask);
    free_alloc_fpr(vreg_temp);
}

/* USHLL/SSHLL - Vector shift left with widening */
static void handle_vec_simd_wshli(DisasContext* s, bool is_q, bool is_u,
    int immh, int immb, int opcode, int rn, int rd)
{
    int size = 32 - clz32(immh) - 1;
    int immhb = immh << 3 | immb;
    int shift = immhb - (8 << size);
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();

    if (size >= 3) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    /* 统一移至低位处理 */
    if (!is_q) {
        la_vbsrl_v(vtemp, vreg_n, 0);
    } else {
        la_vbsrl_v(vtemp, vreg_n, 8);
    }

    /* USHLL/USHLL2*/
    if (is_u) {
        switch (size) {
            case 0:
                la_vsllwil_hu_bu(vreg_d, vtemp, shift);
                break;
            case 1:
                la_vsllwil_wu_hu(vreg_d, vtemp, shift);
                break;
            case 2:
                la_vsllwil_du_wu(vreg_d, vtemp, shift);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
        }
    } else {
        switch (size) {
            case 0:
                la_vsllwil_h_b(vreg_d, vtemp, shift);
                break;
            case 1:
                la_vsllwil_w_h(vreg_d, vtemp, shift);
                break;
            case 2:
                la_vsllwil_d_w(vreg_d, vtemp, shift);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
        }
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
}

/* SHRN/RSHRN - Shift right with narrowing (and potential rounding) */
static void handle_vec_simd_shrn(DisasContext* s, bool is_q,
    int immh, int immb, int opcode, int rn, int rd)
{
    int immhb = immh << 3 | immb;
    int size = 32 - clz32(immh) - 1;
    int esize = 8 << size;
    int shift = (2 * esize) - immhb;
    bool round = extract32(opcode, 0, 1);
    IR2_OPND vreg_d = alloc_fpr_src(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp2 = ra_alloc_ftemp();

    if (size < 0) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    la_vandi_b(vtemp2, vtemp2, 0);

    if (is_q) { // SHRN2/RSHRN2 (writes the upper, keep the lower)
        switch (size) {
            case 0:
                if (round) {
                    la_vsrlri_h(vtemp, vreg_n, shift);
                } else {
                    la_vsrli_h(vtemp, vreg_n, shift);
                }
                la_vsrln_b_h(vtemp, vtemp, vtemp2);
                break;
            case 1:
                if (round) {
                    la_vsrlri_w(vtemp, vreg_n, shift);
                } else {
                    la_vsrli_w(vtemp, vreg_n, shift);
                }
                la_vsrln_h_w(vtemp, vtemp, vtemp2);
                break;
            case 2:
                if (round) {
                    la_vsrlri_d(vtemp, vreg_n, shift);
                } else {
                    la_vsrli_d(vtemp, vreg_n, shift);
                }
                la_vsrln_w_d(vtemp, vtemp, vtemp2);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
        }
        la_vpickev_d(vreg_d, vtemp, vreg_d);
    } else { // SHRN/RSHRN (writes the lower, clears the upper)
        switch (size) {
            case 0:
                if (round) {
                    la_vsrlri_h(vtemp, vreg_n, shift);
                } else {
                    la_vsrli_h(vtemp, vreg_n, shift);
                }
                la_vsrln_b_h(vreg_d, vtemp, vtemp2);
                break;
            case 1:
                if (round) {
                    la_vsrlri_w(vtemp, vreg_n, shift);
                } else {
                    la_vsrli_w(vtemp, vreg_n, shift);
                }
                la_vsrln_h_w(vreg_d, vtemp, vtemp2);
                break;
            case 2:
                if (round) {
                    la_vsrlri_d(vtemp, vreg_n, shift);
                } else {
                    la_vsrli_d(vtemp, vreg_n, shift);
                }
                la_vsrln_w_d(vreg_d, vtemp, vtemp2);
                break;
            default:
                assert(0);
        }
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp2);
}

/* AdvSIMD shift by immediate
 *  31  30   29 28         23 22  19 18  16 15    11  10 9    5 4    0
 * +---+---+---+-------------+------+------+--------+---+------+------+
 * | 0 | Q | U | 0 1 1 1 1 0 | immh | immb | opcode | 1 |  Rn  |  Rd  |
 * +---+---+---+-------------+------+------+--------+---+------+------+
 */
static void disas_simd_shift_imm(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int opcode = extract32(insn, 11, 5);
    int immb = extract32(insn, 16, 3);
    int immh = extract32(insn, 19, 4);
    bool is_u = extract32(insn, 29, 1);
    bool is_q = extract32(insn, 30, 1);

    /* data_proc_simd[] has sent immh == 0 to disas_simd_mod_imm. */
    assert(immh != 0);

    switch (opcode) {
        case 0x08: /* SRI */
            if (!is_u) {
                lata_unallocated_encoding(s);
                return;
            }
            /* fall through */
        case 0x00: /* SSHR / USHR */
        case 0x02: /* SSRA / USRA (accumulate) */
        case 0x04: /* SRSHR / URSHR (rounding) */
        case 0x06: /* SRSRA / URSRA (accum + rounding) */
            handle_vec_simd_shri(s, is_q, is_u, immh, immb, opcode, rn, rd);
            break;
        case 0x0a: /* SHL / SLI */
            handle_vec_simd_shli(s, is_q, is_u, immh, immb, opcode, rn, rd);
            break;
        case 0x10: /* SHRN */
        case 0x11: /* RSHRN / SQRSHRUN */
            if (is_u) {
                handle_vec_simd_sqshrn(s, false, is_q, false, true, immh, immb,
                    opcode, rn, rd);
            } else {
                handle_vec_simd_shrn(s, is_q, immh, immb, opcode, rn, rd);
            }
            break;
        case 0x12: /* SQSHRN / UQSHRN */
        case 0x13: /* SQRSHRN / UQRSHRN */
            handle_vec_simd_sqshrn(s, false, is_q, is_u, is_u, immh, immb,
                opcode, rn, rd);
            break;
        case 0x14: /* SSHLL / USHLL */
            handle_vec_simd_wshli(s, is_q, is_u, immh, immb, opcode, rn, rd);
            break;
        case 0x1c: /* SCVTF / UCVTF */
            handle_simd_shift_intfp_conv(s, false, is_q, is_u, immh, immb,
                opcode, rn, rd);
            break;
        case 0xc: /* SQSHLU */
            if (!is_u) {
                lata_unallocated_encoding(s);
                return;
            }
            handle_simd_qshl(s, false, is_q, false, true, immh, immb, rn, rd);
            break;
        case 0xe: /* SQSHL, UQSHL */
            handle_simd_qshl(s, false, is_q, is_u, is_u, immh, immb, rn, rd);
            break;
        case 0x1f: /* FCVTZS/ FCVTZU */
            handle_simd_shift_fpint_conv(s, false, is_q, is_u, immh, immb, rn, rd);
            return;
        default:
            lata_unallocated_encoding(s);
            return;
    }
}

static void handle_3rd_widening(DisasContext* s, int is_q, int is_u, int size,
    int opcode, int rd, int rn, int rm)
{
    /* 3-reg-different widening insns: 64 x 64 -> 128 */
    IR2_OPND vreg_d;
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp1 = ra_alloc_ftemp();

    /* 0向量寄存器 */
    IR2_OPND vzero = ra_alloc_ftemp();
    la_vandi_b(vzero, vzero, 0);

    int op_id = (is_u << 4) | opcode;
    int is_sub = extract32(op_id, 1, 1);

    switch (op_id) {
        case 0x0:  /* SADDL, SADDL2 */
        case 0x2:  /* SSUBL, SSUBL2 */
        case 0x7:  /* SABDL, SABDL2 */
        case 0x17: /* UABDL, UABDL2 */
            vreg_d = alloc_fpr_dst(rd);
            if (is_q) {
                /* SADDL2/SSUBL2/SABDL2: widen UPPER half, then operate */
                if (is_u) {
                    switch (size) {
                        case 0:
                            la_vexth_hu_bu(vtemp, vreg_n);
                            la_vexth_hu_bu(vreg_d, vreg_m);
                            break;
                        case 1:
                            la_vexth_wu_hu(vtemp, vreg_n);
                            la_vexth_wu_hu(vreg_d, vreg_m);
                            break;
                        case 2:
                            la_vexth_du_wu(vtemp, vreg_n);
                            la_vexth_du_wu(vreg_d, vreg_m);
                            break;
                    }
                } else {
                    switch (size) {
                        case 0:
                            la_vexth_h_b(vtemp, vreg_n);
                            la_vexth_h_b(vreg_d, vreg_m);
                            break;
                        case 1:
                            la_vexth_w_h(vtemp, vreg_n);
                            la_vexth_w_h(vreg_d, vreg_m);
                            break;
                        case 2:
                            la_vexth_d_w(vtemp, vreg_n);
                            la_vexth_d_w(vreg_d, vreg_m);
                            break;
                    }
                }
                bool is_abd = (opcode == 0x7);
                if (is_abd) {
                    if (is_u) {
                        switch (size) {
                            case 0: la_vabsd_hu(vreg_d, vtemp, vreg_d); break;
                            case 1: la_vabsd_wu(vreg_d, vtemp, vreg_d); break;
                            case 2: la_vabsd_du(vreg_d, vtemp, vreg_d); break;
                        }
                    } else {
                        switch (size) {
                            case 0: la_vabsd_h(vreg_d, vtemp, vreg_d); break;
                            case 1: la_vabsd_w(vreg_d, vtemp, vreg_d); break;
                            case 2: la_vabsd_d(vreg_d, vtemp, vreg_d); break;
                        }
                    }
                } else if (is_sub) {
                    switch (size) {
                        case 0: la_vsub_h(vreg_d, vtemp, vreg_d); break;
                        case 1: la_vsub_w(vreg_d, vtemp, vreg_d); break;
                        case 2: la_vsub_d(vreg_d, vtemp, vreg_d); break;
                    }
                } else {
                    switch (size) {
                        case 0: la_vadd_h(vreg_d, vtemp, vreg_d); break;
                        case 1: la_vadd_w(vreg_d, vtemp, vreg_d); break;
                        case 2: la_vadd_d(vreg_d, vtemp, vreg_d); break;
                    }
                }
            } else {
                /* Q=0: widen LOWER half, then operate */
                if (is_u) {
                    switch (size) {
                        case 0:
                            la_vsllwil_hu_bu(vtemp, vreg_m, 0);
                            la_vsllwil_hu_bu(vreg_d, vreg_n, 0);
                            break;
                        case 1:
                            la_vsllwil_wu_hu(vtemp, vreg_m, 0);
                            la_vsllwil_wu_hu(vreg_d, vreg_n, 0);
                            break;
                        case 2:
                            la_vsllwil_du_wu(vtemp, vreg_m, 0);
                            la_vsllwil_du_wu(vreg_d, vreg_n, 0);
                            break;
                    }
                } else {
                    switch (size) {
                        case 0:
                            la_vsllwil_h_b(vtemp, vreg_m, 0);
                            la_vsllwil_h_b(vreg_d, vreg_n, 0);
                            break;
                        case 1:
                            la_vsllwil_w_h(vtemp, vreg_m, 0);
                            la_vsllwil_w_h(vreg_d, vreg_n, 0);
                            break;
                        case 2:
                            la_vsllwil_d_w(vtemp, vreg_m, 0);
                            la_vsllwil_d_w(vreg_d, vreg_n, 0);
                            break;
                    }
                }
                bool is_abd = (opcode == 0x7);
                if (is_abd) {
                    if (is_u) {
                        switch (size) {
                            case 0: la_vabsd_hu(vreg_d, vtemp, vreg_d); break;
                            case 1: la_vabsd_wu(vreg_d, vtemp, vreg_d); break;
                            case 2: la_vabsd_du(vreg_d, vtemp, vreg_d); break;
                        }
                    } else {
                        switch (size) {
                            case 0: la_vabsd_h(vreg_d, vreg_d, vtemp); break;
                            case 1: la_vabsd_w(vreg_d, vreg_d, vtemp); break;
                            case 2: la_vabsd_d(vreg_d, vreg_d, vtemp); break;
                        }
                    }
                } else if (is_sub) {
                    switch (size) {
                        case 0: la_vsub_h(vreg_d, vreg_d, vtemp); break;
                        case 1: la_vsub_w(vreg_d, vreg_d, vtemp); break;
                        case 2: la_vsub_d(vreg_d, vreg_d, vtemp); break;
                    }
                } else {
                    switch (size) {
                        case 0: la_vadd_h(vreg_d, vreg_d, vtemp); break;
                        case 1: la_vadd_w(vreg_d, vreg_d, vtemp); break;
                        case 2: la_vadd_d(vreg_d, vreg_d, vtemp); break;
                    }
                }
            }
            break;
        case 0x5:  /* SABAL, SABAL2 */
        case 0x15: /* UABAL, UABAL2 — same as SABAL but unsigned (op_id = U<<4|opcode) */
            vreg_d = alloc_fpr_src(rd);
            if (size > 2) {
                lata_unallocated_encoding(s);
                return;
            }
            {
                /* Widen source elements.
                   SABAL (is_q=0): widen LOWER half → vilvl.
                   SABAL2 (is_q=1): widen UPPER half → vilvh. */
                IR2_OPND vn_w = ra_alloc_ftemp();
                IR2_OPND vm_w = ra_alloc_ftemp();
                if (is_u) {
                    if (size == 0) {
                        if (is_q) {
                            la_vilvh_b(vn_w, vzero, vreg_n);
                            la_vilvh_b(vm_w, vzero, vreg_m);
                        } else {
                            la_vilvl_b(vn_w, vzero, vreg_n);
                            la_vilvl_b(vm_w, vzero, vreg_m);
                        }
                    } else if (size == 1) {
                        if (is_q) {
                            la_vilvh_h(vn_w, vzero, vreg_n);
                            la_vilvh_h(vm_w, vzero, vreg_m);
                        } else {
                            la_vilvl_h(vn_w, vzero, vreg_n);
                            la_vilvl_h(vm_w, vzero, vreg_m);
                        }
                    } else {
                        if (is_q) {
                            la_vilvh_w(vn_w, vzero, vreg_n);
                            la_vilvh_w(vm_w, vzero, vreg_m);
                        } else {
                            la_vilvl_w(vn_w, vzero, vreg_n);
                            la_vilvl_w(vm_w, vzero, vreg_m);
                        }
                    }
                } else {
                    if (size == 0) {
                        if (is_q) {
                            la_vilvh_b(vn_w, vreg_n, vreg_n);
                            la_vilvh_b(vm_w, vreg_m, vreg_m);
                        } else {
                            la_vilvl_b(vn_w, vreg_n, vreg_n);
                            la_vilvl_b(vm_w, vreg_m, vreg_m);
                        }
                        la_vslli_h(vn_w, vn_w, 8);
                        la_vsrai_h(vn_w, vn_w, 8);
                        la_vslli_h(vm_w, vm_w, 8);
                        la_vsrai_h(vm_w, vm_w, 8);
                    } else if (size == 1) {
                        if (is_q) {
                            la_vilvh_h(vn_w, vreg_n, vreg_n);
                            la_vilvh_h(vm_w, vreg_m, vreg_m);
                        } else {
                            la_vilvl_h(vn_w, vreg_n, vreg_n);
                            la_vilvl_h(vm_w, vreg_m, vreg_m);
                        }
                        la_vslli_w(vn_w, vn_w, 16);
                        la_vsrai_w(vn_w, vn_w, 16);
                        la_vslli_w(vm_w, vm_w, 16);
                        la_vsrai_w(vm_w, vm_w, 16);
                    } else {
                        if (is_q) {
                            la_vilvh_w(vn_w, vreg_n, vreg_n);
                            la_vilvh_w(vm_w, vreg_m, vreg_m);
                        } else {
                            la_vilvl_w(vn_w, vreg_n, vreg_n);
                            la_vilvl_w(vm_w, vreg_m, vreg_m);
                        }
                        la_vslli_d(vn_w, vn_w, 32);
                        la_vsrai_d(vn_w, vn_w, 32);
                        la_vslli_d(vm_w, vm_w, 32);
                        la_vsrai_d(vm_w, vm_w, 32);
                    }
                }
                /* SABAL/UABAL: |Vn - Vm| (absolute difference of widened values) */
                if (is_u) {
                    if (size == 0)
                        la_vabsd_hu(vn_w, vn_w, vm_w);
                    else if (size == 1)
                        la_vabsd_wu(vn_w, vn_w, vm_w);
                    else
                        la_vabsd_du(vn_w, vn_w, vm_w);
                } else {
                    if (size == 0)
                        la_vabsd_h(vn_w, vn_w, vm_w);
                    else if (size == 1)
                        la_vabsd_w(vn_w, vn_w, vm_w);
                    else
                        la_vabsd_d(vn_w, vn_w, vm_w);
                }
                /* Accumulate into Vd. */
                if (is_q)
                    la_vadd_q(vreg_d, vreg_d, vn_w);
                else
                    la_vadd_d(vreg_d, vreg_d, vn_w);
                free_alloc_fpr(vn_w);
                free_alloc_fpr(vm_w);
            }
            break;
        case 0x8: /* SMLAL, SMLAL2 */
        case 0xa: /* SMLSL, SMLSL2 */
            vreg_d = alloc_fpr_src(rd);
            if (!is_q) {
                /* 低位统一移至偶数位后做偶数位的相乘并拓2倍宽 */
                switch (size) {
                    case 0:
                        la_vilvl_b(vtemp, vzero, vreg_n);
                        la_vilvl_b(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_h_b(vtemp, vtemp, vtemp1);
                            la_vsub_h(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_h_b(vreg_d, vtemp, vtemp1);
                        break;
                    case 1:
                        la_vilvl_h(vtemp, vzero, vreg_n);
                        la_vilvl_h(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_w_h(vtemp, vtemp, vtemp1);
                            la_vsub_w(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_w_h(vreg_d, vtemp, vtemp1);
                        break;
                    case 2:
                        la_vilvl_w(vtemp, vzero, vreg_n);
                        la_vilvl_w(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_d_w(vtemp, vtemp, vtemp1);
                            la_vsub_d(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_d_w(vreg_d, vtemp, vtemp1);
                        break;
                    case 3:
                        la_vilvl_d(vtemp, vzero, vreg_n);
                        la_vilvl_d(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_h_b(vtemp, vtemp, vtemp1);
                            la_vsub_q(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_q_d(vreg_d, vtemp, vtemp1);
                        break;
                    default:
                        lata_unallocated_encoding(s);
                        return;
                }
            } else {
                /* 高位统一移至偶数位后做偶数位的相乘并拓2倍宽 */
                switch (size) {
                    case 0:
                        la_vilvh_b(vtemp, vzero, vreg_n);
                        la_vilvh_b(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_h_b(vtemp, vtemp, vtemp1);
                            la_vsub_h(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_h_b(vreg_d, vtemp, vtemp1);
                        break;
                    case 1:
                        la_vilvh_h(vtemp, vzero, vreg_n);
                        la_vilvh_h(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_w_h(vtemp, vtemp, vtemp1);
                            la_vsub_w(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_w_h(vreg_d, vtemp, vtemp1);
                        break;
                    case 2:
                        la_vilvh_w(vtemp, vzero, vreg_n);
                        la_vilvh_w(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_d_w(vtemp, vtemp, vtemp1);
                            la_vsub_d(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_d_w(vreg_d, vtemp, vtemp1);
                        break;
                    case 3:
                        la_vilvh_d(vtemp, vzero, vreg_n);
                        la_vilvh_d(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_h_b(vtemp, vtemp, vtemp1);
                            la_vsub_q(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_q_d(vreg_d, vtemp, vtemp1);
                        break;
                    default:
                        assert(0);
                }
            }
            break;
        case 0xc: /* SMULL, SMULL2 */
            vreg_d = alloc_fpr_dst(rd);
            if (!is_q) {
                /* 低位统一移至偶数位后做偶数位的相乘并拓2倍宽 */
                switch (size) {
                    case 0:
                        la_vilvl_b(vtemp, vzero, vreg_n);
                        la_vilvl_b(vtemp1, vzero, vreg_m);
                        la_vmulwev_h_b(vreg_d, vtemp, vtemp1);
                        break;
                    case 1:
                        la_vilvl_h(vtemp, vzero, vreg_n);
                        la_vilvl_h(vtemp1, vzero, vreg_m);
                        la_vmulwev_w_h(vreg_d, vtemp, vtemp1);
                        break;
                    case 2:
                        la_vilvl_w(vtemp, vzero, vreg_n);
                        la_vilvl_w(vtemp1, vzero, vreg_m);
                        la_vmulwev_d_w(vreg_d, vtemp, vtemp1);
                        break;
                    case 3:
                        la_vilvl_d(vtemp, vzero, vreg_n);
                        la_vilvl_d(vtemp1, vzero, vreg_m);
                        la_vmulwev_q_d(vreg_d, vtemp, vtemp1);
                        break;
                    default:
                        assert(0);
                }
            } else {
                /* 高位统一移至偶数位后做偶数位的相乘并拓2倍宽 */
                switch (size) {
                    case 0:
                        la_vilvh_b(vtemp, vzero, vreg_n);
                        la_vilvh_b(vtemp1, vzero, vreg_m);
                        la_vmulwev_h_b(vreg_d, vtemp, vtemp1);
                        break;
                    case 1:
                        la_vilvh_h(vtemp, vzero, vreg_n);
                        la_vilvh_h(vtemp1, vzero, vreg_m);
                        la_vmulwev_w_h(vreg_d, vtemp, vtemp1);
                        break;
                    case 2:
                        la_vilvh_w(vtemp, vzero, vreg_n);
                        la_vilvh_w(vtemp1, vzero, vreg_m);
                        la_vmulwev_d_w(vreg_d, vtemp, vtemp1);
                        break;
                    case 3:
                        la_vilvh_d(vtemp, vzero, vreg_n);
                        la_vilvh_d(vtemp1, vzero, vreg_m);
                        la_vmulwev_q_d(vreg_d, vtemp, vtemp1);
                        break;
                    default:
                        assert(0);
                }
            }
            break;
        case 0x9: /* SQDMLAL, SQDMLAL2 */
            vreg_d = alloc_fpr_src(rd);
            if (!is_q) {
                switch (size) {
                    case 1:
                        la_vilvl_h(vtemp, vzero, vreg_n);
                        la_vilvl_h(vtemp1, vzero, vreg_m);
                        la_vmulwev_w_h(vzero, vtemp, vtemp1);
                        lata_helper_addl_saturate_s32(s, vzero, vzero, vzero, -1);
                        lata_helper_addl_saturate_s32(s, vreg_d, vreg_d, vzero, rd);
                        break;
                    case 2:
                        la_vilvl_w(vtemp, vzero, vreg_n);
                        la_vilvl_w(vtemp1, vzero, vreg_m);
                        la_vmulwev_d_w(vzero, vtemp, vtemp1);
                        lata_helper_addl_saturate_s64(s, vzero, vzero, vzero, -1);
                        lata_helper_addl_saturate_s64(s, vreg_d, vreg_d, vzero, rd);
                        break;
                    default:
                        assert(0);
                }

            } else {
                /* SQDMLAL2: high half widening saturating doubling multiply-accumulate */
                switch (size) {
                    case 1:
                        la_vilvh_h(vtemp, vzero, vreg_n);
                        la_vilvh_h(vtemp1, vzero, vreg_m);
                        la_vmulwev_w_h(vzero, vtemp, vtemp1);
                        lata_helper_addl_saturate_s32(s, vzero, vzero, vzero, -1);
                        lata_helper_addl_saturate_s32(s, vreg_d, vreg_d, vzero, rd);
                        break;
                    case 2:
                        la_vilvh_w(vtemp, vzero, vreg_n);
                        la_vilvh_w(vtemp1, vzero, vreg_m);
                        la_vmulwev_d_w(vzero, vtemp, vtemp1);
                        lata_helper_addl_saturate_s64(s, vzero, vzero, vzero, -1);
                        lata_helper_addl_saturate_s64(s, vreg_d, vreg_d, vzero, rd);
                        break;
                    default:
                        assert(0);
                }
            }
            break;
        case 0xb: /* SQDMLSL, SQDMLSL2 */
            vreg_d = alloc_fpr_src(rd);
            if (!is_q) {
                switch (size) {
                    case 1:
                        la_vilvl_h(vtemp, vzero, vreg_n);
                        la_vilvl_h(vtemp1, vzero, vreg_m);
                        la_vmulwev_w_h(vzero, vtemp, vtemp1);
                        lata_helper_addl_saturate_s32(s, vzero, vzero, vzero, -1);
                        // la_vsadd_w(vzero, vzero, vzero);
                        // gen_sat_q(vzero, 1, false);
                        la_vneg_w(vzero, vzero);
                        lata_helper_addl_saturate_s32(s, vreg_d, vreg_d, vzero, rd);
                        // la_vsadd_w(vreg_d, vreg_d, vzero);
                        // gen_sat_q(vreg_d, 1, false);
                        break;
                    case 2:
                        la_vilvl_w(vtemp, vzero, vreg_n);
                        la_vilvl_w(vtemp1, vzero, vreg_m);
                        la_vmulwev_d_w(vzero, vtemp, vtemp1);
                        lata_helper_addl_saturate_s64(s, vzero, vzero, vzero, -1);
                        // la_vsadd_d(vzero, vzero, vzero);
                        // gen_sat_q(vreg_d, 2, false);
                        la_vneg_d(vzero, vzero);
                        lata_helper_addl_saturate_s64(s, vreg_d, vreg_d, vzero, rd);
                        // la_vsadd_d(vreg_d, vreg_d, vzero);
                        // gen_sat_q(vreg_d, 2, false);
                        break;
                    default:
                        assert(0);
                }

            } else {
                /* SQDMLSL2: high half widening saturating doubling multiply-subtract */
                switch (size) {
                    case 1:
                        la_vilvh_h(vtemp, vzero, vreg_n);
                        la_vilvh_h(vtemp1, vzero, vreg_m);
                        la_vmulwev_w_h(vzero, vtemp, vtemp1);
                        lata_helper_addl_saturate_s32(s, vzero, vzero, vzero, -1);
                        la_vneg_w(vzero, vzero); /* subtract */
                        lata_helper_addl_saturate_s32(s, vreg_d, vreg_d, vzero, rd);
                        break;
                    case 2:
                        la_vilvh_w(vtemp, vzero, vreg_n);
                        la_vilvh_w(vtemp1, vzero, vreg_m);
                        la_vmulwev_d_w(vzero, vtemp, vtemp1);
                        lata_helper_addl_saturate_s64(s, vzero, vzero, vzero, -1);
                        la_vneg_d(vzero, vzero); /* subtract */
                        lata_helper_addl_saturate_s64(s, vreg_d, vreg_d, vzero, rd);
                        break;
                    default:
                        assert(0);
                }
            }
            break;
        case 0xd: /* SQDMULL, SQDMULL2 */
            vreg_d = alloc_fpr_dst(rd);
            /* SQDMULL (is_q=0): widen lower half → 4x32/2x64 result.
             * SQDMULL2 (is_q=1): widen upper half → 4x32/2x64 result.
             * Both produce 128-bit destination, no narrowing needed. */
            switch (size) {
                case 1:
                    if (is_q) {
                        la_vilvh_h(vtemp, vzero, vreg_n);
                        la_vilvh_h(vtemp1, vzero, vreg_m);
                    } else {
                        la_vilvl_h(vtemp, vzero, vreg_n);
                        la_vilvl_h(vtemp1, vzero, vreg_m);
                    }
                    la_vmulwev_w_h(vzero, vtemp, vtemp1);
                    lata_helper_addl_saturate_s32(s, vreg_d, vzero, vzero, rd);
                    break;
                case 2:
                    if (is_q) {
                        la_vilvh_w(vtemp, vzero, vreg_n);
                        la_vilvh_w(vtemp1, vzero, vreg_m);
                    } else {
                        la_vilvl_w(vtemp, vzero, vreg_n);
                        la_vilvl_w(vtemp1, vzero, vreg_m);
                    }
                    la_vmulwev_d_w(vzero, vtemp, vtemp1);
                    lata_helper_addl_saturate_s64(s, vzero, vzero, vzero, rd);
                    break;
                default:
                    assert(0);
            }
            break;
        case 0x10: /* UADDL, UADDL2 */
        case 0x12: /* USUBL, USUBL2 */
            vreg_d = alloc_fpr_dst(rd);
            if (!is_q) { /* 统一移到高位处理 */
                la_vbsll_v(vtemp, vreg_n, 8);
                la_vbsll_v(vtemp1, vreg_m, 8);
                switch (size) {
                    case 0:
                        /* 高位扩展 */
                        la_vexth_hu_bu(vtemp, vtemp);
                        la_vexth_hu_bu(vtemp1, vtemp1);
                        if (is_sub)
                            la_vsub_h(vreg_d, vtemp, vtemp1);
                        else
                            la_vadd_h(vreg_d, vtemp, vtemp1);
                        break;
                    case 1:
                        la_vexth_wu_hu(vtemp, vtemp);
                        la_vexth_wu_hu(vtemp1, vtemp1);
                        if (is_sub)
                            la_vsub_w(vreg_d, vtemp, vtemp1);
                        else
                            la_vadd_w(vreg_d, vtemp, vtemp1);
                        break;
                    case 2:
                        la_vexth_du_wu(vtemp, vtemp);
                        la_vexth_du_wu(vtemp1, vtemp1);
                        if (is_sub)
                            la_vsub_d(vreg_d, vtemp, vtemp1);
                        else
                            la_vadd_d(vreg_d, vtemp, vtemp1);
                        break;
                    case 3:
                        la_vexth_qu_du(vtemp, vtemp);
                        la_vexth_qu_du(vtemp1, vtemp1);
                        if (is_sub)
                            la_vsub_q(vreg_d, vtemp, vtemp1);
                        else
                            la_vadd_q(vreg_d, vtemp, vtemp1);
                        break;
                    default:
                        assert(0);
                }
            } else {
                switch (size) {
                    case 0:
                        /* 高位扩展 */
                        la_vexth_hu_bu(vtemp, vreg_n);
                        la_vexth_hu_bu(vtemp1, vreg_m);
                        if (is_sub)
                            la_vsub_h(vreg_d, vtemp, vtemp1);
                        else
                            la_vadd_h(vreg_d, vtemp, vtemp1);
                        break;
                    case 1:
                        la_vexth_wu_hu(vtemp, vreg_n);
                        la_vexth_wu_hu(vtemp1, vreg_m);
                        if (is_sub)
                            la_vsub_w(vreg_d, vtemp, vtemp1);
                        else
                            la_vadd_w(vreg_d, vtemp, vtemp1);
                        break;
                    case 2:
                        la_vexth_du_wu(vtemp, vreg_n);
                        la_vexth_du_wu(vtemp1, vreg_m);
                        if (is_sub)
                            la_vsub_d(vreg_d, vtemp, vtemp1);
                        else
                            la_vadd_d(vreg_d, vtemp, vtemp1);
                        break;
                    case 3:
                        la_vexth_qu_du(vtemp, vreg_n);
                        la_vexth_qu_du(vtemp1, vreg_m);
                        if (is_sub)
                            la_vsub_q(vreg_d, vtemp, vtemp1);
                        else
                            la_vadd_q(vreg_d, vtemp, vtemp1);
                        break;
                    default:
                        assert(0);
                }
            }

            break;
        /* case 0x17 handled above with case 0x7 */
        case 0x18: /* UMLAL, UMLAL2 */
        case 0x1a: /* UMLSL, UMLSL2 */
            vreg_d = alloc_fpr_src(rd);
            if (!is_q) {
                /* 低位统一移至偶数位后做偶数位的相乘并拓2倍宽 */
                switch (size) {
                    case 0:
                        la_vilvl_b(vtemp, vzero, vreg_n);
                        la_vilvl_b(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_h_bu(vtemp, vtemp, vtemp1);
                            la_vsub_h(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_h_bu(vreg_d, vtemp, vtemp1);
                        break;
                    case 1:
                        la_vilvl_h(vtemp, vzero, vreg_n);
                        la_vilvl_h(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_w_hu(vtemp, vtemp, vtemp1);
                            la_vsub_w(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_w_hu(vreg_d, vtemp, vtemp1);
                        break;
                    case 2:
                        la_vilvl_w(vtemp, vzero, vreg_n);
                        la_vilvl_w(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_d_wu(vtemp, vtemp, vtemp1);
                            la_vsub_d(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_d_wu(vreg_d, vtemp, vtemp1);
                        break;
                    case 3:
                        la_vilvl_d(vtemp, vzero, vreg_n);
                        la_vilvl_d(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_h_bu(vtemp, vtemp, vtemp1);
                            la_vsub_q(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_q_du(vreg_d, vtemp, vtemp1);
                        break;
                    default:
                        assert(0);
                }
            } else {
                /* 高位统一移至偶数位后做偶数位的相乘并拓2倍宽 */
                switch (size) {
                    case 0:
                        la_vilvh_b(vtemp, vzero, vreg_n);
                        la_vilvh_b(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_h_bu(vtemp, vtemp, vtemp1);
                            la_vsub_h(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_h_bu(vreg_d, vtemp, vtemp1);
                        break;
                    case 1:
                        la_vilvh_h(vtemp, vzero, vreg_n);
                        la_vilvh_h(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_w_hu(vtemp, vtemp, vtemp1);
                            la_vsub_w(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_w_hu(vreg_d, vtemp, vtemp1);
                        break;
                    case 2:
                        la_vilvh_w(vtemp, vzero, vreg_n);
                        la_vilvh_w(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_d_wu(vtemp, vtemp, vtemp1);
                            la_vsub_d(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_d_wu(vreg_d, vtemp, vtemp1);
                        break;
                    case 3:
                        la_vilvh_d(vtemp, vzero, vreg_n);
                        la_vilvh_d(vtemp1, vzero, vreg_m);
                        if (is_sub) {
                            la_vmulwev_h_bu(vtemp, vtemp, vtemp1);
                            la_vsub_q(vreg_d, vreg_d, vtemp);
                        } else
                            la_vmaddwev_q_du(vreg_d, vtemp, vtemp1);
                        break;
                    default:
                        assert(0);
                }
            }

            break;
        case 0x1c: /* UMULL, UMULL2 */
            vreg_d = alloc_fpr_dst(rd);
            if (!is_q) {
                /* 低位统一移至偶数位后做偶数位的相乘并拓2倍宽 */
                switch (size) {
                    case 0:
                        la_vilvl_b(vtemp, vzero, vreg_n);
                        la_vilvl_b(vtemp1, vzero, vreg_m);
                        la_vmulwev_h_bu(vreg_d, vtemp, vtemp1);
                        break;
                    case 1:
                        la_vilvl_h(vtemp, vzero, vreg_n);
                        la_vilvl_h(vtemp1, vzero, vreg_m);
                        la_vmulwev_w_hu(vreg_d, vtemp, vtemp1);
                        break;
                    case 2:
                        la_vilvl_w(vtemp, vzero, vreg_n);
                        la_vilvl_w(vtemp1, vzero, vreg_m);
                        la_vmulwev_d_wu(vreg_d, vtemp, vtemp1);
                        break;
                    case 3:
                        la_vilvl_d(vtemp, vzero, vreg_n);
                        la_vilvl_d(vtemp1, vzero, vreg_m);
                        la_vmulwev_q_du(vreg_d, vtemp, vtemp1);
                        break;
                    default:
                        assert(0);
                }
            } else {
                /* 高位统一移至偶数位后做偶数位的相乘并拓2倍宽 */
                switch (size) {
                    case 0:
                        la_vilvh_b(vtemp, vzero, vreg_n);
                        la_vilvh_b(vtemp1, vzero, vreg_m);
                        la_vmulwev_h_bu(vreg_d, vtemp, vtemp1);
                        break;
                    case 1:
                        la_vilvh_h(vtemp, vzero, vreg_n);
                        la_vilvh_h(vtemp1, vzero, vreg_m);
                        la_vmulwev_w_hu(vreg_d, vtemp, vtemp1);
                        break;
                    case 2:
                        la_vilvh_w(vtemp, vzero, vreg_n);
                        la_vilvh_w(vtemp1, vzero, vreg_m);
                        la_vmulwev_d_wu(vreg_d, vtemp, vtemp1);
                        break;
                    case 3:
                        la_vilvh_d(vtemp, vzero, vreg_n);
                        la_vilvh_d(vtemp1, vzero, vreg_m);
                        la_vmulwev_q_du(vreg_d, vtemp, vtemp1);
                        break;
                    default:
                        assert(0);
                }
            }

            break;
        default:
            g_assert_not_reached();
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp1);
    free_alloc_fpr(vzero);
}

static void handle_3rd_wide(DisasContext* s, int is_q, int is_u, int size,
    int opcode, int rd, int rn, int rm)
{
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vtemp = ra_alloc_ftemp();
    int is_sub = extract32(opcode, 1, 1);

    /* 统一移到高位处理*/
    if (!is_q) {
        la_vbsll_v(vtemp, vreg_m, 8);
    } else {
        la_vbsll_v(vtemp, vreg_m, 0);
    }

    /* SSUBW/SSUBW2 */
    if (!is_u) {
        switch (size) {
            case 0:
                /* 高位扩展 */
                la_vexth_h_b(vtemp, vtemp);
                if (is_sub)
                    la_vsub_h(vreg_d, vreg_n, vtemp);
                else
                    la_vadd_h(vreg_d, vreg_n, vtemp);
                break;
            case 1:
                la_vexth_w_h(vtemp, vtemp);
                if (is_sub)
                    la_vsub_w(vreg_d, vreg_n, vtemp);
                else
                    la_vadd_w(vreg_d, vreg_n, vtemp);
                break;
            case 2:
                la_vexth_d_w(vtemp, vtemp);
                if (is_sub)
                    la_vsub_d(vreg_d, vreg_n, vtemp);
                else
                    la_vadd_d(vreg_d, vreg_n, vtemp);
                break;
            case 3:
                la_vexth_q_d(vtemp, vtemp);
                if (is_sub)
                    la_vsub_q(vreg_d, vreg_n, vtemp);
                else
                    la_vadd_q(vreg_d, vreg_n, vtemp);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
        }
    }
    /* USUBW/USUBW2 */
    else {
        switch (size) {
            case 0:
                /* 高位扩展 */
                la_vexth_hu_bu(vtemp, vtemp);
                if (is_sub)
                    la_vsub_h(vreg_d, vreg_n, vtemp);
                else
                    la_vadd_h(vreg_d, vreg_n, vtemp);
                break;
            case 1:
                la_vexth_wu_hu(vtemp, vtemp);
                if (is_sub)
                    la_vsub_w(vreg_d, vreg_n, vtemp);
                else
                    la_vadd_w(vreg_d, vreg_n, vtemp);
                break;
            case 2:
                la_vexth_du_wu(vtemp, vtemp);
                if (is_sub)
                    la_vsub_d(vreg_d, vreg_n, vtemp);
                else
                    la_vadd_d(vreg_d, vreg_n, vtemp);
                break;
            case 3:
                la_vexth_qu_du(vtemp, vtemp);
                if (is_sub)
                    la_vsub_q(vreg_d, vreg_n, vtemp);
                else
                    la_vadd_q(vreg_d, vreg_n, vtemp);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
        }
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
    free_alloc_fpr(vtemp);
}

/* ADDHN, ADDHN2, RADDHN, RADDHN2  SUBHN, SUBHN2, RSUBHN, RSUBHN2 */
static void handle_3rd_narrowing(DisasContext* s, int is_q, int is_u, int size,
    int opcode, int rd, int rn, int rm)
{
    IR2_OPND vreg_d = alloc_fpr_src(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vtemp = ra_alloc_ftemp();
    int is_sub = extract32(opcode, 1, 1);

    switch (size) {
        case 0:
            if (is_sub)
                la_vsub_h(vtemp, vreg_n, vreg_m);
            else
                la_vadd_h(vtemp, vreg_n, vreg_m);
            break;
        case 1:
            if (is_sub)
                la_vsub_w(vtemp, vreg_n, vreg_m);
            else
                la_vadd_w(vtemp, vreg_n, vreg_m);
            break;
        case 2:
            if (is_sub)
                la_vsub_d(vtemp, vreg_n, vreg_m);
            else
                la_vadd_d(vtemp, vreg_n, vreg_m);
            break;
        default:
            lata_unallocated_encoding(s);
            return;
    }

    if (is_u) { /* RADDHN, RADDHN2, RSUBHN, RSUBHN2 */
        switch (size) {
            case 0:
                la_vsrlri_h(vtemp, vtemp, 8);
                break;
            case 1:
                la_vsrlri_w(vtemp, vtemp, 16);
                break;
            case 2:
                la_vsrlri_d(vtemp, vtemp, 32);
                break;
            default:
                break;
        }
    } else { /* ADDHN, ADDHN2, SUBHN, SUBHN2 */
        switch (size) {
            case 0:
                la_vsrli_h(vtemp, vtemp, 8);
                break;
            case 1:
                la_vsrli_w(vtemp, vtemp, 16);
                break;
            case 2:
                la_vsrli_d(vtemp, vtemp, 32);
                break;
            default:
                break;
        }
    }

    if (is_q) { /* store in uppper*/
        switch (size) {
            case 0:
                la_vpickev_b(vtemp, vtemp, vtemp);
                break;
            case 1:
                la_vpickev_h(vtemp, vtemp, vtemp);
                break;
            case 2:
                la_vpickev_w(vtemp, vtemp, vtemp);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
        }
        la_vpickev_d(vreg_d, vtemp, vreg_d);
    } else {
        switch (size) {
            case 0:
                la_vpickev_b(vreg_d, vtemp, vtemp);
                break;
            case 1:
                la_vpickev_h(vreg_d, vtemp, vtemp);
                break;
            case 2:
                la_vpickev_w(vreg_d, vtemp, vtemp);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
        }
    }

    if (!is_q) {
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
    free_alloc_fpr(vtemp);
}

/* AdvSIMD three different
 *   31  30  29 28       24 23  22  21 20  16 15    12 11 10 9    5 4    0
 * +---+---+---+-----------+------+---+------+--------+-----+------+------+
 * | 0 | Q | U | 0 1 1 1 0 | size | 1 |  Rm  | opcode | 0 0 |  Rn  |  Rd  |
 * +---+---+---+-----------+------+---+------+--------+-----+------+------+
 */
static void disas_simd_three_reg_diff(DisasContext* s, uint32_t insn)
{
    /* Instructions in this group fall into three basic classes
     * (in each case with the operation working on each element in
     * the input vectors):
     * (1) widening 64 x 64 -> 128 (with possibly Vd as an extra
     *     128 bit input)
     * (2) wide 64 x 128 -> 128
     * (3) narrowing 128 x 128 -> 64
     * Here we do initial decode, catch unallocated cases and
     * dispatch to separate functions for each class.
     */
    int is_q = extract32(insn, 30, 1);
    int is_u = extract32(insn, 29, 1);
    int size = extract32(insn, 22, 2);
    int opcode = extract32(insn, 12, 4);
    int rm = extract32(insn, 16, 5);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);

    switch (opcode) {
        case 1: /* SADDW, SADDW2, UADDW, UADDW2 */
        case 3: /* SSUBW, SSUBW2, USUBW, USUBW2 */
            /* 64 x 128 -> 128 */
            if (size == 3) {
                lata_unallocated_encoding(s);
                return;
            }
            if (!fp_access_check(s)) {
                return;
            }
            handle_3rd_wide(s, is_q, is_u, size, opcode, rd, rn, rm);
            break;
        case 4: /* ADDHN, ADDHN2, RADDHN, RADDHN2 */
        case 6: /* SUBHN, SUBHN2, RSUBHN, RSUBHN2 */
            /* 128 x 128 -> 64 */
            if (size == 3) {
                lata_unallocated_encoding(s);
                return;
            }
            if (!fp_access_check(s)) {
                return;
            }
            handle_3rd_narrowing(s, is_q, is_u, size, opcode, rd, rn, rm);
            break;
        case 14: /* PMULL, PMULL2 */
            if (is_u) {
                lata_unallocated_encoding(s);
                return;
            }
            switch (size) {
                case 0: /* PMULL.P8 — poly multiply 8b→16b, shift-XOR loop */
                    if (!fp_access_check(s)) { return; }
                    {
                        IR2_OPND vreg_d = alloc_fpr_dst(rd);
                        IR2_OPND vreg_n_fpr = alloc_fpr_src(rn);
                        IR2_OPND vreg_m_fpr = alloc_fpr_src(rm);
                        IR2_OPND vzero = ra_alloc_ftemp();
                        IR2_OPND vawide = ra_alloc_ftemp();
                        IR2_OPND vbwide = ra_alloc_ftemp();
                        IR2_OPND vmask = ra_alloc_ftemp();
                        IR2_OPND vsel = ra_alloc_ftemp();
                        IR2_OPND vtmp = ra_alloc_ftemp();
                        IR2_OPND ctr = ra_alloc_itemp();
                        IR2_OPND loop = ir2_opnd_new_type(IR2_OPND_LABEL);
                        la_vxor_v(vzero, vzero, vzero);
                        /* PMULL always writes eight widened halfword products.
                         * Q selects which 64-bit half of each input is used:
                         * low half for PMULL, high half for PMULL2. */
                        if (is_q) {
                            la_vilvh_b(vawide, vzero, vreg_n_fpr);
                            la_vilvh_b(vbwide, vzero, vreg_m_fpr);
                        } else {
                            la_vilvl_b(vawide, vzero, vreg_n_fpr);
                            la_vilvl_b(vbwide, vzero, vreg_m_fpr);
                        }
                        la_vxor_v(vreg_d, vreg_d, vreg_d);
                        /* vldi 0x401: broadcast 1 as 16-bit elements */
                        la_vldi(vmask, 0x401);
                        la_addi_w(ctr, zero_ir2_opnd, 8);
                        la_label(loop);
                        la_vand_v(vtmp, vbwide, vmask);
                        la_vseq_h(vtmp, vtmp, vmask);
                        la_vxor_v(vsel, vreg_d, vawide);
                        /* vbitsel: match dynarmic order exactly */
                        la_vbitsel_v(vreg_d, vreg_d, vsel, vtmp);
                        la_vslli_h(vmask, vmask, 1);
                        la_vslli_h(vawide, vawide, 1);
                        la_addi_w(ctr, ctr, -1);
                        la_bnez(ctr, loop);
                        store_fpr_dst(rd, vreg_d);
                        free_alloc_fpr(vreg_d);
                        free_alloc_fpr(vreg_n_fpr);
                        free_alloc_fpr(vreg_m_fpr);
                        free_alloc_fpr(vzero);
                        free_alloc_fpr(vawide);
                        free_alloc_fpr(vbwide);
                        free_alloc_fpr(vmask);
                        free_alloc_fpr(vsel);
                        free_alloc_fpr(vtmp);
                        free_alloc_gpr(ctr);
                    }
                    return;

                case 3: /* PMULL.P64 */
                    if (!dc_isar_feature(aa64_pmull, s)) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    if (!fp_access_check(s)) {
                        return;
                    }
                    lata_unallocated_encoding(s);
                    return;
                    break;

                default:
                    lata_unallocated_encoding(s);
                    break;
            }
            return;
        case 9:  /* SQDMLAL, SQDMLAL2 */
        case 11: /* SQDMLSL, SQDMLSL2 */
        case 13: /* SQDMULL, SQDMULL2 */
            if (is_u || size == 0) {
                lata_unallocated_encoding(s);
                return;
            }
            /* fall through */
        case 0:  /* SADDL, SADDL2, UADDL, UADDL2 */
        case 2:  /* SSUBL, SSUBL2, USUBL, USUBL2 */
        case 5:  /* SABAL, SABAL2, UABAL, UABAL2 */
        case 7:  /* SABDL, SABDL2, UABDL, UABDL2 */
        case 8:  /* SMLAL, SMLAL2, UMLAL, UMLAL2 */
        case 10: /* SMLSL, SMLSL2, UMLSL, UMLSL2 */
        case 12: /* SMULL, SMULL2, UMULL, UMULL2 */
            /* 64 x 64 -> 128 */
            if (size == 3) {
                lata_unallocated_encoding(s);
                return;
            }
            if (!fp_access_check(s)) {
                return;
            }

            handle_3rd_widening(s, is_q, is_u, size, opcode, rd, rn, rm);
            break;
        default:
            /* opcode 15 not allocated */
            lata_unallocated_encoding(s);
            break;
    }
}

/* Logic op (opcode == 3) subgroup of C3.6.16. */
static void disas_simd_3same_logic(DisasContext* s, uint32_t insn)
{
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int rm = extract32(insn, 16, 5);
    int size = extract32(insn, 22, 2);
    bool is_u = extract32(insn, 29, 1);
    bool is_q = extract32(insn, 30, 1);

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_src(rd); // BSL, BIT, BIF结果受到目的寄存器影响
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vtemp = ra_alloc_ftemp();

    switch (size + 4 * is_u) {
        case 0: /* AND */
            la_vand_v(vreg_d, vreg_n, vreg_m);
            break;
        case 1: /* BIC */
            /*  vandn.v vd, vj, vk :
                vr[vd] = ~vr[vj] & vr[vk]
                LA先对第一个寄存器取反再相与，ARM先对第二个寄存器取反再相与;
            */
            la_vandn_v(vreg_d, vreg_m, vreg_n);
            break;
        case 2: /* ORR */
            la_vor_v(vreg_d, vreg_n, vreg_m);
            break;
        case 3: /* ORN */
            la_vorn_v(vreg_d, vreg_n, vreg_m);
            break;
        case 4: /* EOR */
            la_vxor_v(vreg_d, vreg_n, vreg_m);
            break;

        case 5: /* BSL bitwise select */
            la_vxor_v(vtemp, vreg_m, vreg_n);
            la_vand_v(vtemp, vtemp, vreg_d);
            la_vxor_v(vreg_d, vreg_m, vtemp);
            break;
        case 6: /* BIT, bitwise insert if true */
            la_vxor_v(vtemp, vreg_d, vreg_n);
            la_vand_v(vtemp, vtemp, vreg_m);
            la_vxor_v(vreg_d, vreg_d, vtemp);
            break;
        case 7: /* BIF, bitwise insert if false */
            la_vxor_v(vtemp, vreg_d, vreg_n);
            la_vandn_v(vtemp, vreg_m, vtemp);
            la_vxor_v(vreg_d, vreg_d, vtemp);
            break;

        default:
            g_assert_not_reached();
    }

    if (!is_q) {
        /* 高64位清零 */
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }
    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
    free_alloc_fpr(vtemp);
}

/* Pairwise op subgroup of C3.6.16.
 *
 * This is called directly or via the handle_3same_float for float pairwise
 * operations where the opcode and size are calculated differently.
 */
static void handle_simd_3same_pair(DisasContext* s, int is_q, int u, int opcode,
    int size, int rn, int rm, int rd)
{
    // if(!is_q){
    //     assert(0);
    // }

    if (!fp_access_check(s)) {
        return;
    }

    /* These operations work on the concatenated rm:rn, with each pair of
     * adjacent elements being operated on to produce an element in the result.
     */
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp1 = ra_alloc_ftemp();

    switch (opcode) {
        case 0x17: /* ADDP */
        {
            switch (size) {
                case 0:
                    la_vpickev_b(vtemp, vreg_m, vreg_n);
                    la_vpickod_b(vtemp1, vreg_m, vreg_n);
                    la_vadd_b(vreg_d, vtemp, vtemp1);
                    break;
                case 1:
                    la_vpickev_h(vtemp, vreg_m, vreg_n);
                    la_vpickod_h(vtemp1, vreg_m, vreg_n);
                    la_vadd_h(vreg_d, vtemp, vtemp1);
                    break;
                case 2:
                    la_vpickev_w(vtemp, vreg_m, vreg_n);
                    la_vpickod_w(vtemp1, vreg_m, vreg_n);
                    la_vadd_w(vreg_d, vtemp, vtemp1);
                    break;
                case 3:
                    la_vpickev_d(vtemp, vreg_m, vreg_n);
                    la_vpickod_d(vtemp1, vreg_m, vreg_n);
                    la_vadd_d(vreg_d, vtemp, vtemp1);
                    break;
                default:
                    lata_unallocated_encoding(s);
                    return;
            }

            if (!is_q) {
                la_vpickev_w(vreg_d, vreg_d, vreg_d);
            }

            break;
        }
        case 0x14: /* SMAXP, UMAXP */
        {
            switch (size) {
                case 0:
                    /* pack vector pair*/
                    la_vpickev_b(vtemp, vreg_m, vreg_n);
                    la_vpickod_b(vtemp1, vreg_m, vreg_n);

                    /* compare*/
                    if (u) { // UMAXP
                        la_vmax_bu(vreg_d, vtemp, vtemp1);
                    } else { // SMAXP
                        la_vmax_b(vreg_d, vtemp, vtemp1);
                    }
                    break;
                case 1:
                    la_vpickev_h(vtemp, vreg_m, vreg_n);
                    la_vpickod_h(vtemp1, vreg_m, vreg_n);

                    if (u) {
                        la_vmax_hu(vreg_d, vtemp, vtemp1);
                    } else {
                        la_vmax_h(vreg_d, vtemp, vtemp1);
                    }
                    break;
                case 2:
                    la_vpickev_w(vtemp, vreg_m, vreg_n);
                    la_vpickod_w(vtemp1, vreg_m, vreg_n);

                    if (u) {
                        la_vmax_wu(vreg_d, vtemp, vtemp1);
                    } else {
                        la_vmax_w(vreg_d, vtemp, vtemp1);
                    }
                    break;
                default:
                    assert(0);
            }

            /* move vector to the lower*/
            if (!is_q) {
                la_vpickev_w(vreg_d, vreg_d, vreg_d);
            }
            break;
        }
        case 0x15: /* SMINP, UMINP */
        {
            switch (size) {
                case 0:
                    /* pack vector pair*/
                    la_vpickev_b(vtemp, vreg_m, vreg_n);
                    la_vpickod_b(vtemp1, vreg_m, vreg_n);

                    /* compare*/
                    if (u) { // UMINP
                        la_vmin_bu(vreg_d, vtemp, vtemp1);
                    } else { // SMINP
                        la_vmin_b(vreg_d, vtemp, vtemp1);
                    }
                    break;
                case 1:
                    la_vpickev_h(vtemp, vreg_m, vreg_n);
                    la_vpickod_h(vtemp1, vreg_m, vreg_n);

                    if (u) {
                        la_vmin_hu(vreg_d, vtemp, vtemp1);
                    } else {
                        la_vmin_h(vreg_d, vtemp, vtemp1);
                    }
                    break;
                case 2:
                    la_vpickev_w(vtemp, vreg_m, vreg_n);
                    la_vpickod_w(vtemp1, vreg_m, vreg_n);

                    if (u) {
                        la_vmin_wu(vreg_d, vtemp, vtemp1);
                    } else {
                        la_vmin_w(vreg_d, vtemp, vtemp1);
                    }
                    break;
                default:
                    assert(0);
            }

            /* move vector to the lower*/
            if (!is_q) {
                la_vpickev_w(vreg_d, vreg_d, vreg_d);
            }
            break;
        }
        /* The FP operations are all on single floats (32 bit) */
        case 0x58: /* FMAXNMP — pairwise float maxnum */
        case 0x5e: /* FMAXP — pairwise float max */
        case 0x78: /* FMINNMP — pairwise float minnum */
        case 0x7e: /* FMINP — pairwise float min */
            if (size == 2) {
                la_vpickev_w(vtemp, vreg_m, vreg_n);
                la_vpickod_w(vtemp1, vreg_m, vreg_n);
                if (opcode == 0x5e || opcode == 0x58) {
                    la_vfmax_s(vreg_d, vtemp, vtemp1);
                } else if (opcode == 0x7e) {
                    /* FMINP: NaN-propagating min */
                    IR2_OPND nan_res = ra_alloc_ftemp();
                    IR2_OPND vmask = ra_alloc_ftemp();
                    la_vfcmp_cond_s(vmask, vtemp, vtemp1, FCMP_COND_CUN);
                    la_vfadd_s(nan_res, vtemp, vtemp1);
                    la_vfmin_s(vreg_d, vtemp, vtemp1);
                    la_vbitsel_v(vreg_d, vreg_d, nan_res, vmask);
                    free_alloc_fpr(nan_res);
                    free_alloc_fpr(vmask);
                } else {
                    /* FMINNMP: NaN-ignoring min */
                    la_vfmin_s(vreg_d, vtemp, vtemp1);
                }
            } else if (size == 3) {
                la_vpickev_d(vtemp, vreg_m, vreg_n);
                la_vpickod_d(vtemp1, vreg_m, vreg_n);
                if (opcode == 0x5e || opcode == 0x58) {
                    la_vfmax_d(vreg_d, vtemp, vtemp1);
                } else if (opcode == 0x7e) {
                    /* FMINP: NaN-propagating min */
                    IR2_OPND nan_res = ra_alloc_ftemp();
                    IR2_OPND vmask = ra_alloc_ftemp();
                    la_vfcmp_cond_d(vmask, vtemp, vtemp1, FCMP_COND_CUN);
                    la_vfadd_d(nan_res, vtemp, vtemp1);
                    la_vfmin_d(vreg_d, vtemp, vtemp1);
                    la_vbitsel_v(vreg_d, vreg_d, nan_res, vmask);
                    free_alloc_fpr(nan_res);
                    free_alloc_fpr(vmask);
                } else {
                    /* FMINNMP: NaN-ignoring min */
                    la_vfmin_d(vreg_d, vtemp, vtemp1);
                }
            } else {
                assert(0);
            }
            if (!is_q) la_vpickev_w(vreg_d, vreg_d, vreg_d);
            break;
        case 0x5a: /* FADDP */
            switch (size) {
                case 2:
                    la_vpickev_w(vtemp, vreg_m, vreg_n);
                    la_vpickod_w(vtemp1, vreg_m, vreg_n);
                    la_vfadd_s(vreg_d, vtemp, vtemp1);
                    break;
                case 3:
                    la_vpickev_d(vtemp, vreg_m, vreg_n);
                    la_vpickod_d(vtemp1, vreg_m, vreg_n);
                    la_vfadd_d(vreg_d, vtemp, vtemp1);
                    break;
                default:
                    assert(0);
            }

            if (!is_q) {
                la_vpickev_w(vreg_d, vreg_d, vreg_d);
            }

            break;
        default:
            g_assert_not_reached();
    }

    if (!is_q) {
        /* 高64位清零 */
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp1);
}

/* Floating point op subgroup of C3.6.16. */
static void disas_simd_3same_float(DisasContext* s, uint32_t insn)
{
    /* For floating point ops, the U, size[1] and opcode bits
     * together indicate the operation. size[0] indicates single
     * or double.
     */
    int fpopcode = extract32(insn, 11, 5) | (extract32(insn, 23, 1) << 5) | (extract32(insn, 29, 1) << 6);
    int is_q = extract32(insn, 30, 1);
    int size = extract32(insn, 22, 1);
    int rm = extract32(insn, 16, 5);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);

    int datasize = is_q ? 128 : 64;
    int esize = 32 << size;
    int elements = datasize / esize;

    if (size == 1 && !is_q) {
        lata_unallocated_encoding(s);
        return;
    }

    switch (fpopcode) {
        case 0x58: /* FMAXNMP */
        case 0x5a: /* FADDP */
        case 0x5e: /* FMAXP */
        case 0x78: /* FMINNMP */
        case 0x7e: /* FMINP */
            if (size && !is_q) {
                lata_unallocated_encoding(s);
                return;
            }
            handle_simd_3same_pair(s, is_q, 0, fpopcode, size ? MO_64 : MO_32,
                rn, rm, rd);
            return;
        case 0x1b: /* FMULX */
        case 0x1f: /* FRECPS */
        case 0x3f: /* FRSQRTS */
        case 0x5d: /* FACGE */
        case 0x7d: /* FACGT */
        case 0x19: /* FMLA */
        case 0x39: /* FMLS */
        case 0x18: /* FMAXNM */
        case 0x1a: /* FADD */
        case 0x1c: /* FCMEQ */
        case 0x1e: /* FMAX */
        case 0x38: /* FMINNM */
        case 0x3a: /* FSUB */
        case 0x3e: /* FMIN */
        case 0x5b: /* FMUL */
        case 0x5c: /* FCMGE */
        case 0x5f: /* FDIV */
        case 0x7a: /* FABD */
        case 0x7c: /* FCMGT */
            if (!fp_access_check(s)) {
                return;
            }
            handle_3same_float(s, size, elements, fpopcode, rd, rn, rm);
            return;

        case 0x1d: /* FMLAL  */
        case 0x3d: /* FMLSL  */
        case 0x59: /* FMLAL2 */
        case 0x79: /* FMLSL2 */
            if (size & 1 || !dc_isar_feature(aa64_fhm, s)) {
                lata_unallocated_encoding(s);
                return;
            }
            if (fp_access_check(s)) {
                lata_unallocated_encoding(s);
                return;
            }
            return;

        default:
            lata_unallocated_encoding(s);
            return;
    }
}

static void gen_sqdmulh_vec_q(IR2_OPND vd, IR2_OPND vn, IR2_OPND vm,
    IR2_OPND even, IR2_OPND odd, IR2_OPND tmp, int size, bool rounding)
{
    switch (size) {
        case 1:
            la_vmulwev_w_h(even, vn, vm);
            la_vmulwod_w_h(odd, vn, vm);
            la_vsadd_w(even, even, even);
            la_vsadd_w(odd, odd, odd);
            la_vori_b(tmp, even, 0);
            if (rounding)
                la_vssrarni_h_w(tmp, odd, 16);
            else
                la_vssrani_h_w(tmp, odd, 16);
            la_vori_b(even, tmp, 0);
            la_vshuf4i_d(even, even, 0x01);
            la_vilvl_h(vd, tmp, even);
            break;
        case 2:
            la_vmulwev_d_w(even, vn, vm);
            la_vmulwod_d_w(odd, vn, vm);
            la_vsadd_d(even, even, even);
            la_vsadd_d(odd, odd, odd);
            la_vori_b(tmp, even, 0);
            if (rounding)
                la_vssrarni_w_d(tmp, odd, 32);
            else
                la_vssrani_w_d(tmp, odd, 32);
            la_vori_b(even, tmp, 0);
            la_vshuf4i_d(even, even, 0x01);
            la_vilvl_w(vd, tmp, even);
            break;
        default:
            assert(0);
    }
}

/* Integer op subgroup of C3.6.16. */
static void disas_simd_3same_int(DisasContext* s, uint32_t insn)
{
    int is_q = extract32(insn, 30, 1);
    int u = extract32(insn, 29, 1);
    int size = extract32(insn, 22, 2);
    int opcode = extract32(insn, 11, 5);
    int rm = extract32(insn, 16, 5);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);

    switch (opcode) {
        case 0x13: /* MUL, PMUL */
            if (u && size != 0) {
                lata_unallocated_encoding(s);
                return;
            }
            /* fall through */
        case 0x0:  /* SHADD, UHADD */
        case 0x2:  /* SRHADD, URHADD */
        case 0x4:  /* SHSUB, UHSUB */
        case 0xc:  /* SMAX, UMAX */
        case 0xd:  /* SMIN, UMIN */
        case 0xe:  /* SABD, UABD */
        case 0xf:  /* SABA, UABA */
        case 0x12: /* MLA, MLS */
            if (size == 3) {
                lata_unallocated_encoding(s);
                return;
            }
            break;
        case 0x16: /* SQDMULH, SQRDMULH */
            if (size == 0 || size == 3) {
                lata_unallocated_encoding(s);
                return;
            }
            break;
        default:
            if (size == 3 && !is_q) {
                lata_unallocated_encoding(s);
                return;
            }
            break;
    }

    if (!fp_access_check(s)) {
        return;
    }

    if (size == 3 && (opcode == 0x09 || opcode == 0x0b || opcode == 0x0a)) {
        handle_3same_64(s, opcode, u, rd, rn, rm);
        return;
    }

    IR2_OPND vreg_d;
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    if (opcode == 0x12) {
        vreg_d = alloc_fpr_src(rd);
    } else {
        vreg_d = alloc_fpr_dst(rd);
    }
    /* 分别执行左移和右移 */
    IR2_OPND vtemp, vleft, vright, vtemp1, vzero;
    IR2_OPND set_qc, exit;
    IR2_OPND temp;
    if (opcode == 0x08) {
        vtemp = ra_alloc_ftemp();
        vleft = ra_alloc_ftemp();
        vright = ra_alloc_ftemp();
    } else if (opcode == 0x16) {
        vtemp = ra_alloc_ftemp();
        vtemp1 = ra_alloc_ftemp();
        vzero = ra_alloc_ftemp();
        la_vandi_b(vzero, vzero, 0);
    } else if (opcode == 0x09 || opcode == 0x0b || opcode == 0x0a) {
        vtemp = ra_alloc_ftemp();
        vtemp1 = ra_alloc_ftemp();
        vzero = ra_alloc_ftemp();
        vleft = ra_alloc_ftemp();
        vright = ra_alloc_ftemp();
        la_vxor_v(vzero, vzero, vzero);
    } else if (opcode == 0x05) {
        vtemp = ra_alloc_ftemp();
        vtemp1 = ra_alloc_ftemp();
        temp = ra_alloc_itemp();
        set_qc = ir2_opnd_new_type(IR2_OPND_LABEL);
        exit = ir2_opnd_new_type(IR2_OPND_LABEL);
    }

    switch (opcode) {
        case 0x01: /* SQADD, UQADD */
            if (u) {
                switch (size) {
                    case 0: la_vsadd_bu(vreg_d, vreg_n, vreg_m); break;
                    case 1: la_vsadd_hu(vreg_d, vreg_n, vreg_m); break;
                    case 2: la_vsadd_wu(vreg_d, vreg_n, vreg_m); break;
                    case 3: la_vsadd_du(vreg_d, vreg_n, vreg_m); break;
                }
            } else {
                switch (size) {
                    case 0: la_vsadd_b(vreg_d, vreg_n, vreg_m); break;
                    case 1: la_vsadd_h(vreg_d, vreg_n, vreg_m); break;
                    case 2: la_vsadd_w(vreg_d, vreg_n, vreg_m); break;
                    case 3: la_vsadd_d(vreg_d, vreg_n, vreg_m); break;
                }
            }
            goto do_gvec_end;
        case 0x05: /* SQSUB, UQSUB */
            if (u) {
                switch (size) {
                    case 0:
                        la_vssub_bu(vtemp1, vreg_n, vreg_m);
                        la_vsub_b(vtemp, vreg_n, vreg_m);
                        break;
                    case 1:
                        la_vssub_hu(vtemp1, vreg_n, vreg_m);
                        la_vsub_h(vtemp, vreg_n, vreg_m);
                        break;
                    case 2:
                        la_vssub_wu(vtemp1, vreg_n, vreg_m);
                        la_vsub_w(vtemp, vreg_n, vreg_m);
                        break;
                    case 3:
                        la_vssub_du(vtemp1, vreg_n, vreg_m);
                        la_vsub_d(vtemp, vreg_n, vreg_m);
                        break;
                    default:
                        assert(0);
                }
            } else {
                switch (size) {
                    case 0:
                        la_vssub_b(vtemp1, vreg_n, vreg_m);
                        la_vsub_b(vtemp, vreg_n, vreg_m);
                        break;
                    case 1:
                        la_vssub_h(vtemp1, vreg_n, vreg_m);
                        la_vsub_h(vtemp, vreg_n, vreg_m);
                        break;
                    case 2:
                        la_vssub_w(vtemp1, vreg_n, vreg_m);
                        la_vsub_w(vtemp, vreg_n, vreg_m);
                        break;
                    case 3:
                        la_vssub_d(vtemp1, vreg_n, vreg_m);
                        la_vsub_d(vtemp, vreg_n, vreg_m);
                        break;
                    default:
                        assert(0);
                }
            }
            la_vseq_d(vtemp, vtemp1, vtemp);
            la_vsetanyeqz_b(fcc1_ir2_opnd, vtemp);
            la_bcnez(fcc1_ir2_opnd, set_qc);
            la_b(exit);

            la_label(set_qc);
            li_d(temp, 1);
            la_st_w(temp, env_ir2_opnd, env_offset_QC());

            la_label(exit);

            la_vori_b(vreg_d, vtemp1, 0);
            goto do_gvec_end;
        case 0x08: /* SSHL, USHL */
            switch (size) {
                case 0:
                    /* 取元素中shift */
                    la_vslli_b(vleft, vreg_m, 0);
                    la_vsrli_b(vleft, vleft, 0);

                    /* 正数放vleft左移，负数取反后放vright右移，vtemp存放符号位*/
                    la_vslti_b(vtemp, vleft, 0);
                    la_vand_v(vright, vtemp, vleft);
                    la_vsub_b(vleft, vleft, vright);
                    la_vsigncov_b(vright, vtemp, vright);

                    /* ARM 移位量不做模运算，这里需要特殊处理，左移大于等于元素长度对应清零，右移大于等于元素长度shift-1*/
                    la_vsll_b(vreg_d, vreg_n, vleft);
                    if (!u) {
                        la_vsra_b(vreg_d, vreg_d, vright);
                    } else {
                        la_vsrl_b(vreg_d, vreg_d, vright);
                    }
                    la_vslei_bu(vleft, vleft, 7);
                    la_vslei_bu(vright, vright, 7);
                    la_vand_v(vtemp, vreg_d, vleft);

                    /* 正常右移 */

                    la_vand_v(vtemp, vtemp, vright);
                    /* 满位右移 */
                    la_vnori_b(vright, vright, 0);
                    if (!u) {
                        la_vsrai_b(vleft, vreg_n, 7);
                    } else {
                        la_vandi_b(vleft, vreg_n, 0);
                    }
                    la_vand_v(vleft, vright, vleft);
                    la_vadd_b(vreg_d, vtemp, vleft);

                    break;
                case 1:
                    /* 取元素中shift */
                    la_vslli_h(vleft, vreg_m, 8);
                    la_vsrli_h(vleft, vleft, 8);

                    /* 正数放vleft左移，负数取反后放vright右移，vtemp存放符号位*/
                    la_vslti_b(vtemp, vleft, 0);
                    la_vand_v(vright, vtemp, vleft);
                    la_vsub_b(vleft, vleft, vright);
                    la_vsigncov_b(vright, vtemp, vright);

                    /* ARM 移位量不做模运算，这里需要特殊处理，左移大于等于元素长度对应清零，右移大于等于元素长度shift-1*/
                    la_vsll_h(vreg_d, vreg_n, vleft);
                    if (!u) {
                        la_vsra_h(vreg_d, vreg_d, vright);
                    } else {
                        la_vsrl_h(vreg_d, vreg_d, vright);
                    }
                    la_vslei_hu(vleft, vleft, 15);
                    la_vslei_hu(vright, vright, 15);
                    la_vand_v(vtemp, vreg_d, vleft);

                    /* 正常右移 */

                    la_vand_v(vtemp, vtemp, vright);
                    /* 满位右移 */
                    la_vnori_b(vright, vright, 0);
                    if (!u) {
                        la_vsrai_h(vleft, vreg_n, 15);
                    } else {
                        la_vandi_b(vleft, vreg_n, 0);
                    }
                    la_vand_v(vleft, vright, vleft);
                    la_vadd_h(vreg_d, vtemp, vleft);

                    break;
                case 2:
                    /* 取元素中shift */
                    la_vslli_w(vleft, vreg_m, 24);
                    la_vsrli_w(vleft, vleft, 24);

                    /* 正数放vleft左移，负数取反后放vright右移，vtemp存放符号位*/
                    la_vslti_b(vtemp, vleft, 0);
                    la_vand_v(vright, vtemp, vleft);
                    la_vsub_b(vleft, vleft, vright);
                    la_vsigncov_b(vright, vtemp, vright);

                    /* ARM 移位量不做模运算，这里需要特殊处理，左移大于等于元素长度对应清零，右移大于等于元素长度shift-1*/
                    la_vsll_w(vreg_d, vreg_n, vleft);
                    if (!u) {
                        la_vsra_w(vreg_d, vreg_d, vright);
                    } else {
                        la_vsrl_w(vreg_d, vreg_d, vright);
                    }
                    la_vslei_wu(vleft, vleft, 31);
                    la_vslei_wu(vright, vright, 31);
                    la_vand_v(vtemp, vreg_d, vleft);

                    /* 正常右移 */

                    la_vand_v(vtemp, vtemp, vright);
                    /* 满位右移 */
                    la_vnori_b(vright, vright, 0);
                    if (!u) {
                        la_vsrai_w(vleft, vreg_n, 31);
                    } else {
                        la_vandi_b(vleft, vreg_n, 0);
                    }
                    la_vand_v(vleft, vright, vleft);
                    la_vadd_w(vreg_d, vtemp, vleft);

                    break;
                case 3:
                    /* 取元素中shift */
                    la_vslli_d(vleft, vreg_m, 56);
                    la_vsrli_d(vleft, vleft, 56);

                    /* 正数放vleft左移，负数取反后放vright右移，vtemp存放符号位*/
                    la_vslti_b(vtemp, vleft, 0);
                    la_vand_v(vright, vtemp, vleft);
                    la_vsub_b(vleft, vleft, vright);
                    la_vsigncov_b(vright, vtemp, vright);

                    /* ARM 移位量不做模运算，这里需要特殊处理，左移大于等于元素长度对应清零，右移大于等于元素长度shift-1*/
                    /* vslti的立即数限制5位，进行特殊处理，右移缩小2倍与16比较 */
                    la_vsll_d(vreg_d, vreg_n, vleft);
                    if (!u) {
                        la_vsra_d(vreg_d, vreg_d, vright);
                    } else {
                        la_vsrl_d(vreg_d, vreg_d, vright);
                    }
                    la_vsrli_b(vtemp, vleft, 2);
                    la_vslti_du(vleft, vtemp, 16);
                    la_vsrli_b(vright, vright, 2);
                    la_vslti_du(vright, vright, 16);

                    // la_vsll_d(vtemp, vreg_n, vleft);
                    la_vand_v(vtemp, vreg_d, vleft);

                    /* 正常右移 */
                    la_vand_v(vtemp, vtemp, vright);
                    /* 满位右移 */
                    la_vnori_b(vright, vright, 0);
                    if (!u) {
                        la_vsrai_d(vleft, vreg_n, 63);
                    } else {
                        la_vandi_b(vleft, vreg_n, 0);
                    }
                    la_vand_v(vleft, vright, vleft);
                    la_vadd_d(vreg_d, vtemp, vleft);

                    break;
                default:
                    assert(0);
            }

            goto do_gvec_end;
        case 0x0c: /* SMAX, UMAX */
            switch (size) {
                case 0:
                    if (u) {
                        la_vmax_bu(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vmax_b(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                case 1:
                    if (u) {
                        la_vmax_hu(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vmax_h(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                case 2:
                    if (u) {
                        la_vmax_wu(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vmax_w(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                default:
                    assert(0);
            }
            goto do_gvec_end;
        case 0x0d: /* SMIN, UMIN */
            switch (size) {
                case 0:
                    if (u) {
                        la_vmin_bu(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vmin_b(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                case 1:
                    if (u) {
                        la_vmin_hu(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vmin_h(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                case 2:
                    if (u) {
                        la_vmin_wu(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vmin_w(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                default:
                    assert(0);
            }
            goto do_gvec_end;
        case 0xe: /* SABD, UABD */
            switch (size) {
                case 0:
                    if (u)
                        la_vabsd_bu(vreg_d, vreg_n, vreg_m);
                    else
                        la_vabsd_b(vreg_d, vreg_n, vreg_m);
                    break;
                case 1:
                    if (u)
                        la_vabsd_hu(vreg_d, vreg_n, vreg_m);
                    else
                        la_vabsd_h(vreg_d, vreg_n, vreg_m);
                    break;
                case 2:
                    if (u)
                        la_vabsd_wu(vreg_d, vreg_n, vreg_m);
                    else
                        la_vabsd_w(vreg_d, vreg_n, vreg_m);
                    break;
                case 3:
                    if (u)
                        la_vabsd_du(vreg_d, vreg_n, vreg_m);
                    else
                        la_vabsd_d(vreg_d, vreg_n, vreg_m);
                    break;
            }
            goto do_gvec_end;
        case 0xf: /* SABA, UABA */
        {
            IR2_OPND vt_aba = ra_alloc_ftemp();
            switch (size) {
                case 0:
                    if (u)
                        la_vabsd_bu(vt_aba, vreg_n, vreg_m);
                    else
                        la_vabsd_b(vt_aba, vreg_n, vreg_m);
                    la_vadd_b(vreg_d, vreg_d, vt_aba);
                    break;
                case 1:
                    if (u)
                        la_vabsd_hu(vt_aba, vreg_n, vreg_m);
                    else
                        la_vabsd_h(vt_aba, vreg_n, vreg_m);
                    la_vadd_h(vreg_d, vreg_d, vt_aba);
                    break;
                case 2:
                    if (u)
                        la_vabsd_wu(vt_aba, vreg_n, vreg_m);
                    else
                        la_vabsd_w(vt_aba, vreg_n, vreg_m);
                    la_vadd_w(vreg_d, vreg_d, vt_aba);
                    break;
                case 3:
                    if (u)
                        la_vabsd_du(vt_aba, vreg_n, vreg_m);
                    else
                        la_vabsd_d(vt_aba, vreg_n, vreg_m);
                    la_vadd_d(vreg_d, vreg_d, vt_aba);
                    break;
            }
            free_alloc_fpr(vt_aba);
            goto do_gvec_end;
        }
        case 0x10: /* ADD, SUB */
            switch (size) {
                case 0:
                    if (u) {
                        la_vsub_b(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vadd_b(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                case 1:
                    if (u) {
                        la_vsub_h(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vadd_h(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                case 2:
                    if (u) {
                        la_vsub_w(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vadd_w(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                case 3:
                    assert(is_q);
                    if (u) {
                        la_vsub_d(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vadd_d(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                default:
                    assert(0);
            }
            goto do_gvec_end;
        case 0x13:    /* MUL, PMUL */
            if (!u) { /* MUL */
                switch (size) {
                    case 0:
                        la_vmul_b(vreg_d, vreg_n, vreg_m);
                        break;
                    case 1:
                        la_vmul_h(vreg_d, vreg_n, vreg_m);
                        break;
                    case 2:
                        la_vmul_w(vreg_d, vreg_n, vreg_m);
                        break;
                    case 3:
                        la_vmul_d(vreg_d, vreg_n, vreg_m);
                        break;
                    default:
                        assert(0);
                }
            } else { /* PMUL — poly multiply 8b→8b, shift-XOR loop */
                IR2_OPND vmask = ra_alloc_ftemp();
                IR2_OPND vshifted = ra_alloc_ftemp();
                IR2_OPND vsel = ra_alloc_ftemp();
                IR2_OPND vtmp = ra_alloc_ftemp();
                IR2_OPND ctr = ra_alloc_itemp();
                IR2_OPND loop = ir2_opnd_new_type(IR2_OPND_LABEL);
                /* Copy the source before clearing the destination.  The guest
                 * instruction commonly has rd == rn, and LATA may map both to
                 * the same host FPR. */
                la_vori_b(vshifted, vreg_n, 0);
                la_vxor_v(vreg_d, vreg_d, vreg_d);
                /* vldi imm[12:10]=0b000: broadcast imm[7:0]=1 as 8-bit elements */
                la_vldi(vmask, 0x001);
                la_addi_w(ctr, zero_ir2_opnd, 8);
                la_label(loop);
                la_vand_v(vtmp, vreg_m, vmask);
                la_vseq_b(vtmp, vtmp, vmask);
                la_vxor_v(vsel, vreg_d, vshifted);
                la_vbitsel_v(vreg_d, vreg_d, vsel, vtmp);
                la_vslli_b(vmask, vmask, 1);
                la_vslli_b(vshifted, vshifted, 1);
                la_addi_w(ctr, ctr, -1);
                la_bnez(ctr, loop);
                free_alloc_fpr(vmask);
                free_alloc_fpr(vshifted);
                free_alloc_fpr(vsel);
                free_alloc_fpr(vtmp);
                free_alloc_gpr(ctr);
            }
            goto do_gvec_end;
        case 0x12: /* MLA, MLS */
            switch (size) {
                case 0:
                    if (u) {
                        la_vmsub_b(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vmadd_b(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                case 1:
                    if (u) {
                        la_vmsub_h(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vmadd_h(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                case 2:
                    if (u) {
                        la_vmsub_w(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vmadd_w(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                case 3:
                    assert(is_q);
                    if (u) {
                        la_vmsub_d(vreg_d, vreg_n, vreg_m);
                    } else {
                        la_vmadd_d(vreg_d, vreg_n, vreg_m);
                    }
                    break;
                default:
                    assert(0);
            }
            goto do_gvec_end;
        case 0x16: /* SQDMULH, SQRDMULH */
            // TODO : need handle saturate
            if (is_q) {
                /* Q=1: even/odd multiply on full 128-bit (ref: dynarmic) */
                IR2_OPND even = ra_alloc_ftemp();
                IR2_OPND odd = ra_alloc_ftemp();
                IR2_OPND tmp = ra_alloc_ftemp();
                switch (size) {
                    case 1:
                        la_vmulwev_w_h(even, vreg_n, vreg_m);
                        la_vmulwod_w_h(odd, vreg_n, vreg_m);
                        la_vsadd_w(even, even, even);
                        la_vsadd_w(odd, odd, odd);
                        la_vori_b(tmp, even, 0);
                        if (u)
                            la_vssrarni_h_w(tmp, odd, 16);
                        else
                            la_vssrani_h_w(tmp, odd, 16);
                        la_vori_b(even, tmp, 0);
                        la_vshuf4i_d(even, even, 0x01);
                        la_vilvl_h(vreg_d, tmp, even);
                        break;
                    case 2:
                        la_vmulwev_d_w(even, vreg_n, vreg_m);
                        la_vmulwod_d_w(odd, vreg_n, vreg_m);
                        la_vsadd_d(even, even, even);
                        la_vsadd_d(odd, odd, odd);
                        la_vori_b(tmp, even, 0);
                        if (u)
                            la_vssrarni_w_d(tmp, odd, 32);
                        else
                            la_vssrani_w_d(tmp, odd, 32);
                        la_vori_b(even, tmp, 0);
                        la_vshuf4i_d(even, even, 0x01);
                        la_vilvl_w(vreg_d, tmp, even);
                        break;
                    default:
                        assert(0);
                }
                free_alloc_fpr(even);
                free_alloc_fpr(odd);
                free_alloc_fpr(tmp);
            } else if (u) {
                switch (size) {
                    case 1:
                        la_vilvl_h(vtemp, vzero, vreg_n);
                        la_vilvl_h(vtemp1, vzero, vreg_m);
                        la_vmulwev_w_h(vreg_d, vtemp, vtemp1);
                        la_vsadd_w(vreg_d, vreg_d, vreg_d);
                        la_vssrarni_h_w(vreg_d, vreg_d, 16);
                        break;
                    case 2:
                        la_vilvl_w(vtemp, vzero, vreg_n);
                        la_vilvl_w(vtemp1, vzero, vreg_m);
                        la_vmulwev_d_w(vreg_d, vtemp, vtemp1);
                        la_vsadd_d(vreg_d, vreg_d, vreg_d);
                        la_vssrarni_w_d(vreg_d, vreg_d, 32);
                        break;
                    default:
                        assert(0);
                }
            } else {
                switch (size) {
                    case 1:
                        la_vilvl_h(vtemp, vzero, vreg_n);
                        la_vilvl_h(vtemp1, vzero, vreg_m);
                        la_vmulwev_w_h(vreg_d, vtemp, vtemp1);
                        la_vsadd_w(vreg_d, vreg_d, vreg_d);
                        la_vssrani_h_w(vreg_d, vreg_d, 16);
                        break;
                    case 2:
                        la_vilvl_w(vtemp, vzero, vreg_n);
                        la_vilvl_w(vtemp1, vzero, vreg_m);
                        la_vmulwev_d_w(vreg_d, vtemp, vtemp1);
                        la_vsadd_d(vreg_d, vreg_d, vreg_d);
                        la_vssrani_w_d(vreg_d, vreg_d, 32);
                        break;
                    default:
                        assert(0);
                }
            }
            goto do_gvec_end;
        case 0x11:   /* CMEQ, CMTST */
            if (u) { /* CMEQ */
                switch (size) {
                    case 0:
                        la_vseq_b(vreg_d, vreg_n, vreg_m);
                        break;
                    case 1:
                        la_vseq_h(vreg_d, vreg_n, vreg_m);
                        break;
                    case 2:
                        la_vseq_w(vreg_d, vreg_n, vreg_m);
                        break;
                    case 3:
                        la_vseq_d(vreg_d, vreg_n, vreg_m);
                        break;
                    default:
                        assert(0);
                }
            } else { /* CMTST */
                la_vand_v(vreg_d, vreg_n, vreg_m);
                switch (size) {
                    case 0:
                        la_vseqi_b(vreg_d, vreg_d, 0);
                        break;
                    case 1:
                        la_vseqi_h(vreg_d, vreg_d, 0);
                        break;
                    case 2:
                        la_vseqi_w(vreg_d, vreg_d, 0);
                        break;
                    case 3:
                        la_vseqi_d(vreg_d, vreg_d, 0);
                        break;
                    default:
                        assert(0);
                }
                la_vnori_b(vreg_d, vreg_d, 0);
            }
            goto do_gvec_end;
        case 0x06:   /* CMGT, CMHI */
            if (u) { /* CMHI */
                switch (size) {
                    case 0:
                        la_vslt_bu(vreg_d, vreg_m, vreg_n);
                        break;
                    case 1:
                        la_vslt_hu(vreg_d, vreg_m, vreg_n);
                        break;
                    case 2:
                        la_vslt_wu(vreg_d, vreg_m, vreg_n);
                        break;
                    case 3:
                        la_vslt_du(vreg_d, vreg_m, vreg_n);
                        break;
                    default:
                        assert(0);
                }
            } else { /* CMGT */
                switch (size) {
                    case 0:
                        la_vslt_b(vreg_d, vreg_m, vreg_n);
                        break;
                    case 1:
                        la_vslt_h(vreg_d, vreg_m, vreg_n);
                        break;
                    case 2:
                        la_vslt_w(vreg_d, vreg_m, vreg_n);
                        break;
                    case 3:
                        la_vslt_d(vreg_d, vreg_m, vreg_n);
                        break;
                    default:
                        assert(0);
                }
            }
            goto do_gvec_end;
        case 0x07:   /* CMGE, CMHS */
            if (u) { /* CMHS */
                switch (size) {
                    case 0:
                        la_vsle_bu(vreg_d, vreg_m, vreg_n);
                        break;
                    case 1:
                        la_vsle_hu(vreg_d, vreg_m, vreg_n);
                        break;
                    case 2:
                        la_vsle_wu(vreg_d, vreg_m, vreg_n);
                        break;
                    case 3:
                        la_vsle_du(vreg_d, vreg_m, vreg_n);
                        break;
                    default:
                        assert(0);
                }
            } else { /* CMGE */
                switch (size) {
                    case 0:
                        la_vsle_b(vreg_d, vreg_m, vreg_n);
                        break;
                    case 1:
                        la_vsle_h(vreg_d, vreg_m, vreg_n);
                        break;
                    case 2:
                        la_vsle_w(vreg_d, vreg_m, vreg_n);
                        break;
                    case 3:
                        la_vsle_d(vreg_d, vreg_m, vreg_n);
                        break;
                    default:
                        assert(0);
                }
            }
        do_gvec_end:
            if (!is_q) {
                /* 高64位清零 */
                la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            }
            store_fpr_dst(rd, vreg_d);
            free_alloc_fpr(vreg_d);
            free_alloc_fpr(vreg_n);
            free_alloc_fpr(vreg_m);
            if (opcode == 0x08) {
                free_alloc_fpr(vtemp);
                free_alloc_fpr(vleft);
                free_alloc_fpr(vright);
            } else if (opcode == 0x09 || opcode == 0x0b) {
                free_alloc_fpr(vtemp);
                free_alloc_fpr(vtemp1);
            } else if (opcode == 0x0a) {
                free_alloc_fpr(vtemp);
                free_alloc_fpr(vtemp1);
                free_alloc_fpr(vzero);
            } else if (opcode == 0x16) {
                free_alloc_fpr(vtemp);
                free_alloc_fpr(vtemp1);
                free_alloc_fpr(vzero);
            } else if (opcode == 0x05) {
                free_alloc_fpr(vtemp);
                free_alloc_fpr(vtemp1);
                free_alloc_gpr(temp);
            }
            return;
    }

    if (size == 3) {
        assert(is_q);
    } else {
        switch (opcode) {
            case 0x0: /* SHADD, UHADD — halving add: (a+b)>>1 */
                switch (size) {
                    case 0:
                        if (u)
                            la_vavg_bu(vreg_d, vreg_n, vreg_m);
                        else
                            la_vavg_b(vreg_d, vreg_n, vreg_m);
                        break;
                    case 1:
                        if (u)
                            la_vavg_hu(vreg_d, vreg_n, vreg_m);
                        else
                            la_vavg_h(vreg_d, vreg_n, vreg_m);
                        break;
                    case 2:
                        if (u)
                            la_vavg_wu(vreg_d, vreg_n, vreg_m);
                        else
                            la_vavg_w(vreg_d, vreg_n, vreg_m);
                        break;
                    case 3:
                        if (u)
                            la_vavg_du(vreg_d, vreg_n, vreg_m);
                        else
                            la_vavg_d(vreg_d, vreg_n, vreg_m);
                        break;
                }
                goto do_gvec_end;
            case 0x2: /* SRHADD, URHADD — rounding halving add: (a+b+1)>>1 */
                switch (size) {
                    case 0:
                        if (u)
                            la_vavgr_bu(vreg_d, vreg_n, vreg_m);
                        else
                            la_vavgr_b(vreg_d, vreg_n, vreg_m);
                        break;
                    case 1:
                        if (u)
                            la_vavgr_hu(vreg_d, vreg_n, vreg_m);
                        else
                            la_vavgr_h(vreg_d, vreg_n, vreg_m);
                        break;
                    case 2:
                        if (u)
                            la_vavgr_wu(vreg_d, vreg_n, vreg_m);
                        else
                            la_vavgr_w(vreg_d, vreg_n, vreg_m);
                        break;
                    case 3:
                        if (u)
                            la_vavgr_du(vreg_d, vreg_n, vreg_m);
                        else
                            la_vavgr_d(vreg_d, vreg_n, vreg_m);
                        break;
                }
                goto do_gvec_end;
            case 0x4: /* SHSUB, UHSUB — halving sub: (a-b)>>1 */
            {
                IR2_OPND vt_ev = ra_alloc_ftemp();
                /* Widen, subtract, then narrow with shift by 1 */
                switch (size) {
                    case 0:
                        if (u) {
                            la_vsubwev_h_bu(vt_ev, vreg_n, vreg_m);
                            la_vsubwod_h_bu(vreg_d, vreg_n, vreg_m);
                            la_vsrlni_b_h(vreg_d, vt_ev, 1);
                        } else {
                            la_vsubwev_h_b(vt_ev, vreg_n, vreg_m);
                            la_vsubwod_h_b(vreg_d, vreg_n, vreg_m);
                            la_vsrani_b_h(vreg_d, vt_ev, 1);
                        }
                        la_vbsrl_v(vt_ev, vreg_d, 8);
                        la_vilvl_b(vreg_d, vt_ev, vreg_d);
                        break;
                    case 1:
                        if (u) {
                            la_vsubwev_w_hu(vt_ev, vreg_n, vreg_m);
                            la_vsubwod_w_hu(vreg_d, vreg_n, vreg_m);
                            la_vsrlni_h_w(vreg_d, vt_ev, 1);
                        } else {
                            la_vsubwev_w_h(vt_ev, vreg_n, vreg_m);
                            la_vsubwod_w_h(vreg_d, vreg_n, vreg_m);
                            la_vsrani_h_w(vreg_d, vt_ev, 1);
                        }
                        la_vbsrl_v(vt_ev, vreg_d, 8);
                        la_vilvl_h(vreg_d, vt_ev, vreg_d);
                        break;
                    case 2:
                        if (u) {
                            la_vsubwev_d_wu(vt_ev, vreg_n, vreg_m);
                            la_vsubwod_d_wu(vreg_d, vreg_n, vreg_m);
                            la_vsrlni_w_d(vreg_d, vt_ev, 1);
                        } else {
                            la_vsubwev_d_w(vt_ev, vreg_n, vreg_m);
                            la_vsubwod_d_w(vreg_d, vreg_n, vreg_m);
                            la_vsrani_w_d(vreg_d, vt_ev, 1);
                        }
                        la_vbsrl_v(vt_ev, vreg_d, 8);
                        la_vilvl_w(vreg_d, vt_ev, vreg_d);
                        break;
                    default:
                        g_assert_not_reached();
                }
                free_alloc_fpr(vt_ev);
                goto do_gvec_end;
            }
            case 0x9: /* SQSHL, UQSHL — saturating shift left (register) */
            case 0xb: /* SQRSHL, UQRSHL — saturating rounding shift left (register) */
            {
                int esize = 8 << size;
                bool is_rounding = (opcode == 0x0b);
                /*
                 * ARM semantics:
                 *   shift < 0: right shift by -shift
                 *   shift >= 0: left shift, saturating on overflow
                 *   shift <= -esize: unsigned -> 0, signed -> sign mask
                 *   shift >= esize: saturate if operand != 0
                 */

                /* 1. Truncate shift to int8_t and sign-extend. */
                if (size == 1) {
                    la_vslli_h(vreg_m, vreg_m, 8);
                    la_vsrai_h(vreg_m, vreg_m, 8);
                } else if (size == 2) {
                    la_vslli_w(vreg_m, vreg_m, 24);
                    la_vsrai_w(vreg_m, vreg_m, 24);
                } else if (size == 3) {
                    la_vslli_d(vreg_m, vreg_m, 56);
                    la_vsrai_d(vreg_m, vreg_m, 56);
                }
                /* 2. shift_sign = shift < 0. */
                switch (size) {
                    case 0: la_vslti_b(vtemp1, vreg_m, 0); break;
                    case 1: la_vslti_h(vtemp1, vreg_m, 0); break;
                    case 2: la_vslti_w(vtemp1, vreg_m, 0); break;
                    case 3: la_vslti_d(vtemp1, vreg_m, 0); break;
                }
                /* 3. neg_shift = -shift. */
                switch (size) {
                    case 0: la_vneg_b(vtemp, vreg_m); break;
                    case 1: la_vneg_h(vtemp, vreg_m); break;
                    case 2: la_vneg_w(vtemp, vreg_m); break;
                    case 3: la_vneg_d(vtemp, vreg_m); break;
                }

                /* 4. Right-shift path. */
                /* 4.1 large_right = shift <= -esize. */
                if (size <= 1) {
                    if (size == 0)
                        la_vslti_b(vright, vreg_m, -(esize - 1));
                    else
                        la_vslti_h(vright, vreg_m, -(esize - 1));
                } else {
                    la_vldi(vright, (size == 2 ? 0x800 : 0xC00) | ((-(esize - 1)) & 0x3FF));
                    if (size == 2)
                        la_vslt_w(vright, vreg_m, vright);
                    else
                        la_vslt_d(vright, vreg_m, vright);
                }
                if (is_rounding) {
                    if (u) {
                        /* UQRSHL: unsigned rounding right shift uses vsrlr,
                           NOT vsrar (which is arithmetic/signed). */
                        switch (size) {
                            case 0: la_vsrlr_b(vleft, vreg_n, vtemp); break;
                            case 1: la_vsrlr_h(vleft, vreg_n, vtemp); break;
                            case 2: la_vsrlr_w(vleft, vreg_n, vtemp); break;
                            case 3: la_vsrlr_d(vleft, vreg_n, vtemp); break;
                        }
                    } else {
                        /* SQRSHL: signed rounding right shift = vsrar. */
                        switch (size) {
                            case 0: la_vsrar_b(vleft, vreg_n, vtemp); break;
                            case 1: la_vsrar_h(vleft, vreg_n, vtemp); break;
                            case 2: la_vsrar_w(vleft, vreg_n, vtemp); break;
                            case 3: la_vsrar_d(vleft, vreg_n, vtemp); break;
                        }
                    }
                } else if (u) {
                    switch (size) {
                        case 0: la_vsrl_b(vleft, vreg_n, vtemp); break;
                        case 1: la_vsrl_h(vleft, vreg_n, vtemp); break;
                        case 2: la_vsrl_w(vleft, vreg_n, vtemp); break;
                        case 3: la_vsrl_d(vleft, vreg_n, vtemp); break;
                    }
                } else {
                    switch (size) {
                        case 0: la_vsra_b(vleft, vreg_n, vtemp); break;
                        case 1: la_vsra_h(vleft, vreg_n, vtemp); break;
                        case 2: la_vsra_w(vleft, vreg_n, vtemp); break;
                        case 3: la_vsra_d(vleft, vreg_n, vtemp); break;
                    }
                }
                /* 4.2 Fix shift <= -esize.
                 *     SQSHL: sign_mask for signed, 0 for unsigned.
                 *     QRSHL rounding: for signed, rounding arithmetic
                 *     right shift by >= esize always produces 0 (not sign).
                 *     For unsigned, rounding logical right shift by >= esize
                 *     gives 0, except shift==-esize which gives MSB. */
                if (u) {
                    la_vbitsel_v(vleft, vleft, vzero, vright);
                } else if (is_rounding) {
                    /* SQRSHL: large_right gives 0, not sign_mask. */
                    la_vbitsel_v(vleft, vleft, vzero, vright);
                } else {
                    /* SQSHL: large_right gives sign_mask. */
                    IR2_OPND t6 = ra_alloc_ftemp();
                    switch (size) {
                        case 0: la_vslti_b(t6, vreg_n, 0); break;
                        case 1: la_vslti_h(t6, vreg_n, 0); break;
                        case 2: la_vslti_w(t6, vreg_n, 0); break;
                        case 3: la_vslti_d(t6, vreg_n, 0); break;
                    }
                    la_vbitsel_v(vleft, vleft, t6, vright);
                    free_alloc_fpr(t6);
                }
                /* 4.3 [UQRSHL] shift == -esize special case.
                 *     ARM rounding logical right shift by esize = MSB.
                 *     LSX vsrlr masks shift to &(esize-1), so vsrlr(x,esize)
                 *     produces x rather than MSB. */
                if (u && is_rounding) {
                    if (size == 0) {
                        la_vseqi_b(vright, vreg_m, -8);
                    } else if (size == 1) {
                        la_vseqi_h(vright, vreg_m, -16);
                    } else {
                        la_vldi(vright, (size == 2 ? 0x800 : 0xC00)
                                           | ((-esize) & 0x3FF));
                        if (size == 2)
                            la_vseq_w(vright, vreg_m, vright);
                        else
                            la_vseq_d(vright, vreg_m, vright);
                    }
                    IR2_OPND t6 = ra_alloc_ftemp();
                    switch (size) {
                        case 0: la_vsrli_b(t6, vreg_n, 7); break;
                        case 1: la_vsrli_h(t6, vreg_n, 15); break;
                        case 2: la_vsrli_w(t6, vreg_n, 31); break;
                        case 3: la_vsrli_d(t6, vreg_n, 63); break;
                    }
                    la_vbitsel_v(vleft, vleft, t6, vright);
                    free_alloc_fpr(t6);
                }
                /* Free large_right before allocating the saved operand. */
                free_alloc_fpr(vright);

                /* rd may alias rn; keep operand for overflow/sign checks. */
                IR2_OPND vn_saved = ra_alloc_ftemp();
                la_vori_b(vn_saved, vreg_n, 0);

                /* 5. Left-shift path.  Keep rresult in vleft and write
                   lresult to vreg_d so rd==rn does not destroy rresult. */
                switch (size) {
                    case 0: la_vsll_b(vreg_d, vn_saved, vreg_m); break;
                    case 1: la_vsll_h(vreg_d, vn_saved, vreg_m); break;
                    case 2: la_vsll_w(vreg_d, vn_saved, vreg_m); break;
                    case 3: la_vsll_d(vreg_d, vn_saved, vreg_m); break;
                }

                /* 5.1 overflow = shift >= esize. */
                {
                    IR2_OPND t6 = ra_alloc_ftemp(); /* 5 */
                    if (size <= 1) {
                        if (size == 0)
                            la_vslti_bu(vtemp, vreg_m, esize);
                        else
                            la_vslti_hu(vtemp, vreg_m, esize);
                        la_vnori_b(vtemp, vtemp, 0);
                    } else {
                        la_vldi(vtemp, (size == 2 ? 0x800 : 0xC00) | (esize & 0x3FF));
                        if (size == 2) {
                            la_vslt_wu(vtemp, vreg_m, vtemp);
                            la_vnori_b(vtemp, vtemp, 0);
                        } else {
                            la_vslt_du(vtemp, vreg_m, vtemp);
                            la_vnori_b(vtemp, vtemp, 0);
                        }
                    }
                    la_vnori_b(t6, vtemp1, 0);
                    la_vand_v(vtemp, vtemp, t6);

                    /* Zero shifted left never overflows. */
                    la_vxor_v(vzero, vzero, vzero);
                    switch (size) {
                        case 0: la_vseq_b(t6, vn_saved, vzero); break;
                        case 1: la_vseq_h(t6, vn_saved, vzero); break;
                        case 2: la_vseq_w(t6, vn_saved, vzero); break;
                        case 3: la_vseq_d(t6, vn_saved, vzero); break;
                    }
                    la_vnori_b(t6, t6, 0);
                    la_vand_v(vtemp, vtemp, t6);

                    /* 5.2 overflow |= (lresult >> shift) != operand. */
                    if (is_rounding) {
                        if (u) {
                            switch (size) {
                                case 0: la_vsrl_b(t6, vreg_d, vreg_m); break;
                                case 1: la_vsrl_h(t6, vreg_d, vreg_m); break;
                                case 2: la_vsrl_w(t6, vreg_d, vreg_m); break;
                                case 3: la_vsrl_d(t6, vreg_d, vreg_m); break;
                            }
                        } else {
                            switch (size) {
                                case 0: la_vsra_b(t6, vreg_d, vreg_m); break;
                                case 1: la_vsra_h(t6, vreg_d, vreg_m); break;
                                case 2: la_vsra_w(t6, vreg_d, vreg_m); break;
                                case 3: la_vsra_d(t6, vreg_d, vreg_m); break;
                            }
                        }
                    } else if (u) {
                        switch (size) {
                            case 0: la_vsrl_b(t6, vreg_d, vreg_m); break;
                            case 1: la_vsrl_h(t6, vreg_d, vreg_m); break;
                            case 2: la_vsrl_w(t6, vreg_d, vreg_m); break;
                            case 3: la_vsrl_d(t6, vreg_d, vreg_m); break;
                        }
                    } else {
                        switch (size) {
                            case 0: la_vsra_b(t6, vreg_d, vreg_m); break;
                            case 1: la_vsra_h(t6, vreg_d, vreg_m); break;
                            case 2: la_vsra_w(t6, vreg_d, vreg_m); break;
                            case 3: la_vsra_d(t6, vreg_d, vreg_m); break;
                        }
                    }
                    switch (size) {
                        case 0: la_vseq_b(t6, t6, vn_saved); break;
                        case 1: la_vseq_h(t6, t6, vn_saved); break;
                        case 2: la_vseq_w(t6, t6, vn_saved); break;
                        case 3: la_vseq_d(t6, t6, vn_saved); break;
                    }
                    la_vnor_v(t6, t6, t6);
                    la_vor_v(vtemp, t6, vtemp);
                    free_alloc_fpr(t6);
                }
                /* 6. Build signed saturation selector before freeing operand. */
                IR2_OPND vsgn = ra_alloc_ftemp(); /* 4: sign_mask */
                if (!u) {
                    switch (size) {
                        case 0: la_vslti_b(vsgn, vn_saved, 0); break;
                        case 1: la_vslti_h(vsgn, vn_saved, 0); break;
                        case 2: la_vslti_w(vsgn, vn_saved, 0); break;
                        case 3: la_vslti_d(vsgn, vn_saved, 0); break;
                    }
                }
                free_alloc_fpr(vzero);
                free_alloc_fpr(vn_saved);

                /* 7. Select saturated value where overflow is set. */
                if (u) {
                    IR2_OPND vsat = ra_alloc_ftemp(); /* 4 */
                    la_vxor_v(vsat, vsat, vsat);
                    la_vnori_b(vsat, vsat, 0); /* UINT_MAX via NOR with self=0 */
                    la_vbitsel_v(vreg_d, vreg_d, vsat, vtemp);
                    free_alloc_fpr(vsat);
                    free_alloc_fpr(vsgn); /* unused, allocated too early */
                } else {
                    IR2_OPND vmin = ra_alloc_ftemp(); /* 4: INT_MIN */
                    IR2_OPND vmax = ra_alloc_ftemp(); /* 5: INT_MAX */
                    /* INT_MIN = 1 << (esize - 1). */
                    IR2_OPND igpr = ra_alloc_itemp();
                    if (size == 0)
                        li_d(igpr, 0x8080808080808080LL);
                    else if (size == 1)
                        li_d(igpr, 0x8000800080008000LL);
                    else if (size == 2)
                        li_d(igpr, 0x8000000080000000LL);
                    else
                        li_d(igpr, 0x8000000000000000LL);
                    switch (size) {
                        case 0: la_vreplgr2vr_b(vmin, igpr); break;
                        case 1: la_vreplgr2vr_h(vmin, igpr); break;
                        case 2: la_vreplgr2vr_w(vmin, igpr); break;
                        case 3: la_vreplgr2vr_d(vmin, igpr); break;
                    }
                    free_alloc_gpr(igpr);
                    la_vnori_b(vmax, vmin, 0);
                    la_vbitsel_v(vmax, vmax, vmin, vsgn);
                    free_alloc_fpr(vmin);
                    free_alloc_fpr(vsgn);
                    la_vbitsel_v(vreg_d, vreg_d, vmax, vtemp);
                    free_alloc_fpr(vmax);
                }

                /* 8. Final select: shift < 0 ? rresult : lresult. */
                la_vbitsel_v(vreg_d, vreg_d, vleft, vtemp1);
            }
                free_alloc_fpr(vleft); /* vright already freed above */
                goto do_gvec_end;
            case 0xa: /* SRSHL, URSHL — non-saturating rounding shift (register) */
            {
                int esize = 8 << size;

                /* 1. Truncate shift to int8_t and sign-extend. */
                if (size == 1) {
                    la_vslli_h(vreg_m, vreg_m, 8);
                    la_vsrai_h(vreg_m, vreg_m, 8);
                } else if (size == 2) {
                    la_vslli_w(vreg_m, vreg_m, 24);
                    la_vsrai_w(vreg_m, vreg_m, 24);
                } else if (size == 3) {
                    la_vslli_d(vreg_m, vreg_m, 56);
                    la_vsrai_d(vreg_m, vreg_m, 56);
                }

                /* 2. vtemp1 = sign_mask (shift < 0). */
                switch (size) {
                    case 0: la_vslti_b(vtemp1, vreg_m, 0); break;
                    case 1: la_vslti_h(vtemp1, vreg_m, 0); break;
                    case 2: la_vslti_w(vtemp1, vreg_m, 0); break;
                    case 3: la_vslti_d(vtemp1, vreg_m, 0); break;
                }

                /* 3. vtemp = neg_shift = -shift. */
                switch (size) {
                    case 0: la_vneg_b(vtemp, vreg_m); break;
                    case 1: la_vneg_h(vtemp, vreg_m); break;
                    case 2: la_vneg_w(vtemp, vreg_m); break;
                    case 3: la_vneg_d(vtemp, vreg_m); break;
                }

                /* 4. vleft = large_left = (shift >= esize).
                 *    LSX vsll masks shift to &(esize-1), so vsll(x, esize)=x.
                 *    ARM says result should be 0 when shift >= esize. */
                if (size <= 1) {
                    if (size == 0)
                        la_vslti_bu(vleft, vreg_m, esize);
                    else
                        la_vslti_hu(vleft, vreg_m, esize);
                    la_vnori_b(vleft, vleft, 0);
                } else {
                    la_vldi(vleft, (size == 2 ? 0x800 : 0xC00) | (esize & 0x3FF));
                    if (size == 2) {
                        la_vslt_wu(vleft, vreg_m, vleft);
                        la_vnori_b(vleft, vleft, 0);
                    } else {
                        la_vslt_du(vleft, vreg_m, vleft);
                        la_vnori_b(vleft, vleft, 0);
                    }
                }

                /* 5. vright = left_result = operand << shift. */
                switch (size) {
                    case 0: la_vsll_b(vright, vreg_n, vreg_m); break;
                    case 1: la_vsll_h(vright, vreg_n, vreg_m); break;
                    case 2: la_vsll_w(vright, vreg_n, vreg_m); break;
                    case 3: la_vsll_d(vright, vreg_n, vreg_m); break;
                }

                /* 5.1 Zero left_result when shift >= esize. */
                la_vxor_v(vzero, vzero, vzero);
                la_vbitsel_v(vright, vright, vzero, vleft);

                /* 6. vleft = large_right = (neg_shift >= esize).
                 *    LSX vsrar/vsrlr masks shift to &(esize-1). */
                if (size <= 1) {
                    if (size == 0)
                        la_vslti_bu(vleft, vtemp, esize);
                    else
                        la_vslti_hu(vleft, vtemp, esize);
                    la_vnori_b(vleft, vleft, 0);
                } else {
                    la_vldi(vleft, (size == 2 ? 0x800 : 0xC00) | (esize & 0x3FF));
                    if (size == 2) {
                        la_vslt_wu(vleft, vtemp, vleft);
                        la_vnori_b(vleft, vleft, 0);
                    } else {
                        la_vslt_du(vleft, vtemp, vleft);
                        la_vnori_b(vleft, vleft, 0);
                    }
                }

                /* 7. vzero = right_result (rounding right shift). */
                if (u) {
                    switch (size) {
                        case 0: la_vsrlr_b(vzero, vreg_n, vtemp); break;
                        case 1: la_vsrlr_h(vzero, vreg_n, vtemp); break;
                        case 2: la_vsrlr_w(vzero, vreg_n, vtemp); break;
                        case 3: la_vsrlr_d(vzero, vreg_n, vtemp); break;
                    }
                } else {
                    switch (size) {
                        case 0: la_vsrar_b(vzero, vreg_n, vtemp); break;
                        case 1: la_vsrar_h(vzero, vreg_n, vtemp); break;
                        case 2: la_vsrar_w(vzero, vreg_n, vtemp); break;
                        case 3: la_vsrar_d(vzero, vreg_n, vtemp); break;
                    }
                }

                /* 8. Zero right_result when neg_shift >= esize.
                 *    Reuse vtemp (neg_shift no longer needed) as zero vector. */
                la_vxor_v(vtemp, vtemp, vtemp);
                la_vbitsel_v(vzero, vzero, vtemp, vleft);

                /* 9. [unsigned] Handle neg_shift == esize special case.
                 *    LSX vsrlr masks shift to &(esize-1), so vsrlr(x, esize)=x.
                 *    But ARM rounding right shift by esize = MSB of each element.
                 *    Detect shift == -esize via the original shift value. */
                if (u) {
                    if (size == 0) {
                        la_vseqi_b(vleft, vreg_m, -8);
                    } else if (size == 1) {
                        la_vseqi_h(vleft, vreg_m, -16);
                    } else {
                        la_vldi(vleft, (size == 2 ? 0x800 : 0xC00)
                                         | ((-esize) & 0x3FF));
                        if (size == 2)
                            la_vseq_w(vleft, vreg_m, vleft);
                        else
                            la_vseq_d(vleft, vreg_m, vleft);
                    }
                    /* rounding_bit = operand >> (esize-1) = MSB of each elem. */
                    switch (size) {
                        case 0: la_vsrli_b(vtemp, vreg_n, 7); break;
                        case 1: la_vsrli_h(vtemp, vreg_n, 15); break;
                        case 2: la_vsrli_w(vtemp, vreg_n, 31); break;
                        case 3: la_vsrli_d(vtemp, vreg_n, 63); break;
                    }
                    la_vbitsel_v(vzero, vzero, vtemp, vleft);
                }

                /* 10. Final select: sign_mask ? rresult(vzero) : lresult(vright). */
                la_vbitsel_v(vreg_d, vright, vzero, vtemp1);
            }
                free_alloc_fpr(vleft);
                free_alloc_fpr(vright);
                goto do_gvec_end;
            default:
                g_assert_not_reached();
        }
    }
}

/* AdvSIMD three same
 *  31  30  29  28       24 23  22  21 20  16 15    11  10 9    5 4    0
 * +---+---+---+-----------+------+---+------+--------+---+------+------+
 * | 0 | Q | U | 0 1 1 1 0 | size | 1 |  Rm  | opcode | 1 |  Rn  |  Rd  |
 * +---+---+---+-----------+------+---+------+--------+---+------+------+
 */
static void disas_simd_three_reg_same(DisasContext* s, uint32_t insn)
{
    int opcode = extract32(insn, 11, 5);

    switch (opcode) {
        case 0x3: /* logic ops */
            disas_simd_3same_logic(s, insn);
            break;
        case 0x17: /* ADDP */
        case 0x14: /* SMAXP, UMAXP */
        case 0x15: /* SMINP, UMINP */
        {
            /* Pairwise operations */
            int is_q = extract32(insn, 30, 1);
            int u = extract32(insn, 29, 1);
            int size = extract32(insn, 22, 2);
            int rm = extract32(insn, 16, 5);
            int rn = extract32(insn, 5, 5);
            int rd = extract32(insn, 0, 5);
            if (opcode == 0x17) {
                if (u || (size == 3 && !is_q)) {
                    lata_unallocated_encoding(s);
                    return;
                }
            } else {
                if (size == 3) {
                    lata_unallocated_encoding(s);
                    return;
                }
            }
            handle_simd_3same_pair(s, is_q, u, opcode, size, rn, rm, rd);
            break;
        }
        case 0x18 ... 0x31:
            /* floating point ops, sz[1] and U are part of opcode */
            disas_simd_3same_float(s, insn);
            break;
        default:
            disas_simd_3same_int(s, insn);
            break;
    }
}

/*
 * Advanced SIMD three same (ARMv8.2 FP16 variants)
 *
 *  31  30  29  28       24 23  22 21 20  16 15 14 13    11 10  9    5 4    0
 * +---+---+---+-----------+---------+------+-----+--------+---+------+------+
 * | 0 | Q | U | 0 1 1 1 0 | a | 1 0 |  Rm  | 0 0 | opcode | 1 |  Rn  |  Rd  |
 * +---+---+---+-----------+---------+------+-----+--------+---+------+------+
 *
 * This includes FMULX, FCMEQ (register), FRECPS, FRSQRTS, FCMGE
 * (register), FACGE, FABD, FCMGT (register) and FACGT.
 *
 */
static void disas_simd_three_reg_same_fp16(DisasContext* s, uint32_t insn) { lata_unallocated_encoding(s); }

/* AdvSIMD three same extra
 *  31   30  29 28       24 23  22  21 20  16  15 14    11  10 9  5 4  0
 * +---+---+---+-----------+------+---+------+---+--------+---+----+----+
 * | 0 | Q | U | 0 1 1 1 0 | size | 0 |  Rm  | 1 | opcode | 1 | Rn | Rd |
 * +---+---+---+-----------+------+---+------+---+--------+---+----+----+
 */
static void disas_simd_three_reg_same_extra(DisasContext* s, uint32_t insn)
{
    int is_q = extract32(insn, 30, 1);
    int u = extract32(insn, 29, 1);
    int size = extract32(insn, 22, 2);
    int opcode = extract32(insn, 11, 5);
    int rm = extract32(insn, 16, 5);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);

    if (size == 3) {
        lata_unallocated_encoding(s);
        return;
    }
    if (!fp_access_check(s)) return;

    switch (opcode) {
        case 0x0e: /* SDOT */
        case 0x0f: /* UDOT */
        case 0x12: /* SDOT */
        case 0x13: /* UDOT */
        {
            /* Dot product: 4x 8b signed/unsigned multiply, sum pairs → 32b.
               vilvl_b + sign/zero-extend, vmulwev_w_h + vmulwod_w_h, vadd_w. */
            IR2_OPND vreg_d = alloc_fpr_dst(rd);
            IR2_OPND vn = alloc_fpr_src(rn);
            IR2_OPND vm = alloc_fpr_src(rm);
            IR2_OPND vn_lo = ra_alloc_ftemp(), vn_hi = ra_alloc_ftemp();
            IR2_OPND vm_lo = ra_alloc_ftemp(), vm_hi = ra_alloc_ftemp();
            IR2_OPND vz = ra_alloc_ftemp(); /* 5 ftemps */
            la_vxor_v(vz, vz, vz);
            if (u) {
                la_vilvl_b(vn_lo, vz, vn);
                la_vilvh_b(vn_hi, vz, vn);
                la_vilvl_b(vm_lo, vz, vm);
                la_vilvh_b(vm_hi, vz, vm);
            } else {
                la_vilvl_b(vn_lo, vn, vn);
                la_vslli_h(vn_lo, vn_lo, 8);
                la_vsrai_h(vn_lo, vn_lo, 8);
                la_vilvh_b(vn_hi, vn, vn);
                la_vslli_h(vn_hi, vn_hi, 8);
                la_vsrai_h(vn_hi, vn_hi, 8);
                la_vilvl_b(vm_lo, vm, vm);
                la_vslli_h(vm_lo, vm_lo, 8);
                la_vsrai_h(vm_lo, vm_lo, 8);
                la_vilvh_b(vm_hi, vm, vm);
                la_vslli_h(vm_hi, vm_hi, 8);
                la_vsrai_h(vm_hi, vm_hi, 8);
            }
            free_alloc_fpr(vz); /* free zero, back to 4 ftemps */
            /* Multiply even/odd pairs, sum. 2 more ftemps = 6 max. */
            IR2_OPND prod_lo = ra_alloc_ftemp(), prod_hi = ra_alloc_ftemp();
            la_vmulwev_w_h(prod_lo, vn_lo, vm_lo);
            la_vmulwod_w_h(prod_hi, vn_lo, vm_lo);
            la_vadd_w(vreg_d, prod_lo, prod_hi);
            la_vmulwev_w_h(prod_lo, vn_hi, vm_hi);
            la_vmulwod_w_h(prod_hi, vn_hi, vm_hi);
            la_vadd_w(prod_lo, prod_lo, prod_hi);
            la_vadd_w(vreg_d, vreg_d, prod_lo);
            free_alloc_fpr(prod_lo);
            free_alloc_fpr(prod_hi);
            if (!is_q) la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            store_fpr_dst(rd, vreg_d);
            free_alloc_fpr(vreg_d);
            free_alloc_fpr(vn);
            free_alloc_fpr(vm);
            free_alloc_fpr(vn_lo);
            free_alloc_fpr(vn_hi);
            free_alloc_fpr(vm_lo);
            free_alloc_fpr(vm_hi);
            return;
        }
        case 0x1c: /* FCADD #90 */
        case 0x1e: /* FCADD #270 */
        {
            /* Complex add with rotation.
             * FCADD #90: result[2n]=vn[2n]-vm[2n+1], result[2n+1]=vn[2n+1]+vm[2n]
             * FCADD #270: result[2n]=vn[2n]+vm[2n+1], result[2n+1]=vn[2n+1]-vm[2n]
             * Use vector interleave to pair even/odd elements, then add/sub. */
            IR2_OPND vd = alloc_fpr_dst(rd);
            IR2_OPND vn_re = alloc_fpr_src(rn);
            IR2_OPND vm_im = alloc_fpr_src(rm);
            IR2_OPND ve = ra_alloc_ftemp(); /* even elements: vilvl */
            IR2_OPND vo = ra_alloc_ftemp(); /* odd elements: vilvh */
            IR2_OPND te = ra_alloc_ftemp();
            IR2_OPND to2 = ra_alloc_ftemp();
            bool is270 = (opcode == 0x1e);
            if (size != 3) {
                /* FCADD: complex add with rotation. Use per-element extraction for simplicity. */
                int esize = (size == 0) ? 1 : 3; /* 0→f32(word), else→f64(dword) */
                if (esize == 1) {                /* f32 */
                    IR2_OPND vn_e = ra_alloc_ftemp(), vn_o = ra_alloc_ftemp();
                    IR2_OPND vm_e = ra_alloc_ftemp(), vm_o = ra_alloc_ftemp();
                    IR2_OPND r1 = ra_alloc_ftemp(), r2 = ra_alloc_ftemp();
                    la_vilvl_w(ve, vn_re, vm_im);
                    la_vilvh_w(vo, vn_re, vm_im);
                    la_vilvl_w(vn_e, ve, vo);
                    la_vilvh_w(vm_e, ve, vo);
                    la_vilvh_w(vn_o, vn_e, vn_e);
                    la_vilvh_w(vm_o, vm_e, vm_e);
                    if (is270) {
                        la_vfadd_s(r1, vn_e, vm_o);
                        la_vfsub_s(r2, vn_o, vm_e);
                    } else {
                        la_vfsub_s(r1, vn_e, vm_o);
                        la_vfadd_s(r2, vn_o, vm_e);
                    }
                    la_vilvl_w(vd, r1, r2);
                    free_alloc_fpr(vn_e);
                    free_alloc_fpr(vn_o);
                    free_alloc_fpr(vm_e);
                    free_alloc_fpr(vm_o);
                    free_alloc_fpr(r1);
                    free_alloc_fpr(r2);
                } else { /* f64: 2 elements */
                    IR2_OPND g0 = ra_alloc_itemp(), g1 = ra_alloc_itemp();
                    IR2_OPND g2 = ra_alloc_itemp(), g3 = ra_alloc_itemp();
                    la_vpickve2gr_d(g0, vn_re, 0);
                    la_vpickve2gr_d(g1, vn_re, 1);
                    la_vpickve2gr_d(g2, vm_im, 0);
                    la_vpickve2gr_d(g3, vm_im, 1);
                    IR2_OPND va = ra_alloc_ftemp(), vb = ra_alloc_ftemp(), vc = ra_alloc_ftemp(), vd2 = ra_alloc_ftemp();
                    la_movgr2fr_d(va, g0);
                    la_movgr2fr_d(vb, g1);
                    la_movgr2fr_d(vc, g2);
                    la_movgr2fr_d(vd2, g3);
                    IR2_OPND rr = ra_alloc_ftemp(), ri = ra_alloc_ftemp();
                    if (is270) {
                        la_fadd_d(rr, va, vd2);
                        la_fsub_d(ri, vb, vc);
                    } else {
                        la_fsub_d(rr, va, vd2);
                        la_fadd_d(ri, vb, vc);
                    }
                    la_movfr2gr_d(g0, rr);
                    la_movfr2gr_d(g1, ri);
                    la_vinsgr2vr_d(vd, g0, 0);
                    la_vinsgr2vr_d(vd, g1, 1);
                    free_alloc_fpr(va);
                    free_alloc_fpr(vb);
                    free_alloc_fpr(vc);
                    free_alloc_fpr(vd2);
                    free_alloc_fpr(rr);
                    free_alloc_fpr(ri);
                    free_alloc_gpr(g0);
                    free_alloc_gpr(g1);
                    free_alloc_gpr(g2);
                    free_alloc_gpr(g3);
                }
            } else {
                free_alloc_fpr(vd);
                free_alloc_fpr(vn_re);
                free_alloc_fpr(vm_im);
                free_alloc_fpr(ve);
                free_alloc_fpr(vo);
                free_alloc_fpr(te);
                free_alloc_fpr(to2);
                lata_unallocated_encoding(s);
                return;
            }
            if (!is_q) la_vinsgr2vr_d(vd, zero_ir2_opnd, 1);
            store_fpr_dst(rd, vd);
            free_alloc_fpr(vd);
            free_alloc_fpr(vn_re);
            free_alloc_fpr(vm_im);
            free_alloc_fpr(ve);
            free_alloc_fpr(vo);
            free_alloc_fpr(te);
            free_alloc_fpr(to2);
            return;
        }
        case 0x0c: /* SQDMULH */
        case 0x0d: /* SQRDMULH */
        default:
            lata_unallocated_encoding(s);
            return;
    }
}

static void handle_2misc_widening(DisasContext* s, int opcode, bool is_q,
    int size, int rn, int rd)
{
    /* Handle 2-reg-misc ops which are widening (so each size element
     * in the source becomes a 2*size element in the destination.
     * The only instruction like this is FCVTL.
     */
    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    if (size == 3) {
        /* 32 -> 64 bit fp conversion */
        if (is_q)
            la_vfcvth_d_s(vreg_d, vreg_n);
        else
            la_vfcvtl_d_s(vreg_d, vreg_n);
    } else {
        /* 16 -> 32 bit fp conversion (any size != 3, per QEMU) */
        if (is_q)
            la_vfcvth_s_h(vreg_d, vreg_n);
        else
            la_vfcvtl_s_h(vreg_d, vreg_n);
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
}

static void handle_rev(DisasContext* s, int opcode, bool u,
    bool is_q, int size, int rn, int rd)
{
    int op = (opcode << 1) | u;
    int opsz = op + size;
    // int grp_size = 3 - opsz;
    // int dsize = is_q ? 128 : 64;
    int i;

    if (opsz >= 3) {
        lata_unallocated_encoding(s);
        return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND temp = ra_alloc_itemp();

    switch (op) {
        case 0: /* REV64 */
            for (i = 0; i < (is_q ? 2 : 1); ++i) {
                la_vpickve2gr_d(temp, vreg_n, i);
                switch (size) {
                    case 0:
                        la_revb_d(temp, temp);
                        break;
                    case 1:
                        la_revh_d(temp, temp);
                        break;
                    case 2:
                        la_rotri_d(temp, temp, 32);
                        break;
                    default:
                        break;
                }
                la_vinsgr2vr_d(vreg_d, temp, i);
            }
            break;
        case 1: /* REV32 */
            for (i = 0; i < (is_q ? 2 : 1); ++i) {
                la_vpickve2gr_d(temp, vreg_n, i);
                switch (size) {
                    case 0:
                        la_revb_2w(temp, temp);
                        break;
                    case 1:
                        la_revh_2w(temp, temp);
                        break;
                    default:
                        break;
                }
                la_vinsgr2vr_d(vreg_d, temp, i);
            }
            break;
        case 2: /* REV16: reverse bytes in each 16-bit halfword */
        {
            /* ((x & 0x00FF00FF...) << 8) | ((x & 0xFF00FF00...) >> 8) */
            IR2_OPND mask_lo = ra_alloc_ftemp();
            IR2_OPND mask_hi = ra_alloc_ftemp();
            IR2_OPND tmp_lo = ra_alloc_ftemp();
            IR2_OPND tmp_hi = ra_alloc_ftemp();
            IR2_OPND igpr = ra_alloc_itemp();
            li_w(igpr, 0x00FF);
            la_vreplgr2vr_h(mask_lo, igpr); /* 0x00FF per halfword → FF/00 byte pattern */
            li_w(igpr, 0xFF00);
            la_vreplgr2vr_h(mask_hi, igpr); /* 0xFF00 per halfword → 00/FF byte pattern */
            la_vand_v(tmp_lo, vreg_n, mask_lo);
            la_vslli_h(tmp_lo, tmp_lo, 8); /* low bytes → high position */
            la_vand_v(tmp_hi, vreg_n, mask_hi);
            la_vsrli_h(tmp_hi, tmp_hi, 8); /* high bytes → low position */
            la_vor_v(vreg_d, tmp_lo, tmp_hi);
            free_alloc_fpr(mask_lo);
            free_alloc_fpr(mask_hi);
            free_alloc_fpr(tmp_lo);
            free_alloc_fpr(tmp_hi);
            free_alloc_gpr(igpr);
            break;
        }
    }

    if (!is_q) {
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }
    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_gpr(temp);
}

static void handle_2misc_pairwise(DisasContext* s, int opcode, bool u,
    bool is_q, int size, int rn, int rd)
{
    /* Implement the pairwise operations from 2-misc:
     * SADDLP, UADDLP, SADALP, UADALP.
     * These all add pairs of elements in the input to produce a
     * double-width result element in the output (possibly accumulating).
     */
    bool accum = (opcode == 0x6);
    IR2_OPND vreg_d;
    IR2_OPND vreg_n = alloc_fpr_src(rn);

    if (accum) {
        vreg_d = alloc_fpr_src(rd);
        IR2_OPND vtemp = ra_alloc_ftemp();
        if (u) { // UADALP
            switch (size) {
                case 0:
                    la_vhaddw_hu_bu(vtemp, vreg_n, vreg_n);
                    la_vadd_h(vreg_d, vreg_d, vtemp);
                    break;
                case 1:
                    la_vhaddw_wu_hu(vtemp, vreg_n, vreg_n);
                    la_vadd_w(vreg_d, vreg_d, vtemp);
                    break;
                case 2:
                    la_vhaddw_du_wu(vtemp, vreg_n, vreg_n);
                    la_vadd_d(vreg_d, vreg_d, vtemp);
                    break;
                default:
                    lata_unallocated_encoding(s);
                    return;
            }
        } else { // SADALP
            switch (size) {
                case 0:
                    la_vhaddw_h_b(vtemp, vreg_n, vreg_n);
                    la_vadd_h(vreg_d, vreg_d, vtemp);
                    break;
                case 1:
                    la_vhaddw_w_h(vtemp, vreg_n, vreg_n);
                    la_vadd_w(vreg_d, vreg_d, vtemp);
                    break;
                case 2:
                    la_vhaddw_d_w(vtemp, vreg_n, vreg_n);
                    la_vadd_d(vreg_d, vreg_d, vtemp);
                    break;
                default:
                    lata_unallocated_encoding(s);
                    return;
            }
        }
        free_alloc_gpr(vtemp);
    } else {
        vreg_d = alloc_fpr_dst(rd);
        if (u) { // UADDLP
            switch (size) {
                case 0:
                    la_vhaddw_hu_bu(vreg_d, vreg_n, vreg_n);
                    break;
                case 1:
                    la_vhaddw_wu_hu(vreg_d, vreg_n, vreg_n);
                    break;
                case 2:
                    la_vhaddw_du_wu(vreg_d, vreg_n, vreg_n);
                    break;
                default:
                    lata_unallocated_encoding(s);
                    return;
            }
        } else { // SADDLP
            switch (size) {
                case 0:
                    la_vhaddw_h_b(vreg_d, vreg_n, vreg_n);
                    break;
                case 1:
                    la_vhaddw_w_h(vreg_d, vreg_n, vreg_n);
                    break;
                case 2:
                    la_vhaddw_d_w(vreg_d, vreg_n, vreg_n);
                    break;
                default:
                    lata_unallocated_encoding(s);
                    return;
            }
        }
    }

    if (!is_q) {
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }

    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
}

static void handle_shll(DisasContext* s, bool is_q, int size, int rn, int rd)
{
    IR2_OPND vreg_d = alloc_fpr_src(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vtemp = ra_alloc_ftemp();
    la_vandi_b(vtemp, vtemp, 0);

    if (!is_q) {
        switch (size) {
            case 0:
                la_vilvl_b(vreg_d, vreg_n, vtemp);
                break;
            case 1:
                la_vilvl_h(vreg_d, vreg_n, vtemp);
                break;
            case 2:
                la_vilvl_w(vreg_d, vreg_n, vtemp);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
        }
    } else {
        switch (size) {
            case 0:
                la_vilvh_b(vreg_d, vreg_n, vtemp);
                break;
            case 1:
                la_vilvh_h(vreg_d, vreg_n, vtemp);
                break;
            case 2:
                la_vilvh_w(vreg_d, vreg_n, vtemp);
                break;
            default:
                lata_unallocated_encoding(s);
                return;
        }
    }

    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vtemp);
}

/* AdvSIMD two reg misc
 *   31  30  29 28       24 23  22 21       17 16    12 11 10 9    5 4    0
 * +---+---+---+-----------+------+-----------+--------+-----+------+------+
 * | 0 | Q | U | 0 1 1 1 0 | size | 1 0 0 0 0 | opcode | 1 0 |  Rn  |  Rd  |
 * +---+---+---+-----------+------+-----------+--------+-----+------+------+
 */
static void disas_simd_two_reg_misc(DisasContext* s, uint32_t insn)
{
    int size = extract32(insn, 22, 2);
    int opcode = extract32(insn, 12, 5);
    bool u = extract32(insn, 29, 1);
    bool is_q = extract32(insn, 30, 1);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);

    switch (opcode) {
        case 0x0: /* REV64, REV32 */
        case 0x1: /* REV16 */
            handle_rev(s, opcode, u, is_q, size, rn, rd);
            return;
        case 0x5: /* CNT, NOT, RBIT */
            if (u && size == 0) {
                /* NOT */
                break;
            } else if (u && size == 1) {
                /* RBIT */
                break;
            } else if (!u && size == 0) {
                /* CNT */
                break;
            }
            lata_unallocated_encoding(s);
            return;
        case 0x12: /* XTN, XTN2, SQXTUN, SQXTUN2 */
        case 0x14: /* SQXTN, SQXTN2, UQXTN, UQXTN2 */
            if (size == 3) {
                lata_unallocated_encoding(s);
                return;
            }
            if (!fp_access_check(s)) {
                return;
            }

            handle_2misc_narrow(s, false, opcode, u, is_q, size, rn, rd);
            return;
        case 0x4: /* CLS, CLZ */
            if (size == 3) {
                lata_unallocated_encoding(s);
                return;
            }
            break;
        case 0x2: /* SADDLP, UADDLP */
        case 0x6: /* SADALP, UADALP */
            if (size == 3) {
                lata_unallocated_encoding(s);
                return;
            }
            if (!fp_access_check(s)) {
                return;
            }
            handle_2misc_pairwise(s, opcode, u, is_q, size, rn, rd);
            return;
        case 0x13: /* SHLL, SHLL2 */
            if (u == 0 || size == 3) {
                lata_unallocated_encoding(s);
                return;
            }
            if (!fp_access_check(s)) {
                return;
            }
            handle_shll(s, is_q, size, rn, rd);
            return;
        case 0xa: /* CMLT */
            if (u == 1) {
                lata_unallocated_encoding(s);
                return;
            }
            /* fall through */
        case 0x8: /* CMGT, CMGE */
        case 0x9: /* CMEQ, CMLE */
        case 0xb: /* ABS, NEG */
            if (size == 3 && !is_q) {
                lata_unallocated_encoding(s);
                return;
            }
            break;
        case 0x3: /* SUQADD, USQADD */
            if (size == 3 && !is_q) {
                lata_unallocated_encoding(s);
                return;
            }
            if (!fp_access_check(s)) {
                return;
            }
            handle_2misc_satacc(s, false, u, is_q, size, rn, rd);
            return;
        case 0x7: /* SQABS, SQNEG */
            if (size == 3 && !is_q) {
                lata_unallocated_encoding(s);
                return;
            }
            break;
        case 0xc ... 0xf:
        case 0x16 ... 0x1f: {
            /* Floating point: U, size[1] and opcode indicate operation;
             * size[0] indicates single or double precision.
             */
            int is_double = extract32(size, 0, 1);
            opcode |= (extract32(size, 1, 1) << 5) | (u << 6);
            size = is_double ? 3 : 2;

            /* Note: FRECPE/FRSQRTE (raw 0x1d) now have standalone decode
             * entries, so they no longer reach this switch.  Case values
             * 0x3d/0x3f/0x7d here are used for FCVTPS/FCVTZS/FCVTPU. */

            switch (opcode) {
                case 0x2f: /* FABS */
                case 0x6f: /* FNEG */
                    if (size == 3 && !is_q) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    break;
                case 0x1d: /* SCVTF */
                case 0x5d: /* UCVTF */
                {
                    bool is_signed = (opcode == 0x1d) ? true : false;
                    int elements = is_double ? 2 : is_q ? 4
                                                        : 2;
                    if (is_double && !is_q) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_simd_intfp_conv(s, rd, rn, elements, is_signed, 0, size);
                    return;
                }
                case 0x2c: /* FCMGT (zero) */
                case 0x2d: /* FCMEQ (zero) */
                case 0x2e: /* FCMLT (zero) */
                case 0x6c: /* FCMGE (zero) */
                case 0x6d: /* FCMLE (zero) */
                    if (size == 3 && !is_q) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    handle_2misc_fcmp_zero(s, opcode, false, u, is_q, size, rn, rd);
                    return;
                case 0x7f: /* FSQRT */
                    if (size == 3 && !is_q) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    break;
                case 0x1a: /* FCVTNS */
                case 0x1b: /* FCVTMS */
                case 0x3a: /* FCVTPS */
                case 0x3b: /* FCVTZS */
                case 0x5a: /* FCVTNU */
                case 0x5b: /* FCVTMU */
                case 0x7a: /* FCVTPU */
                case 0x7b: /* FCVTZU */
                    // need_fpstatus = true;
                    // rmode = extract32(opcode, 5, 1) | (extract32(opcode, 0, 1) << 1);
                    if (size == 3 && !is_q) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    break;
                case 0x5c: /* FCVTAU */
                case 0x1c: /* FCVTAS */
                    // need_fpstatus = true;
                    // rmode = FPROUNDING_TIEAWAY;
                    if (size == 3 && !is_q) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    break;
                case 0x3c: /* URECPE */
                    if (size == 3) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    /* fall through */
                case 0x3d: /* FRECPE */
                case 0x7d: /* FRSQRTE */
                    if (size == 3 && !is_q) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_2misc_reciprocal(s, opcode, false, u, is_q, size, rn, rd);
                    return;
                    if (size == 3 && !is_q) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_2misc_reciprocal(s, opcode, false, u, is_q, size, rn, rd);
                    return;
                case 0x56: /* FCVTXN, FCVTXN2 */
                case 0x16: /* FCVTN, FCVTN2 */
                    /* handle_2misc_narrow does a 2*size -> size operation, but these
                     * instructions encode the source size rather than dest size.
                     */
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_2misc_narrow(s, false, opcode, 0, is_q, size - 1, rn, rd);
                    return;
                case 0x36: /* BFCVTN, BFCVTN2 */
                    if (!dc_isar_feature(aa64_bf16, s) || size != 2) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_2misc_narrow(s, false, opcode, 0, is_q, size - 1, rn, rd);
                    return;
                case 0x17: /* FCVTL, FCVTL2 */
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_2misc_widening(s, opcode, is_q, size, rn, rd);
                    return;
                case 0x18: /* FRINTN */
                case 0x19: /* FRINTM */
                case 0x38: /* FRINTP */
                case 0x39: /* FRINTZ */
                    // rmode = extract32(opcode, 5, 1) | (extract32(opcode, 0, 1) << 1);
                    /* fall through */
                case 0x59: /* FRINTX */
                case 0x79: /* FRINTI */
                    // need_fpstatus = true;
                    if (size == 3 && !is_q) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    break;
                case 0x58: /* FRINTA */
                    // rmode = FPROUNDING_TIEAWAY;
                    // need_fpstatus = true;
                    if (size == 3 && !is_q) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    break;
                case 0x7c: /* URSQRTE */
                    if (size == 3) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    if (!fp_access_check(s)) {
                        return;
                    }
                    handle_2misc_reciprocal(s, opcode, false, u, is_q, size, rn, rd);
                    return;
                case 0x1e: /* FRINT32Z */
                case 0x1f: /* FRINT64Z */
                    // rmode = FPROUNDING_ZERO;
                    /* fall through */
                case 0x5e: /* FRINT32X */
                case 0x5f: /* FRINT64X */
                    // need_fpstatus = true;
                    if ((size == 3 && !is_q) || !dc_isar_feature(aa64_frint, s)) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    break;
                default:
                    lata_unallocated_encoding(s);
                    return;
            }
            break;
        }
        default:
            lata_unallocated_encoding(s);
            return;
    }

    if (!fp_access_check(s)) {
        return;
    }

    if (((opcode == 0x1c && size == MO_64) || opcode == 0x5a || opcode == 0x5b ||
         (opcode == 0x5c && size == MO_64) || opcode == 0x7a) &&
        gen_simd_fcvt_fpint_helper(s, opcode, is_q, size, rn, rd)) {
        return;
    }

    IR2_OPND vreg_d = alloc_fpr_dst(rd);
    IR2_OPND vreg_n = alloc_fpr_src(rn);

    switch (opcode) {
        case 0x5: /* CNT (u=0), NOT (u=1,size=0), RBIT (u=1,size>0) */
            if (u) {
                if (size == 0) { /* NOT */
                    la_vnori_b(vreg_d, vreg_n, 0);
                } else { /* RBIT: reverse bits within each byte */
                    IR2_OPND gpr_lo = ra_alloc_itemp();
                    IR2_OPND gpr_hi;
                    la_vpickve2gr_d(gpr_lo, vreg_n, 0);
                    la_bitrev_8b(gpr_lo, gpr_lo);
                    if (is_q) {
                        gpr_hi = ra_alloc_itemp();
                        la_vpickve2gr_d(gpr_hi, vreg_n, 1);
                        la_bitrev_8b(gpr_hi, gpr_hi);
                        la_vinsgr2vr_d(vreg_d, gpr_lo, 0);
                        la_vinsgr2vr_d(vreg_d, gpr_hi, 1);
                        ra_free_itemp(gpr_hi._reg_num);
                    } else {
                        la_vinsgr2vr_d(vreg_d, gpr_lo, 0);
                    }
                    ra_free_itemp(gpr_lo._reg_num);
                }
            } else { /* CNT */
                la_vpcnt_b(vreg_d, vreg_n);
            }
            if (!is_q) la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            store_fpr_dst(rd, vreg_d);
            free_alloc_fpr(vreg_d);
            free_alloc_fpr(vreg_n);
            return;
        case 0x4: /* CLS, CLZ */
            if (u) {
                /* CLZ: u=1, count leading zeros */
                switch (size) {
                    case 0: la_vclz_b(vreg_d, vreg_n); break;
                    case 1: la_vclz_h(vreg_d, vreg_n); break;
                    case 2: la_vclz_w(vreg_d, vreg_n); break;
                    case 3: la_vclz_d(vreg_d, vreg_n); break;
                }
            } else {
                /* CLS: u=0, count leading sign bits.
                   CLS(x) = leading_sign_bits(x) - 1.
                   Use CLO for negative, CLZ for positive/zero. */
                {
                    IR2_OPND vclo_v = ra_alloc_ftemp();
                    IR2_OPND vclz_v = ra_alloc_ftemp();
                    IR2_OPND vsgn_v = ra_alloc_ftemp();
                    IR2_OPND vone_v = ra_alloc_ftemp();
                    switch (size) {
                        case 0:
                            la_vclo_b(vclo_v, vreg_n);
                            la_vclz_b(vclz_v, vreg_n);
                            la_vslti_b(vsgn_v, vreg_n, 0);
                            break;
                        case 1:
                            la_vclo_h(vclo_v, vreg_n);
                            la_vclz_h(vclz_v, vreg_n);
                            la_vslti_h(vsgn_v, vreg_n, 0);
                            break;
                        case 2:
                            la_vclo_w(vclo_v, vreg_n);
                            la_vclz_w(vclz_v, vreg_n);
                            la_vslti_w(vsgn_v, vreg_n, 0);
                            break;
                        case 3:
                            la_vclo_d(vclo_v, vreg_n);
                            la_vclz_d(vclz_v, vreg_n);
                            la_vslti_d(vsgn_v, vreg_n, 0);
                            break;
                    }
                    /* vsgn=-1(neg): select vclo; vsgn=0(pos): select vclz */
                    la_vbitsel_v(vreg_d, vclz_v, vclo_v, vsgn_v);
                    /* Subtract 1: CLS = leading_sign_bits - 1 */
                    la_vxor_v(vone_v, vone_v, vone_v);   /* all zeros */
                    la_vnori_b(vone_v, vone_v, 0);        /* all ones = -1 */
                    switch (size) {
                        case 0: la_vadd_b(vreg_d, vreg_d, vone_v); break;
                        case 1: la_vadd_h(vreg_d, vreg_d, vone_v); break;
                        case 2: la_vadd_w(vreg_d, vreg_d, vone_v); break;
                        case 3: la_vadd_d(vreg_d, vreg_d, vone_v); break;
                    }
                    free_alloc_fpr(vclo_v);
                    free_alloc_fpr(vclz_v);
                    free_alloc_fpr(vsgn_v);
                    free_alloc_fpr(vone_v);
                }
            }
            if (!is_q) la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            store_fpr_dst(rd, vreg_d);
            free_alloc_fpr(vreg_d);
            free_alloc_fpr(vreg_n);
            return;

        case 0x8: /* CMGT, CMGE */
            switch (size) {
                case 0:
                    if (u) {
                        la_vslti_b(vreg_d, vreg_n, 0);
                    } else {
                        la_vslei_b(vreg_d, vreg_n, 0);
                    }
                    break;
                case 1:
                    if (u) {
                        la_vslti_h(vreg_d, vreg_n, 0);
                    } else {
                        la_vslei_h(vreg_d, vreg_n, 0);
                    }
                    break;
                case 2:
                    if (u) {
                        la_vslti_w(vreg_d, vreg_n, 0);
                    } else {
                        la_vslei_w(vreg_d, vreg_n, 0);
                    }
                    break;
                case 3:
                    if (u) {
                        la_vslti_d(vreg_d, vreg_n, 0);
                    } else {
                        la_vslei_d(vreg_d, vreg_n, 0);
                    }
                    break;
                default:
                    break;
            }
            la_vnori_b(vreg_d, vreg_d, 0);
            if (!is_q) {
                /* 高64位清零 */
                la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            }
            store_fpr_dst(rd, vreg_d);
            free_alloc_fpr(vreg_d);
            free_alloc_fpr(vreg_n);
            return;
        case 0x9: /* CMEQ, CMLE */
            switch (size) {
                case 0:
                    if (u) {
                        la_vslei_b(vreg_d, vreg_n, 0);
                    } else {
                        la_vseqi_b(vreg_d, vreg_n, 0);
                    }
                    break;
                case 1:
                    if (u) {
                        la_vslei_h(vreg_d, vreg_n, 0);
                    } else {
                        la_vseqi_h(vreg_d, vreg_n, 0);
                    }
                    break;
                case 2:
                    if (u) {
                        la_vslei_w(vreg_d, vreg_n, 0);
                    } else {
                        la_vseqi_w(vreg_d, vreg_n, 0);
                    }
                    break;
                case 3:
                    if (u) {
                        la_vslei_d(vreg_d, vreg_n, 0);
                    } else {
                        la_vseqi_d(vreg_d, vreg_n, 0);
                    }
                    break;
                default:
                    break;
            }
            if (!is_q) {
                /* 高64位清零 */
                la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            }
            store_fpr_dst(rd, vreg_d);
            free_alloc_fpr(vreg_d);
            free_alloc_fpr(vreg_n);
            return;
        case 0xa: /* CMLT */
            switch (size) {
                case 0:
                    la_vslti_b(vreg_d, vreg_n, 0);
                    break;
                case 1:
                    la_vslti_h(vreg_d, vreg_n, 0);
                    break;
                case 2:
                    la_vslti_w(vreg_d, vreg_n, 0);
                    break;
                case 3:
                    la_vslti_d(vreg_d, vreg_n, 0);
                    break;
                default:
                    break;
            }
            if (!is_q) {
                /* 高64位清零 */
                la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            }
            store_fpr_dst(rd, vreg_d);
            free_alloc_fpr(vreg_d);
            free_alloc_fpr(vreg_n);
            return;
        case 0xb: /* ABS (u=0) or NEG (u=1) */
        {
            IR2_OPND vzero_op = ra_alloc_ftemp();
            la_vxor_v(vzero_op, vzero_op, vzero_op);
            if (u) {
                /* NEG: vd = 0 - vn */
                switch (size) {
                    case 0: la_vsub_b(vreg_d, vzero_op, vreg_n); break;
                    case 1: la_vsub_h(vreg_d, vzero_op, vreg_n); break;
                    case 2: la_vsub_w(vreg_d, vzero_op, vreg_n); break;
                    case 3: la_vsub_d(vreg_d, vzero_op, vreg_n); break;
                }
            } else {
                /* ABS: vd = |vn| via vabsd(vn, 0) */
                switch (size) {
                    case 0: la_vabsd_b(vreg_d, vreg_n, vzero_op); break;
                    case 1: la_vabsd_h(vreg_d, vreg_n, vzero_op); break;
                    case 2: la_vabsd_w(vreg_d, vreg_n, vzero_op); break;
                    case 3: la_vabsd_d(vreg_d, vreg_n, vzero_op); break;
                }
            }
            free_alloc_fpr(vzero_op);
            if (!is_q) {
                /* 高64位清零 */
                la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
            }
            store_fpr_dst(rd, vreg_d);
            free_alloc_fpr(vreg_d);
            free_alloc_fpr(vreg_n);
            return;
        }
    }

    if (size == 3) {
        /* All 64-bit element operations can be shared with scalar 2misc */

        /* Coverity claims (size == 3 && !is_q) has been eliminated
         * from all paths leading to here.
         */
        assert(is_q);

        handle_2misc_64(s, opcode, u, &vreg_d, &vreg_n);
    } else {

        IR2_OPND vtemp = ra_alloc_ftemp();
        if (size == 2) {
            /* Special cases for 32 bit elements */
            switch (opcode) {
                case 0x4: /* CLS — count leading sign bits (32-bit) */
                {
                    IR2_OPND vclo_v = ra_alloc_ftemp();
                    IR2_OPND vclz_v = ra_alloc_ftemp();
                    IR2_OPND vsgn_v = ra_alloc_ftemp();
                    IR2_OPND vone_v = ra_alloc_ftemp();
                    la_vclo_w(vclo_v, vreg_n);
                    la_vclz_w(vclz_v, vreg_n);
                    la_vslti_w(vsgn_v, vreg_n, 0);
                    la_vbitsel_v(vreg_d, vclz_v, vclo_v, vsgn_v);
                    la_vnori_b(vone_v, vone_v, 0);
                    la_vadd_w(vreg_d, vreg_d, vone_v); /* subtract 1 */
                    free_alloc_fpr(vclo_v);
                    free_alloc_fpr(vclz_v);
                    free_alloc_fpr(vsgn_v);
                    free_alloc_fpr(vone_v);
                    break;
                }
                case 0x7: /* SQABS, SQNEG — 32-bit only in this block */
                {
                    IR2_OPND vzero_sq = ra_alloc_ftemp();
                    IR2_OPND vneg = ra_alloc_ftemp();
                    la_vxor_v(vzero_sq, vzero_sq, vzero_sq);
                    if (u) {
                        /* SQNEG: vd = saturating_neg(vn) = vssub(0, vn) */
                        la_vssub_w(vreg_d, vzero_sq, vreg_n);
                    } else {
                        /* SQABS: vd = saturating_abs(vn) = max(vn, vssub(0, vn))
                         * vabsd(a,0) gives |a| but DOES NOT saturate INT_MIN → INT_MAX.
                         * Must use vssub(0, vn) + vmax(vn, neg_vn) per dynarmic. */
                        la_vssub_w(vneg, vzero_sq, vreg_n);
                        la_vmax_w(vreg_d, vreg_n, vneg);
                    }
                    free_alloc_fpr(vzero_sq);
                    free_alloc_fpr(vneg);
                    break;
                }
                case 0x2f: /* FABS */
                    for (int i = 0; i < (is_q ? 4 : 2); ++i) {
                        la_vreplvei_w(vtemp, vreg_n, i);
                        la_fabs_s(vtemp, vtemp);
                        la_vextrins_w(vreg_d, vtemp, i << 4);
                    }
                    break;
                case 0x6f: /* FNEG */
                    for (int i = 0; i < (is_q ? 4 : 2); ++i) {
                        la_vreplvei_w(vtemp, vreg_n, i);
                        la_fneg_s(vtemp, vtemp);
                        la_vextrins_w(vreg_d, vtemp, i << 4);
                    }
                    break;
                case 0x7f: /* FSQRT */
                    la_vfsqrt_s(vreg_d, vreg_n);
                    break;
                case 0x1a: /* FCVTNS */
                    la_vftintrne_w_s(vreg_d, vreg_n);
                    break;
                case 0x1b: /* FCVTMS */
                    la_vftintrm_w_s(vreg_d, vreg_n);
                    break;
                case 0x1c: /* FCVTAS — nearest ties away, sign*floor(|x|+0.5) */
                {
                    IR2_OPND src = vtemp;
                    IR2_OPND abs_x = ra_alloc_ftemp();
                    IR2_OPND half_v = ra_alloc_ftemp();
                    IR2_OPND neg_res = ra_alloc_ftemp();
                    IR2_OPND sign_mask = ra_alloc_ftemp();
                    IR2_OPND zero = ra_alloc_ftemp();
                    IR2_OPND igpr = ra_alloc_itemp();

                    la_vori_b(src, vreg_n, 0);
                    /* |x| via AND with 0x7fffffff (clear sign bit) */
                    if (size == MO_32) {
                        li_w(igpr, 0x7fffffff);
                        la_vreplgr2vr_w(abs_x, igpr);
                    } else {
                        li_d(igpr, 0x7fffffffffffffffLL);
                        la_vreplgr2vr_d(abs_x, igpr);
                    }
                    la_vand_v(abs_x, abs_x, src); /* |x| */
                    if (size == MO_32) {
                        li_w(igpr, 0x3f000000); /* 0.5f each lane */
                        la_vreplgr2vr_w(half_v, igpr);
                        la_vfadd_s(half_v, abs_x, half_v); /* |x|+0.5 */
                        la_vftintrm_w_s(vreg_d, half_v);   /* floor */
                    } else {
                        li_d(igpr, 0x3fe0000000000000LL);
                        la_vreplgr2vr_d(half_v, igpr);
                        la_vfadd_d(half_v, abs_x, half_v); /* |x|+0.5 */
                        la_vftintrm_l_d(vreg_d, half_v);   /* floor */
                    }
                    /* The rounded magnitude is already integer bits.  Apply the
                     * original sign with integer negation; OR-ing the FP sign bit
                     * into the integer result produces 0x8000005b instead of -91. */
                    la_vxor_v(zero, zero, zero);
                    if (size == MO_32) {
                        la_vsub_w(neg_res, zero, vreg_d);
                        la_vsrai_w(sign_mask, src, 31);
                    } else {
                        la_vsub_d(neg_res, zero, vreg_d);
                        la_vsrai_d(sign_mask, src, 63);
                    }
                    la_vbitsel_v(vreg_d, vreg_d, neg_res, sign_mask);
                    /* Reuse the existing six temporaries for the boundary
                     * clamps: abs_x=min_mask, half_v=FP boundary constant,
                     * neg_res=saturation value, sign_mask=max_mask, zero=max. */
                    if (size == MO_32) {
                        li_w(igpr, 0xcf000000u); /* -2^31 as f32 */
                        la_vreplgr2vr_w(half_v, igpr);
                        la_vfcmp_cond_s(abs_x, src, half_v, FCMP_COND_CLE);
                        li_w(igpr, 0x4f000000u); /* 2^31 as f32 */
                        la_vreplgr2vr_w(half_v, igpr);
                        la_vfcmp_cond_s(sign_mask, half_v, src, FCMP_COND_CLE);
                        li_wu(igpr, 0x80000000u);
                        la_vreplgr2vr_w(neg_res, igpr);
                        li_wu(igpr, 0x7fffffffu);
                        la_vreplgr2vr_w(zero, igpr);
                    } else {
                        li_d(igpr, 0xc3e0000000000000ULL); /* -2^63 as f64 */
                        la_vreplgr2vr_d(half_v, igpr);
                        la_vfcmp_cond_d(abs_x, src, half_v, FCMP_COND_CLE);
                        li_d(igpr, 0x43e0000000000000ULL); /* 2^63 as f64 */
                        la_vreplgr2vr_d(half_v, igpr);
                        la_vfcmp_cond_d(sign_mask, half_v, src, FCMP_COND_CLE);
                        li_d(igpr, 0x8000000000000000ULL);
                        la_vreplgr2vr_d(neg_res, igpr);
                        li_d(igpr, 0x7fffffffffffffffULL);
                        la_vreplgr2vr_d(zero, igpr);
                    }
                    la_vbitsel_v(vreg_d, vreg_d, neg_res, abs_x);
                    la_vbitsel_v(vreg_d, vreg_d, zero, sign_mask);
                    free_alloc_fpr(abs_x);
                    free_alloc_fpr(half_v);
                    free_alloc_fpr(neg_res);
                    free_alloc_fpr(sign_mask);
                    free_alloc_fpr(zero);
                    free_alloc_gpr(igpr);
                    break;
                }
                case 0x3a: /* FCVTPS */
                    la_vftintrp_w_s(vreg_d, vreg_n);
                    break;
                    ;
                case 0x3b: /* FCVTZS */
                    la_vftintrz_w_s(vreg_d, vreg_n);
                    break;
                case 0x5a: /* FCVTNU — nearest even, unsigned */
                case 0x5b: /* FCVTMU — toward -inf, unsigned */
                case 0x5c: /* FCVTAU — nearest away, unsigned */
                case 0x7a: /* FCVTPU — toward +inf, unsigned */
                {
                    /* LSX lacks non-trunc unsigned vftint.  Use signed conversion
                     * with the same rounding mode, then clamp negative → 0.
                     * Values > INT32_MAX saturate at INT32_MAX (close enough). */
                    IR2_OPND zero = ra_alloc_ftemp();
                    IR2_OPND nonneg = ra_alloc_ftemp();
                    IR2_OPND overflow = ra_alloc_ftemp();
                    IR2_OPND umax = ra_alloc_ftemp();
                    la_vxor_v(zero, zero, zero);
                    switch (opcode) {
                        case 0x5a: la_vftintrne_w_s(vreg_d, vreg_n); break;
                        case 0x5b: la_vftintrm_w_s(vreg_d, vreg_n); break;
                        case 0x5c: /* FCVTAU: use same sign*floor(|x|+0.5) as FCVTAS */
                        {
                            IR2_OPND src = vtemp;
                            IR2_OPND half_v = ra_alloc_ftemp();
                            IR2_OPND igpr = ra_alloc_itemp();
                            la_vori_b(src, vreg_n, 0);
                            li_w(igpr, 0x3f000000);
                            la_vreplgr2vr_w(half_v, igpr);
                            la_vfadd_s(half_v, src, half_v);
                            la_vftintrm_w_s(vreg_d, half_v);
                            la_vfcmp_cond_s(nonneg, zero, src, FCMP_COND_CLE);
                            li_w(igpr, 0x4f800000); /* 2^32 */
                            la_vreplgr2vr_w(half_v, igpr);
                            la_vfcmp_cond_s(overflow, half_v, src, FCMP_COND_CLE);
                            free_alloc_fpr(half_v);
                            free_alloc_gpr(igpr);
                            break;
                        }
                        case 0x7a: la_vftintrp_w_s(vreg_d, vreg_n); break;
                    }
                    /* Ordered compare: negative and NaN both select zero for
                     * ARM unsigned FP-to-int conversions. */
                    if (opcode != 0x5c) {
                        la_vfcmp_cond_s(nonneg, zero, vreg_n, FCMP_COND_CLE);
                    }
                    la_vbitsel_v(vreg_d, zero, vreg_d, nonneg);
                    if (opcode == 0x5c) {
                        la_vnori_b(umax, zero, 0);
                        la_vbitsel_v(vreg_d, vreg_d, umax, overflow);
                    }
                    free_alloc_fpr(zero);
                    free_alloc_fpr(nonneg);
                    free_alloc_fpr(overflow);
                    free_alloc_fpr(umax);
                    break;
                }
                case 0x7b: /* FCVTZU */
                    la_vftintrz_wu_s(vreg_d, vreg_n);
                    break;
                case 0x18: /* FRINTN */
                    la_vfrintrne_s(vreg_d, vreg_n);
                    break;
                case 0x19: /* FRINTM */
                    la_vfrintrm_s(vreg_d, vreg_n);
                    break;
                case 0x38: /* FRINTP */
                    la_vfrintrp_s(vreg_d, vreg_n);
                    break;
                case 0x39: /* FRINTZ */
                    la_vfrintrz_s(vreg_d, vreg_n);
                    break;
                case 0x58: /* FRINTA: ties away from zero */
                {
                    /* FRINTA(x) = sign(x) * floor(|x| + 0.5) via integer bit ops */
                    IR2_OPND sign_bits = ra_alloc_ftemp();
                    IR2_OPND vhalf = ra_alloc_ftemp();

                    /* sign_bits = Vn & 0x80000000 */
                    IR2_OPND itemp_tmp = ra_alloc_itemp();
                    la_addi_w(itemp_tmp, zero_ir2_opnd, 1);
                    la_slli_w(itemp_tmp, itemp_tmp, 31);
                    la_vreplgr2vr_w(sign_bits, itemp_tmp);
                    la_vand_v(sign_bits, sign_bits, vreg_n);

                    /* abs_val = Vn & 0x7FFFFFFF (clear sign bit), reuse vtemp */
                    la_vreplgr2vr_w(vtemp, itemp_tmp);
                    la_vandn_v(vtemp, vtemp, vreg_n);

                    /* Load 0.5 constant */
                    la_lu12i_w(itemp_tmp, 0x3f000);
                    la_vreplgr2vr_w(vhalf, itemp_tmp);
                    free_alloc_gpr(itemp_tmp);

                    /* vreg_d = floor(|Vn| + 0.5) */
                    la_vfadd_s(vreg_d, vtemp, vhalf);
                    la_vfrintrm_s(vreg_d, vreg_d);

                    /* Apply sign bits: result = floor_result | sign_bits */
                    la_vor_v(vreg_d, vreg_d, sign_bits);

                    free_alloc_fpr(sign_bits);
                    free_alloc_fpr(vhalf);
                    break;
                }
                case 0x79: /* FRINTI: round per FPCR */
                case 0x59: /* FRINTX: round per FPCR, signal inexact */
                    la_vfrint_s(vreg_d, vreg_n);
                    break;
                case 0x7c: /* URSQRTE */
                    break;
                case 0x1e: /* FRINT32Z */
                case 0x5e: /* FRINT32X */
                    break;
                case 0x1f: /* FRINT64Z */
                case 0x5f: /* FRINT64X */
                    break;
                default:
                    g_assert_not_reached();
            }
            free_alloc_fpr(vtemp);
        } else {
            /* Use helpers for 8 and 16 bit elements */
            switch (opcode) {
                case 0x5:    /* CNT, RBIT */
                    if (u) { // RBIT: reverse bits within each byte
                        IR2_OPND gpr_lo = ra_alloc_itemp();
                        IR2_OPND gpr_hi;
                        la_vpickve2gr_d(gpr_lo, vreg_n, 0);
                        la_bitrev_8b(gpr_lo, gpr_lo);
                        if (is_q) {
                            gpr_hi = ra_alloc_itemp();
                            la_vpickve2gr_d(gpr_hi, vreg_n, 1);
                            la_bitrev_8b(gpr_hi, gpr_hi);
                            la_vinsgr2vr_d(vreg_d, gpr_lo, 0);
                            la_vinsgr2vr_d(vreg_d, gpr_hi, 1);
                            ra_free_itemp(gpr_hi._reg_num);
                        } else {
                            la_vinsgr2vr_d(vreg_d, gpr_lo, 0);
                        }
                        ra_free_itemp(gpr_lo._reg_num);
                    } else { // CNT: population count
                        la_vpcnt_b(vreg_d, vreg_n);
                    }
                    break;
                case 0x7: /* SQABS, SQNEG — 8-bit / 16-bit */
                {
                    IR2_OPND vzero_sq = ra_alloc_ftemp();
                    IR2_OPND vneg = ra_alloc_ftemp();
                    la_vxor_v(vzero_sq, vzero_sq, vzero_sq);
                    if (u) {
                        /* SQNEG: vd = vssub(0, vn) */
                        if (size == 0) {
                            la_vssub_b(vreg_d, vzero_sq, vreg_n);
                        } else {
                            la_vssub_h(vreg_d, vzero_sq, vreg_n);
                        }
                    } else {
                        /* SQABS: vd = vmax(vn, vssub(0, vn)) */
                        if (size == 0) {
                            la_vssub_b(vneg, vzero_sq, vreg_n);
                            la_vmax_b(vreg_d, vreg_n, vneg);
                        } else {
                            la_vssub_h(vneg, vzero_sq, vreg_n);
                            la_vmax_h(vreg_d, vreg_n, vneg);
                        }
                    }
                    free_alloc_fpr(vzero_sq);
                    free_alloc_fpr(vneg);
                    break;
                }
                case 0x4: /* CLS, CLZ */
                    if (u) {
                        /* CLZ: u=1, count leading zeros */
                        switch (size) {
                            case 0: la_vclz_b(vreg_d, vreg_n); break;
                            case 1: la_vclz_h(vreg_d, vreg_n); break;
                            case 2: la_vclz_w(vreg_d, vreg_n); break;
                        }
                    } else {
                        /* CLS: u=0, count leading sign bits.
                           CLS(x) = leading_sign_bits(x) - 1.
                           Use CLO for negative, CLZ for positive. */
                        {
                            IR2_OPND vclo_v = ra_alloc_ftemp();
                            IR2_OPND vclz_v = ra_alloc_ftemp();
                            IR2_OPND vsgn_v = ra_alloc_ftemp();
                            IR2_OPND vone_v = ra_alloc_ftemp();
                            switch (size) {
                                case 0:
                                    la_vclo_b(vclo_v, vreg_n);
                                    la_vclz_b(vclz_v, vreg_n);
                                    la_vslti_b(vsgn_v, vreg_n, 0);
                                    break;
                                case 1:
                                    la_vclo_h(vclo_v, vreg_n);
                                    la_vclz_h(vclz_v, vreg_n);
                                    la_vslti_h(vsgn_v, vreg_n, 0);
                                    break;
                                case 2:
                                    la_vclo_w(vclo_v, vreg_n);
                                    la_vclz_w(vclz_v, vreg_n);
                                    la_vslti_w(vsgn_v, vreg_n, 0);
                                    break;
                            }
                            /* vsgn=-1(neg): select vclo; vsgn=0(pos): select vclz */
                            la_vbitsel_v(vreg_d, vclz_v, vclo_v, vsgn_v);
                            /* Subtract 1: CLS = leading_sign_bits - 1 */
                            la_vnori_b(vone_v, vone_v, 0); /* all ones */
                            switch (size) {
                                case 0: la_vadd_b(vreg_d, vreg_d, vone_v); break;
                                case 1: la_vadd_h(vreg_d, vreg_d, vone_v); break;
                                case 2: la_vadd_w(vreg_d, vreg_d, vone_v); break;
                            }
                            free_alloc_fpr(vclo_v);
                            free_alloc_fpr(vclz_v);
                            free_alloc_fpr(vsgn_v);
                            free_alloc_fpr(vone_v);
                        }
                    }
                    break;
                default:
                    g_assert_not_reached();
            }
        }
    }

    if (!is_q) {
        /* 高64位清零 */
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }
    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
}

/* AdvSIMD [scalar] two register miscellaneous (FP16)
 *
 *   31  30  29 28  27     24  23 22 21       17 16    12 11 10 9    5 4    0
 * +---+---+---+---+---------+---+-------------+--------+-----+------+------+
 * | 0 | Q | U | S | 1 1 1 0 | a | 1 1 1 1 0 0 | opcode | 1 0 |  Rn  |  Rd  |
 * +---+---+---+---+---------+---+-------------+--------+-----+------+------+
 *   mask: 1000 1111 0111 1110 0000 1100 0000 0000 0x8f7e 0c00
 *   val:  0000 1110 0111 1000 0000 1000 0000 0000 0x0e78 0800
 *
 * This actually covers two groups where scalar access is governed by
 * bit 28. A bunch of the instructions (float to integral) only exist
 * in the vector form and are un-allocated for the scalar decode. Also
 * in the scalar decode Q is always 1.
 */
static void disas_simd_two_reg_misc_fp16(DisasContext* s, uint32_t insn)
{
    /* FP16 variant of two-reg misc. Handles half-precision float ops. */
    int rd = extract32(insn, 0, 5);
    int rn = extract32(insn, 5, 5);
    int opcode = extract32(insn, 12, 5);
    int a = extract32(insn, 23, 1);
    bool u = extract32(insn, 29, 1);
    bool is_q = extract32(insn, 30, 1);
    bool is_scalar = extract32(insn, 28, 1);
    int fpop = deposit32(opcode, 5, 1, a);
    fpop = deposit32(fpop, 6, 1, u);
    if (!fp_access_check(s)) return;
    switch (fpop) {
        case 0x1d: /* SCVTF */
        case 0x5d: /* UCVTF */
            handle_simd_intfp_conv(s, rd, rn, is_scalar ? 1 : (is_q ? 8 : 4),
                                   !u, 0, MO_16);
            return;
        case 0x16: /* FCVTN */
        case 0x56: /* FCVTXN */
            if (!is_q) {
                IR2_OPND vd = alloc_fpr_dst(rd);
                IR2_OPND vn = alloc_fpr_src(rn);
                la_vfcvt_h_s(vd, vn, vn);
                store_fpr_dst(rd, vd);
                free_alloc_fpr(vd);
                free_alloc_fpr(vn);
            } else
                lata_unallocated_encoding(s);
            return;
        case 0x17: /* FCVTL */
        {
            IR2_OPND vd = alloc_fpr_dst(rd);
            IR2_OPND vn = alloc_fpr_src(rn);
            if (is_q)
                la_vfcvth_s_h(vd, vn);
            else
                la_vfcvtl_s_h(vd, vn);
            store_fpr_dst(rd, vd);
            free_alloc_fpr(vd);
            free_alloc_fpr(vn);
        }
            return;
        default:
            lata_unallocated_encoding(s);
            return;
    }
}

/* AdvSIMD scalar x indexed element
 *  31 30  29 28       24 23  22 21  20  19  16 15 12  11  10 9    5 4    0
 * +-----+---+-----------+------+---+---+------+-----+---+---+------+------+
 * | 0 1 | U | 1 1 1 1 1 | size | L | M |  Rm  | opc | H | 0 |  Rn  |  Rd  |
 * +-----+---+-----------+------+---+---+------+-----+---+---+------+------+
 * AdvSIMD vector x indexed element
 *   31  30  29 28       24 23  22 21  20  19  16 15 12  11  10 9    5 4    0
 * +---+---+---+-----------+------+---+---+------+-----+---+---+------+------+
 * | 0 | Q | U | 0 1 1 1 1 | size | L | M |  Rm  | opc | H | 0 |  Rn  |  Rd  |
 * +---+---+---+-----------+------+---+---+------+-----+---+---+------+------+
 */
static void disas_simd_indexed(DisasContext* s, uint32_t insn)
{
    /* This encoding has two kinds of instruction:
     *  normal, where we perform elt x idxelt => elt for each
     *     element in the vector
     *  long, where we perform elt x idxelt and generate a result of
     *     double the width of the input element
     * The long ops have a 'part' specifier (ie come in INSN, INSN2 pairs).
     */
    bool is_scalar = extract32(insn, 28, 1);
    bool is_q = extract32(insn, 30, 1);
    bool u = extract32(insn, 29, 1);
    int size = extract32(insn, 22, 2);
    int l = extract32(insn, 21, 1);
    int m = extract32(insn, 20, 1);
    /* Note that the Rm field here is only 4 bits, not 5 as it usually is */
    int rm = extract32(insn, 16, 4);
    int opcode = extract32(insn, 12, 4);
    int h = extract32(insn, 11, 1);
    int rn = extract32(insn, 5, 5);
    int rd = extract32(insn, 0, 5);
    bool is_long = false;
    int is_fp = 0;
    bool is_fp16 = false;
    int index;

    switch (16 * u + opcode) {
        case 0x08: /* MUL */
        case 0x10: /* MLA */
        case 0x14: /* MLS */
            if (is_scalar) {
                lata_unallocated_encoding(s);
                return;
            }
            break;
        case 0x02: /* SMLAL, SMLAL2 */
        case 0x12: /* UMLAL, UMLAL2 */
        case 0x06: /* SMLSL, SMLSL2 */
        case 0x16: /* UMLSL, UMLSL2 */
        case 0x0a: /* SMULL, SMULL2 */
        case 0x1a: /* UMULL, UMULL2 */
            if (is_scalar) {
                lata_unallocated_encoding(s);
                return;
            }
            is_long = true;
            break;
        case 0x03: /* SQDMLAL, SQDMLAL2 */
        case 0x07: /* SQDMLSL, SQDMLSL2 */
        case 0x0b: /* SQDMULL, SQDMULL2 */
            is_long = true;
            break;
        case 0x0c: /* SQDMULH */
        case 0x0d: /* SQRDMULH */
            break;
        case 0x01: /* FMLA */
        case 0x05: /* FMLS */
        case 0x09: /* FMUL */
        case 0x19: /* FMULX */
            is_fp = 1;
            break;
        case 0x1d: /* SQRDMLAH */
        case 0x1f: /* SQRDMLSH */
            if (!dc_isar_feature(aa64_rdm, s)) {
                lata_unallocated_encoding(s);
                return;
            }
            break;
        case 0x0e: /* SDOT */
        case 0x1e: /* UDOT */
            if (is_scalar || size != MO_32 || !dc_isar_feature(aa64_dp, s)) {
                lata_unallocated_encoding(s);
                return;
            }
            break;
        case 0x0f:
            switch (size) {
                case 0: /* SUDOT */
                case 2: /* USDOT */
                    if (is_scalar || !dc_isar_feature(aa64_i8mm, s)) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    size = MO_32;
                    break;
                case 1: /* BFDOT */
                    if (is_scalar || !dc_isar_feature(aa64_bf16, s)) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    size = MO_32;
                    break;
                case 3: /* BFMLAL{B,T} */
                    if (is_scalar || !dc_isar_feature(aa64_bf16, s)) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    /* can't set is_fp without other incorrect size checks */
                    size = MO_16;
                    break;
                default:
                    lata_unallocated_encoding(s);
                    return;
            }
            break;
        case 0x11: /* FCMLA #0 */
        case 0x13: /* FCMLA #90 */
        case 0x15: /* FCMLA #180 */
        case 0x17: /* FCMLA #270 */
            if (is_scalar || !dc_isar_feature(aa64_fcma, s)) {
                lata_unallocated_encoding(s);
                return;
            }
            is_fp = 2;
            break;
        case 0x00: /* FMLAL */
        case 0x04: /* FMLSL */
        case 0x18: /* FMLAL2 */
        case 0x1c: /* FMLSL2 */
            if (is_scalar || size != MO_32 || !dc_isar_feature(aa64_fhm, s)) {
                lata_unallocated_encoding(s);
                return;
            }
            size = MO_16;
            /* is_fp, but we pass cpu_env not fp_status.  */
            break;
        default:
            lata_unallocated_encoding(s);
            return;
    }

    switch (is_fp) {
        case 1: /* normal fp */
            /* convert insn encoded size to MemOp size */
            switch (size) {
                case 0: /* half-precision */
                    size = MO_16;
                    is_fp16 = true;
                    break;
                case MO_32: /* single precision */
                case MO_64: /* double precision */
                    break;
                default:
                    lata_unallocated_encoding(s);
                    return;
            }
            break;

        case 2: /* complex fp */
            /* Each indexable element is a complex pair.  */
            size += 1;
            switch (size) {
                case MO_32:
                    if (h && !is_q) {
                        lata_unallocated_encoding(s);
                        return;
                    }
                    is_fp16 = true;
                    break;
                case MO_64:
                    break;
                default:
                    lata_unallocated_encoding(s);
                    return;
            }
            break;

        default: /* integer */
            switch (size) {
                case MO_8:
                case MO_64:
                    lata_unallocated_encoding(s);
                    return;
            }
            break;
    }
    if (is_fp16 && !dc_isar_feature(aa64_fp16, s)) {
        lata_unallocated_encoding(s);
        return;
    }

    /* Given MemOp size, adjust register and indexing.  */
    switch (size) {
        case MO_16:
            index = h << 2 | l << 1 | m;
            break;
        case MO_32:
            index = h << 1 | l;
            rm |= m << 4;
            break;
        case MO_64:
            if (l || !is_q) {
                lata_unallocated_encoding(s);
                return;
            }
            index = h;
            rm |= m << 4;
            break;
        default:
            g_assert_not_reached();
    }

    if (!fp_access_check(s)) {
        return;
    }

    IR2_OPND vreg_d;
    IR2_OPND vreg_n = alloc_fpr_src(rn);
    IR2_OPND vreg_m = alloc_fpr_src(rm);
    IR2_OPND vtemp = ra_alloc_ftemp();
    IR2_OPND vtemp1 = ra_alloc_ftemp();
    IR2_OPND vzero = ra_alloc_ftemp();
    la_vandi_b(vzero, vzero, 0);

    switch (16 * u + opcode) {
        case 0x0e: /* SDOT (16*0 + 14) */
        case 0x1e: /* UDOT (16*1 + 14) */
        {
            /* Dot product: 4x 8b→32b sum per 32-bit lane.
               Process low half, accumulate, then high half. */
            vreg_d = alloc_fpr_dst(rd);
            {
                /* Widen low half of Vn and Vm */
                if (u) {
                    la_vilvl_b(vtemp, vzero, vreg_n);
                    la_vilvl_b(vtemp1, vzero, vreg_m);
                } else {
                    la_vilvl_b(vtemp, vreg_n, vreg_n);
                    la_vslli_h(vtemp, vtemp, 8);
                    la_vsrai_h(vtemp, vtemp, 8);
                    la_vilvl_b(vtemp1, vreg_m, vreg_m);
                    la_vslli_h(vtemp1, vtemp1, 8);
                    la_vsrai_h(vtemp1, vtemp1, 8);
                }
                la_vmulwev_w_h(vreg_d, vtemp, vtemp1);
                la_vmulwod_w_h(vzero, vtemp, vtemp1);
                la_vadd_w(vreg_d, vreg_d, vzero);
                /* Widen high half. Re-zero vzero for unsigned widening. */
                if (u) la_vxor_v(vzero, vzero, vzero);
                if (u) {
                    la_vilvh_b(vtemp, vzero, vreg_n);
                    la_vilvh_b(vtemp1, vzero, vreg_m);
                } else {
                    la_vilvh_b(vtemp, vreg_n, vreg_n);
                    la_vslli_h(vtemp, vtemp, 8);
                    la_vsrai_h(vtemp, vtemp, 8);
                    la_vilvh_b(vtemp1, vreg_m, vreg_m);
                    la_vslli_h(vtemp1, vtemp1, 8);
                    la_vsrai_h(vtemp1, vtemp1, 8);
                }
                la_vmulwev_w_h(vzero, vtemp, vtemp1);
                la_vmulwod_w_h(vtemp, vtemp, vtemp1);
                la_vadd_w(vzero, vzero, vtemp);
                la_vadd_w(vreg_d, vreg_d, vzero);
            }
            goto do_gvec_end;
        }
        case 0x0f:
            assert(0);
            switch (extract32(insn, 22, 2)) {
                case 0: /* SUDOT */
                    return;
                case 1: /* BFDOT */
                    return;
                case 2: /* USDOT */
                    return;
                case 3: /* BFMLAL{B,T} */
                    return;
            }
            g_assert_not_reached();
        case 0x11: /* FCMLA #0 */
        case 0x13: /* FCMLA #90 */
        case 0x15: /* FCMLA #180 */
        case 0x17: /* FCMLA #270 */
        {
            assert(0);
        }
            return;

        case 0x00: /* FMLAL */
        case 0x04: /* FMLSL */
        case 0x18: /* FMLAL2 */
        case 0x1c: /* FMLSL2 */
        {
            assert(0);
        }
            return;

        case 0x08: /* MUL */
            if (!is_long && !is_scalar) {
                vreg_d = alloc_fpr_dst(rd);
                switch (size) {
                    case 1:
                        la_vreplvei_h(vtemp1, vreg_m, index);
                        la_vmul_h(vreg_d, vreg_n, vtemp1);
                        break;
                    case 2:
                        la_vreplvei_w(vtemp1, vreg_m, index);
                        la_vmul_w(vreg_d, vreg_n, vtemp1);
                        break;
                    case 3:
                        la_vreplvei_d(vtemp1, vreg_m, index);
                        la_vmul_d(vreg_d, vreg_n, vtemp1);
                        break;
                    default:
                        g_assert_not_reached();
                }
            }
            goto do_gvec_end;
            break;

        case 0x10: /* MLA — multiply-accumulate: vd += vn * vm[lane] */
            if (!is_long && !is_scalar) {
                vreg_d = alloc_fpr_src(rd);
                switch (size) {
                    case MO_8:
                        la_vreplvei_b(vtemp1, vreg_m, index);
                        la_vmul_b(vtemp, vreg_n, vtemp1);
                        la_vadd_b(vreg_d, vreg_d, vtemp);
                        break;
                    case MO_16:
                        la_vreplvei_h(vtemp1, vreg_m, index);
                        la_vmul_h(vtemp, vreg_n, vtemp1);
                        la_vadd_h(vreg_d, vreg_d, vtemp);
                        break;
                    case MO_32:
                        la_vreplvei_w(vtemp1, vreg_m, index);
                        la_vmul_w(vtemp, vreg_n, vtemp1);
                        la_vadd_w(vreg_d, vreg_d, vtemp);
                        break;
                }
                goto do_gvec_end;
            }
            break;

        case 0x14: /* MLS — multiply-subtract: vd -= vn * vm[lane] */
            if (!is_long && !is_scalar) {
                vreg_d = alloc_fpr_src(rd);
                switch (size) {
                    case MO_8:
                        la_vreplvei_b(vtemp1, vreg_m, index);
                        la_vmul_b(vtemp, vreg_n, vtemp1);
                        la_vsub_b(vreg_d, vreg_d, vtemp);
                        break;
                    case MO_16:
                        la_vreplvei_h(vtemp1, vreg_m, index);
                        la_vmul_h(vtemp, vreg_n, vtemp1);
                        la_vsub_h(vreg_d, vreg_d, vtemp);
                        break;
                    case MO_32:
                        la_vreplvei_w(vtemp1, vreg_m, index);
                        la_vmul_w(vtemp, vreg_n, vtemp1);
                        la_vsub_w(vreg_d, vreg_d, vtemp);
                        break;
                }
                goto do_gvec_end;
            }
            break;
    }

    if (size == 3) {

        assert(is_fp && is_q && !is_long);

        switch (16 * u + opcode) {
            case 0x05: /* FMLS */
                vreg_d = alloc_fpr_src(rd);
                la_vxor_v(vtemp, vtemp, vtemp);
                la_vfsub_d(vtemp, vtemp, vreg_n);
                la_vreplvei_d(vtemp1, vreg_m, index);
                la_vfmadd_d(vreg_d, vtemp, vtemp1, vreg_d);
                break;
            case 0x01: /* FMLA */
                vreg_d = alloc_fpr_src(rd);
                la_vreplvei_d(vtemp1, vreg_m, index);
                la_vfmadd_d(vreg_d, vreg_n, vtemp1, vreg_d);
                break;
            case 0x09: /* FMUL */
                vreg_d = alloc_fpr_dst(rd);
                la_vreplvei_d(vtemp1, vreg_m, index);
                la_vfmul_d(vreg_d, vreg_n, vtemp1);
                break;
            case 0x19: /* FMULX */
                vreg_d = alloc_fpr_dst(rd);
                la_vreplvei_d(vtemp1, vreg_m, index);
                la_vfmul_d(vreg_d, vreg_n, vtemp1);
                break;
            default:
                g_assert_not_reached();
        }
    } else if (!is_long) {
        /* 32 bit floating point, or 16 or 32 bit integer.
         * For the 16 bit scalar case we use the usual Neon helpers and
         * rely on the fact that 0 op 0 == 0 with no side effects.
         */

        switch (16 * u + opcode) {
            case 0x08: /* MUL */
            case 0x10: /* MLA */
            case 0x14: /* MLS */
            {
                assert(0);
                break;
            }
            case 0x05: /* FMLS */
                switch (size) {
                    case 1:
                        assert(0);
                        break;
                    case 2:
                        vreg_d = alloc_fpr_src(rd);
                        la_vxor_v(vtemp, vtemp, vtemp);
                        la_vfsub_s(vtemp, vtemp, vreg_n);
                        la_vreplvei_w(vtemp1, vreg_m, index);
                        la_vfmadd_s(vreg_d, vtemp, vtemp1, vreg_d);
                        break;
                    default:
                        g_assert_not_reached();
                }
                break;
            case 0x01: /* FMLA */
                switch (size) {
                    case 1:
                        assert(0);
                        break;
                    case 2:
                        vreg_d = alloc_fpr_src(rd);
                        la_vreplvei_w(vtemp1, vreg_m, index);
                        la_vfmadd_s(vreg_d, vreg_n, vtemp1, vreg_d);
                        break;
                    default:
                        g_assert_not_reached();
                }
                break;
            case 0x09: /* FMUL */
                vreg_d = alloc_fpr_dst(rd);
                la_vreplvei_w(vtemp1, vreg_m, index);
                la_vfmul_s(vreg_d, vreg_n, vtemp1);
                break;
            case 0x19: /* FMULX */
                vreg_d = alloc_fpr_dst(rd);
                la_vreplvei_w(vtemp1, vreg_m, index);
                la_vfmul_s(vreg_d, vreg_n, vtemp1);
                break;
            case 0x0c: /* SQDMULH */
                if (!is_scalar && is_q) {
                    vreg_d = alloc_fpr_dst(rd);
                    if (size == 1)
                        la_vreplvei_h(vtemp1, vreg_m, index);
                    else if (size == 2)
                        la_vreplvei_w(vtemp1, vreg_m, index);
                    else
                        g_assert_not_reached();
                    gen_sqdmulh_vec_q(vreg_d, vreg_n, vtemp1,
                        vtemp, vzero, vtemp1, size, false);
                    break;
                }
                vreg_d = alloc_fpr_src(rd);
                switch (size) {
                    case 1:
                        la_vreplvei_h(vtemp1, vreg_m, index);
                        la_vilvl_h(vtemp, vzero, vreg_n);

                        la_vmulwev_w_h(vreg_d, vtemp, vtemp1);
                        la_vsadd_w(vreg_d, vreg_d, vreg_d);
                        la_vssrani_h_w(vreg_d, vreg_d, 16);
                        break;
                    case 2:
                        la_vreplvei_w(vtemp1, vreg_m, index);
                        la_vilvl_w(vtemp, vzero, vreg_n);

                        la_vmulwev_d_w(vreg_d, vtemp, vtemp1);
                        la_vsadd_d(vreg_d, vreg_d, vreg_d);
                        la_vssrani_w_d(vreg_d, vreg_d, 32);
                        break;
                    default:
                        g_assert_not_reached();
                }
                break;
            case 0x0d: /* SQRDMULH — rounding variant of SQDMULH */
                vreg_d = alloc_fpr_dst(rd);
                if (!is_scalar && is_q) {
                    if (size == 1)
                        la_vreplvei_h(vtemp1, vreg_m, index);
                    else if (size == 2)
                        la_vreplvei_w(vtemp1, vreg_m, index);
                    else
                        g_assert_not_reached();
                    gen_sqdmulh_vec_q(vreg_d, vreg_n, vtemp1,
                        vtemp, vzero, vtemp1, size, true);
                    break;
                }
                switch (size) {
                    case 1:
                        la_vreplvei_h(vtemp1, vreg_m, index);
                        la_vilvl_h(vtemp, vzero, vreg_n);

                        la_vmulwev_w_h(vreg_d, vtemp, vtemp1);
                        la_vsadd_w(vreg_d, vreg_d, vreg_d);
                        la_vssrarni_h_w(vreg_d, vreg_d, 16);
                        break;
                    case 2:
                        la_vreplvei_w(vtemp1, vreg_m, index);
                        la_vilvl_w(vtemp, vzero, vreg_n);

                        la_vmulwev_d_w(vreg_d, vtemp, vtemp1);
                        la_vsadd_d(vreg_d, vreg_d, vreg_d);
                        la_vssrarni_w_d(vreg_d, vreg_d, 32);
                        break;
                    default:
                        g_assert_not_reached();
                }
                break;
            case 0x1d: /* SQRDMLAH */
            case 0x1f: /* SQRDMLSH */
                lata_unallocated_encoding(s);
                return;
            default:
                g_assert_not_reached();
        }

        if (!is_q) {
            /* 高64位清零 */
            la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
        }
    } else {
        /* long ops: 16x16->32 or 32x32->64 */
        int is_sub = extract32(opcode, 2, 1);
        switch (opcode) {
            case 0x2:
            case 0x12: /* SMLAL/SMLAL2, UMLAL/UMLAL2 */
            case 0x6:
            case 0x16: /* SMLSL/SMLSL2, UMLSL/UMLSL2 */
                vreg_d = alloc_fpr_src(rd);
                if (u) {
                    if (!is_q) {
                        switch (size) {
                            case 1:
                                la_vreplvei_h(vtemp1, vreg_m, index);
                                la_vilvl_h(vtemp, vzero, vreg_n);
                                if (is_sub) {
                                    la_vmulwev_w_hu(vzero, vtemp, vtemp1);
                                    la_vsub_w(vreg_d, vreg_d, vzero);
                                } else
                                    la_vmaddwev_w_hu(vreg_d, vtemp1, vtemp);
                                break;
                            case 2:
                                la_vreplvei_w(vtemp1, vreg_m, index);
                                la_vilvl_w(vtemp, vzero, vreg_n);
                                if (is_sub) {
                                    la_vmulwev_d_wu(vzero, vtemp, vtemp1);
                                    la_vsub_d(vreg_d, vreg_d, vzero);
                                } else
                                    la_vmaddwev_d_wu(vreg_d, vtemp1, vtemp);
                                break;
                            default:
                                assert(0);
                        }
                    } else {
                        switch (size) {
                            case 1:
                                la_vreplvei_h(vtemp1, vreg_m, index);
                                la_vilvh_h(vtemp, vzero, vreg_n);

                                if (is_sub) {
                                    la_vmulwev_w_hu(vzero, vtemp, vtemp1);
                                    la_vsub_w(vreg_d, vreg_d, vzero);
                                } else
                                    la_vmaddwev_w_hu(vreg_d, vtemp1, vtemp);
                                break;
                            case 2:
                                la_vreplvei_w(vtemp1, vreg_m, index);
                                la_vilvh_w(vtemp, vzero, vreg_n);

                                if (is_sub) {
                                    la_vmulwev_d_wu(vzero, vtemp, vtemp1);
                                    la_vsub_d(vreg_d, vreg_d, vzero);
                                } else
                                    la_vmaddwev_d_wu(vreg_d, vtemp1, vtemp);
                                break;
                            default:
                                assert(0);
                        }
                    }
                } else {
                    if (!is_q) {
                        switch (size) {
                            case 1:
                                la_vreplvei_h(vtemp1, vreg_m, index);
                                la_vilvl_h(vtemp, vzero, vreg_n);
                                la_vslli_w(vtemp, vtemp, 16);
                                la_vsrai_w(vtemp, vtemp, 16);

                                if (is_sub) {
                                    la_vmulwev_w_h(vzero, vtemp, vtemp1);
                                    la_vsub_w(vreg_d, vreg_d, vzero);
                                } else
                                    la_vmaddwev_w_h(vreg_d, vtemp1, vtemp);
                                break;
                            case 2:
                                la_vreplvei_w(vtemp1, vreg_m, index);
                                la_vilvl_w(vtemp, vzero, vreg_n);
                                la_vslli_d(vtemp, vtemp, 32);
                                la_vsrai_d(vtemp, vtemp, 32);

                                if (is_sub) {
                                    la_vmulwev_d_w(vzero, vtemp, vtemp1);
                                    la_vsub_d(vreg_d, vreg_d, vzero);
                                } else
                                    la_vmaddwev_d_w(vreg_d, vtemp1, vtemp);
                                break;
                            default:
                                assert(0);
                        }
                    } else {
                        switch (size) {
                            case 1:
                                la_vreplvei_h(vtemp1, vreg_m, index);
                                la_vilvh_h(vtemp, vzero, vreg_n);
                                la_vslli_w(vtemp, vtemp, 16);
                                la_vsrai_w(vtemp, vtemp, 16);

                                if (is_sub) {
                                    la_vmulwev_w_h(vzero, vtemp, vtemp1);
                                    la_vsub_w(vreg_d, vreg_d, vzero);
                                } else
                                    la_vmaddwev_w_h(vreg_d, vtemp1, vtemp);
                                break;
                            case 2:
                                la_vreplvei_w(vtemp1, vreg_m, index);
                                la_vilvh_w(vtemp, vzero, vreg_n);
                                la_vslli_d(vtemp, vtemp, 32);
                                la_vsrai_d(vtemp, vtemp, 32);

                                if (is_sub) {
                                    la_vmulwev_d_w(vzero, vtemp, vtemp1);
                                    la_vsub_d(vreg_d, vreg_d, vzero);
                                } else
                                    la_vmaddwev_d_w(vreg_d, vtemp1, vtemp);
                                break;
                            default:
                                assert(0);
                        }
                    }
                }
                break;
            case 0x0a: /* SMULL, SMULL2 */
            case 0x1a: /* UMULL, UMULL2 */
                vreg_d = alloc_fpr_dst(rd);
                /* is_q selects low/high source half; dest is always 128-bit. */
                if (is_q) {
                    switch (size) {
                        case 1:
                            la_vreplvei_h(vtemp1, vreg_m, index);
                            la_vilvh_h(vtemp, vzero, vreg_n);
                            if (!u) {
                                la_vslli_w(vtemp, vtemp, 16);
                                la_vsrai_w(vtemp, vtemp, 16);
                            }
                            if (u)
                                la_vmulwev_w_hu(vreg_d, vtemp, vtemp1);
                            else
                                la_vmulwev_w_h(vreg_d, vtemp, vtemp1);
                            break;
                        case 2:
                            la_vreplvei_w(vtemp1, vreg_m, index);
                            la_vilvh_w(vtemp, vzero, vreg_n);
                            if (!u) {
                                la_vslli_d(vtemp, vtemp, 32);
                                la_vsrai_d(vtemp, vtemp, 32);
                            }
                            if (u)
                                la_vmulwev_d_wu(vreg_d, vtemp, vtemp1);
                            else
                                la_vmulwev_d_w(vreg_d, vtemp, vtemp1);
                            break;
                    }
                } else {
                    switch (size) {
                        case 1:
                            la_vreplvei_h(vtemp1, vreg_m, index);
                            la_vilvl_h(vtemp, vzero, vreg_n);
                            if (!u) {
                                la_vslli_w(vtemp, vtemp, 16);
                                la_vsrai_w(vtemp, vtemp, 16);
                            }
                            if (u)
                                la_vmulwev_w_hu(vreg_d, vtemp, vtemp1);
                            else
                                la_vmulwev_w_h(vreg_d, vtemp, vtemp1);
                            break;
                        case 2:
                            la_vreplvei_w(vtemp1, vreg_m, index);
                            la_vilvl_w(vtemp, vzero, vreg_n);
                            if (!u) {
                                la_vslli_d(vtemp, vtemp, 32);
                                la_vsrai_d(vtemp, vtemp, 32);
                            }
                            if (u)
                                la_vmulwev_d_wu(vreg_d, vtemp, vtemp1);
                            else
                                la_vmulwev_d_w(vreg_d, vtemp, vtemp1);
                            break;
                    }
                }
                break;
            case 0x0b: /* SQDMULL, SQDMULL2 */
                vreg_d = alloc_fpr_dst(rd);
                /* SQDMULL2 (vector is_q=1): upper half. Scalar (is_scalar=1)
                 * and SQDMULL (is_q=0): lower half. */
                switch (size) {
                    case 1:
                        la_vreplvei_h(vtemp1, vreg_m, index);
                        if (is_q && !is_scalar)
                            la_vilvh_h(vtemp, vzero, vreg_n);
                        else
                            la_vilvl_h(vtemp, vzero, vreg_n);
                        la_vslli_w(vtemp, vtemp, 16);
                        la_vsrai_w(vtemp, vtemp, 16);

                        la_vmulwev_w_h(vreg_d, vtemp, vtemp1);
                        la_vsadd_w(vreg_d, vreg_d, vreg_d);
                        break;
                    case 2:
                        la_vreplvei_w(vtemp1, vreg_m, index);
                        if (is_q && !is_scalar)
                            la_vilvh_w(vtemp, vzero, vreg_n);
                        else
                            la_vilvl_w(vtemp, vzero, vreg_n);
                        la_vslli_d(vtemp, vtemp, 32);
                        la_vsrai_d(vtemp, vtemp, 32);

                        la_vmulwev_d_w(vreg_d, vtemp, vtemp1);
                        la_vsadd_d(vreg_d, vreg_d, vreg_d);
                        break;
                }
                break;
            case 0x3: /* SQDMLAL, SQDMLAL2 */
            case 0x7: /* SQDMLSL, SQDMLSL2 */
                vreg_d = alloc_fpr_src(rd);
                if (!is_q || is_scalar) {
                    switch (size) {
                        case 1:
                            la_vreplvei_h(vtemp1, vreg_m, index);
                            la_vilvl_h(vtemp, vzero, vreg_n);
                            la_vslli_w(vtemp, vtemp, 16);
                            la_vsrai_w(vtemp, vtemp, 16);

                            la_vmulwev_w_h(vtemp, vtemp, vtemp1);
                            la_vsadd_w(vtemp, vtemp, vtemp);
                            if (opcode == 0x7)
                                la_vssub_w(vreg_d, vreg_d, vtemp);
                            else
                                la_vsadd_w(vreg_d, vreg_d, vtemp);
                            break;
                        case 2:
                            la_vreplvei_w(vtemp1, vreg_m, index);
                            la_vilvl_w(vtemp, vzero, vreg_n);
                            la_vslli_d(vtemp, vtemp, 32);
                            la_vsrai_d(vtemp, vtemp, 32);

                            la_vmulwev_d_w(vtemp, vtemp, vtemp1);
                            la_vsadd_d(vtemp, vtemp, vtemp);
                            if (opcode == 0x7)
                                la_vssub_d(vreg_d, vreg_d, vtemp);
                            else
                                la_vsadd_d(vreg_d, vreg_d, vtemp);
                            break;
                    }
                } else {
                    switch (size) {
                        case 1:
                            la_vreplvei_h(vtemp1, vreg_m, index);
                            la_vilvh_h(vtemp, vzero, vreg_n);
                            la_vslli_w(vtemp, vtemp, 16);
                            la_vsrai_w(vtemp, vtemp, 16);

                            la_vmulwev_w_h(vtemp, vtemp, vtemp1);
                            la_vsadd_w(vtemp, vtemp, vtemp);
                            if (opcode == 0x7)
                                la_vssub_w(vreg_d, vreg_d, vtemp);
                            else
                                la_vsadd_w(vreg_d, vreg_d, vtemp);
                            break;
                        case 2:
                            la_vreplvei_w(vtemp1, vreg_m, index);
                            la_vilvh_w(vtemp, vzero, vreg_n);
                            la_vslli_d(vtemp, vtemp, 32);
                            la_vsrai_d(vtemp, vtemp, 32);

                            la_vmulwev_d_w(vtemp, vtemp, vtemp1);
                            la_vsadd_d(vtemp, vtemp, vtemp);
                            if (opcode == 0x7)
                                la_vssub_d(vreg_d, vreg_d, vtemp);
                            else
                                la_vsadd_d(vreg_d, vreg_d, vtemp);
                            break;
                    }
                }
                break;
            default:
                assert(0);
        }
    }
do_gvec_end:
    if (!is_q && !is_long) {
        /* 高64位清零 (long ops always write full 128-bit dest) */
        la_vinsgr2vr_d(vreg_d, zero_ir2_opnd, 1);
    }
    store_fpr_dst(rd, vreg_d);
    free_alloc_fpr(vreg_d);
    free_alloc_fpr(vreg_n);
    free_alloc_fpr(vreg_m);
    free_alloc_fpr(vtemp);
    free_alloc_fpr(vtemp1);
    free_alloc_fpr(vzero);
}

/* Crypto AES
 *  31             24 23  22 21       17 16    12 11 10 9    5 4    0
 * +-----------------+------+-----------+--------+-----+------+------+
 * | 0 1 0 0 1 1 1 0 | size | 1 0 1 0 0 | opcode | 1 0 |  Rn  |  Rd  |
 * +-----------------+------+-----------+--------+-----+------+------+
 */
static void disas_crypto_aes(DisasContext* s, uint32_t insn) { lata_unallocated_encoding(s); }

/* Crypto three-reg SHA
 *  31             24 23  22  21 20  16  15 14    12 11 10 9    5 4    0
 * +-----------------+------+---+------+---+--------+-----+------+------+
 * | 0 1 0 1 1 1 1 0 | size | 0 |  Rm  | 0 | opcode | 0 0 |  Rn  |  Rd  |
 * +-----------------+------+---+------+---+--------+-----+------+------+
 */
static void disas_crypto_three_reg_sha(DisasContext* s, uint32_t insn) { lata_unallocated_encoding(s); }

/* Crypto two-reg SHA
 *  31             24 23  22 21       17 16    12 11 10 9    5 4    0
 * +-----------------+------+-----------+--------+-----+------+------+
 * | 0 1 0 1 1 1 1 0 | size | 1 0 1 0 0 | opcode | 1 0 |  Rn  |  Rd  |
 * +-----------------+------+-----------+--------+-----+------+------+
 */
static void disas_crypto_two_reg_sha(DisasContext* s, uint32_t insn) { lata_unallocated_encoding(s); }

/* Crypto three-reg SHA512
 *  31                   21 20  16 15  14  13 12  11  10  9    5 4    0
 * +-----------------------+------+---+---+-----+--------+------+------+
 * | 1 1 0 0 1 1 1 0 0 1 1 |  Rm  | 1 | O | 0 0 | opcode |  Rn  |  Rd  |
 * +-----------------------+------+---+---+-----+--------+------+------+
 */
static void disas_crypto_three_reg_sha512(DisasContext* s, uint32_t insn) { lata_unallocated_encoding(s); }

/* Crypto two-reg SHA512
 *  31                                     12  11  10  9    5 4    0
 * +-----------------------------------------+--------+------+------+
 * | 1 1 0 0 1 1 1 0 1 1 0 0 0 0 0 0 1 0 0 0 | opcode |  Rn  |  Rd  |
 * +-----------------------------------------+--------+------+------+
 */
static void disas_crypto_two_reg_sha512(DisasContext* s, uint32_t insn) { lata_unallocated_encoding(s); }

/* Crypto four-register
 *  31               23 22 21 20  16 15  14  10 9    5 4    0
 * +-------------------+-----+------+---+------+------+------+
 * | 1 1 0 0 1 1 1 0 0 | Op0 |  Rm  | 0 |  Ra  |  Rn  |  Rd  |
 * +-------------------+-----+------+---+------+------+------+
 */
static void disas_crypto_four_reg(DisasContext* s, uint32_t insn) { lata_unallocated_encoding(s); }

/* Crypto XAR
 *  31                   21 20  16 15    10 9    5 4    0
 * +-----------------------+------+--------+------+------+
 * | 1 1 0 0 1 1 1 0 1 0 0 |  Rm  |  imm6  |  Rn  |  Rd  |
 * +-----------------------+------+--------+------+------+
 */
static void disas_crypto_xar(DisasContext* s, uint32_t insn) { lata_unallocated_encoding(s); }

/* Crypto three-reg imm2
 *  31                   21 20  16 15  14 13 12  11  10  9    5 4    0
 * +-----------------------+------+-----+------+--------+------+------+
 * | 1 1 0 0 1 1 1 0 0 1 0 |  Rm  | 1 0 | imm2 | opcode |  Rn  |  Rd  |
 * +-----------------------+------+-----+------+--------+------+------+
 */
static void disas_crypto_three_reg_imm2(DisasContext* s, uint32_t insn) { lata_unallocated_encoding(s); }


/* C3.6 Data processing - SIMD, inc Crypto
 *
 * As the decode gets a little complex we are using a table based
 * approach for this part of the decode.
 */
static const AArch64DecodeTable data_proc_simd[] = {
    /* pattern  ,  mask     ,  fn                        */
    { 0x0e200800, 0x9f3e0c00, disas_simd_two_reg_misc },
    { 0x0e200400, 0x9f200400, disas_simd_three_reg_same },
    { 0x0e008400, 0x9f208400, disas_simd_three_reg_same_extra },
    { 0x0e200000, 0x9f200c00, disas_simd_three_reg_diff },
    { 0x0e300800, 0x9f3e0c00, disas_simd_across_lanes },
    { 0x0e000400, 0x9fe08400, disas_simd_copy },
    { 0x0f000000, 0x9f000400, disas_simd_indexed }, /* vector indexed */
    /* simd_mod_imm decode is a subset of simd_shift_imm, so must precede it */
    { 0x0f000400, 0x9ff80400, disas_simd_mod_imm },
    { 0x0f000400, 0x9f800400, disas_simd_shift_imm },
    { 0x0e000000, 0xbf208c00, disas_simd_tb },
    { 0x0e000800, 0xbf208c00, disas_simd_zip_trn },
    { 0x2e000000, 0xbf208400, disas_simd_ext },
    { 0x5e200400, 0xdf200400, disas_simd_scalar_three_reg_same },
    { 0x5e008400, 0xdf208400, disas_simd_scalar_three_reg_same_extra },
    { 0x5e200000, 0xdf200c00, disas_simd_scalar_three_reg_diff },
    { 0x5e000800, 0xdf1e0c00, disas_simd_scalar_two_reg_misc }, /* bit21=0 variants */
    { 0x5e200800, 0xdd3e0c00, disas_simd_scalar_two_reg_misc }, /* U bit unconstrained */
    { 0x5e300800, 0xdf3e0c00, disas_simd_scalar_pairwise },
    { 0x5e000400, 0xdfe08400, disas_simd_scalar_copy },
    { 0x5f000000, 0xdf000400, disas_simd_indexed }, /* scalar indexed */
    { 0x5f000400, 0xdf800400, disas_simd_scalar_shift_imm },
    { 0x4e280800, 0xff3e0c00, disas_crypto_aes },
    { 0x5e000000, 0xff208c00, disas_crypto_three_reg_sha },
    { 0x5e280800, 0xff3e0c00, disas_crypto_two_reg_sha },
    { 0xce608000, 0xffe0b000, disas_crypto_three_reg_sha512 },
    { 0xcec08000, 0xfffff000, disas_crypto_two_reg_sha512 },
    { 0xce000000, 0xff808000, disas_crypto_four_reg },
    { 0xce800000, 0xffe00000, disas_crypto_xar },
    { 0xce408000, 0xffe0c000, disas_crypto_three_reg_imm2 },
    { 0x0e400400, 0x9f60c400, disas_simd_three_reg_same_fp16 },
    { 0x0e780800, 0x8f7e0c00, disas_simd_two_reg_misc_fp16 },
    { 0x5e400400, 0xdf60c400, disas_simd_scalar_three_reg_same_fp16 },
    { 0x00000000, 0x00000000, NULL }
};

static void disas_data_proc_simd(DisasContext* s, uint32_t insn)
{
    /* Note that this is called with all non-FP cases from
     * table C3-6 so it must UNDEF for entries not specifically
     * allocated to instructions in that table.
     */
    AArch64DecodeFn* fn = lookup_disas_fn(&data_proc_simd[0], insn);
    if (fn) {
        fn(s, insn);
    } else {
        lata_unallocated_encoding(s);
    }
}

/* C3.6 Data processing - SIMD and floating point */
static bool disas_data_proc_simd_fp(DisasContext* s)
{
    uint32_t insn = s->insn;
    if (extract32(insn, 28, 1) == 1 && extract32(insn, 30, 1) == 0) {
        disas_data_proc_fp(s, insn);
    } else {
        /* SIMD, including crypto */
        disas_data_proc_simd(s, insn);
    }
    return true;
}

// /* C3.1 A64 instruction index by encoding */
static bool (*translate_functions[])(DisasContext*) = {
    TRANS_FUNC_GEN_REAL(AARCH64_A64_NULL, (void*)lata_unallocated_encoding),
    TRANS_FUNC_GEN(AARCH64_A64_ADDG_i, ADDG_i),
    TRANS_FUNC_GEN(AARCH64_A64_ADDS_i, ADDS_i),
    TRANS_FUNC_GEN(AARCH64_A64_ADD_i, ADD_i),
    TRANS_FUNC_GEN(AARCH64_A64_ADR, ADR),
    TRANS_FUNC_GEN(AARCH64_A64_ADRP, ADRP),
    TRANS_FUNC_GEN(AARCH64_A64_ANDS_i, ANDS_i),
    TRANS_FUNC_GEN(AARCH64_A64_AND_i, AND_i),
    TRANS_FUNC_GEN(AARCH64_A64_AUTIA1716, AUTIA1716),
    TRANS_FUNC_GEN(AARCH64_A64_AUTIASP, AUTIASP),
    TRANS_FUNC_GEN(AARCH64_A64_AUTIAZ, AUTIAZ),
    TRANS_FUNC_GEN(AARCH64_A64_AUTIB1716, AUTIB1716),
    TRANS_FUNC_GEN(AARCH64_A64_AUTIBSP, AUTIBSP),
    TRANS_FUNC_GEN(AARCH64_A64_AUTIBZ, AUTIBZ),
    TRANS_FUNC_GEN(AARCH64_A64_AXFLAG, AXFLAG),
    TRANS_FUNC_GEN(AARCH64_A64_B, B),
    TRANS_FUNC_GEN(AARCH64_A64_BFM, BFM),
    TRANS_FUNC_GEN(AARCH64_A64_BL, BL),
    TRANS_FUNC_GEN(AARCH64_A64_BLR, BLR),
    TRANS_FUNC_GEN(AARCH64_A64_BLRA, BLRA),
    TRANS_FUNC_GEN(AARCH64_A64_BLRAZ, BLRAZ),
    TRANS_FUNC_GEN(AARCH64_A64_BR, BR),
    TRANS_FUNC_GEN(AARCH64_A64_BRA, BRA),
    TRANS_FUNC_GEN(AARCH64_A64_BRAZ, BRAZ),
    TRANS_FUNC_GEN(AARCH64_A64_BRK, BRK),
    TRANS_FUNC_GEN(AARCH64_A64_B_cond, B_cond),
    TRANS_FUNC_GEN(AARCH64_A64_CAS, CAS),
    TRANS_FUNC_GEN(AARCH64_A64_CASP, CASP),
    TRANS_FUNC_GEN(AARCH64_A64_CBZ, CBZ),
    TRANS_FUNC_GEN(AARCH64_A64_CFINV, CFINV),
    TRANS_FUNC_GEN(AARCH64_A64_CRYPTO, CRYPTO),
    TRANS_FUNC_GEN(AARCH64_A64_CLREX, CLREX),
    TRANS_FUNC_GEN(AARCH64_A64_DSB_DMB, DSB_DMB),
    TRANS_FUNC_GEN(AARCH64_A64_EOR_i, EOR_i),
    TRANS_FUNC_GEN(AARCH64_A64_ERET, ERET),
    TRANS_FUNC_GEN(AARCH64_A64_ERETA, ERETA),
    TRANS_FUNC_GEN(AARCH64_A64_FCADD, FCADD),
    TRANS_FUNC_GEN(AARCH64_A64_ESB, ESB),
    TRANS_FUNC_GEN(AARCH64_A64_EXTR, EXTR),
    TRANS_FUNC_GEN(AARCH64_A64_HLT, HLT),
    TRANS_FUNC_GEN(AARCH64_A64_HVC, HVC),
    TRANS_FUNC_GEN(AARCH64_A64_ISB, ISB),
    TRANS_FUNC_GEN(AARCH64_A64_LDADD, LDADD),
    TRANS_FUNC_GEN(AARCH64_A64_LDAPR, LDAPR),
    TRANS_FUNC_GEN(AARCH64_A64_LDAPR_i, LDAPR_i),
    TRANS_FUNC_GEN(AARCH64_A64_LDAR, LDAR),
    TRANS_FUNC_GEN(AARCH64_A64_LDCLR, LDCLR),
    TRANS_FUNC_GEN(AARCH64_A64_LDEOR, LDEOR),
    TRANS_FUNC_GEN(AARCH64_A64_LDG, LDG),
    TRANS_FUNC_GEN(AARCH64_A64_LDGM, LDGM),
    TRANS_FUNC_GEN(AARCH64_A64_LDP, LDP),
    TRANS_FUNC_GEN(AARCH64_A64_LDP_v, LDP_v),
    TRANS_FUNC_GEN(AARCH64_A64_LDR, LDR),
    TRANS_FUNC_GEN(AARCH64_A64_LDRA, LDRA),
    TRANS_FUNC_GEN(AARCH64_A64_LDR_i, LDR_i),
    TRANS_FUNC_GEN(AARCH64_A64_LDR_v, LDR_v),
    TRANS_FUNC_GEN(AARCH64_A64_LDR_v_i, LDR_v_i),
    TRANS_FUNC_GEN(AARCH64_A64_LDSET, LDSET),
    TRANS_FUNC_GEN(AARCH64_A64_LDSMAX, LDSMAX),
    TRANS_FUNC_GEN(AARCH64_A64_LDSMIN, LDSMIN),
    TRANS_FUNC_GEN(AARCH64_A64_LDUMAX, LDUMAX),
    TRANS_FUNC_GEN(AARCH64_A64_LDUMIN, LDUMIN),
    TRANS_FUNC_GEN(AARCH64_A64_LDXP, LDXP),
    TRANS_FUNC_GEN(AARCH64_A64_LDXR, LDXR),
    TRANS_FUNC_GEN(AARCH64_A64_LD_lit, LD_lit),
    TRANS_FUNC_GEN(AARCH64_A64_LD_lit_v, LD_lit_v),
    TRANS_FUNC_GEN(AARCH64_A64_LD_mult, LD_mult),
    TRANS_FUNC_GEN(AARCH64_A64_LD_single, LD_single),
    TRANS_FUNC_GEN(AARCH64_A64_LD_single_repl, LD_single_repl),
    TRANS_FUNC_GEN(AARCH64_A64_MOVK, MOVK),
    TRANS_FUNC_GEN(AARCH64_A64_MOVN, MOVN),
    TRANS_FUNC_GEN(AARCH64_A64_MOVZ, MOVZ),
    TRANS_FUNC_GEN(AARCH64_A64_MSR_i_DAIFCLEAR, MSR_i_DAIFCLEAR),
    TRANS_FUNC_GEN(AARCH64_A64_MSR_i_DAIFSET, MSR_i_DAIFSET),
    TRANS_FUNC_GEN(AARCH64_A64_MSR_i_DIT, MSR_i_DIT),
    TRANS_FUNC_GEN(AARCH64_A64_MSR_i_PAN, MSR_i_PAN),
    TRANS_FUNC_GEN(AARCH64_A64_MSR_i_SBSS, MSR_i_SBSS),
    TRANS_FUNC_GEN(AARCH64_A64_MSR_i_SPSEL, MSR_i_SPSEL),
    TRANS_FUNC_GEN(AARCH64_A64_MSR_i_SVCR, MSR_i_SVCR),
    TRANS_FUNC_GEN(AARCH64_A64_MSR_i_TCO, MSR_i_TCO),
    TRANS_FUNC_GEN(AARCH64_A64_MSR_i_UAO, MSR_i_UAO),
    TRANS_FUNC_GEN(AARCH64_A64_NOP, NOP),
    TRANS_FUNC_GEN(AARCH64_A64_ORR_i, ORR_i),
    TRANS_FUNC_GEN(AARCH64_A64_PACIA1716, PACIA1716),
    TRANS_FUNC_GEN(AARCH64_A64_PACIASP, PACIASP),
    TRANS_FUNC_GEN(AARCH64_A64_PACIAZ, PACIAZ),
    TRANS_FUNC_GEN(AARCH64_A64_PACIB1716, PACIB1716),
    TRANS_FUNC_GEN(AARCH64_A64_PACIBSP, PACIBSP),
    TRANS_FUNC_GEN(AARCH64_A64_PACIBZ, PACIBZ),
    TRANS_FUNC_GEN(AARCH64_A64_RET, RET),
    TRANS_FUNC_GEN(AARCH64_A64_RETA, RETA),
    TRANS_FUNC_GEN(AARCH64_A64_RMIF, RMIF),
    TRANS_FUNC_GEN(AARCH64_A64_SB, SB),
    TRANS_FUNC_GEN(AARCH64_A64_SBFM, SBFM),
    TRANS_FUNC_GEN(AARCH64_A64_SMC, SMC),
    TRANS_FUNC_GEN(AARCH64_A64_ST2G, ST2G),
    TRANS_FUNC_GEN(AARCH64_A64_STG, STG),
    TRANS_FUNC_GEN(AARCH64_A64_STGM, STGM),
    TRANS_FUNC_GEN(AARCH64_A64_STGP, STGP),
    TRANS_FUNC_GEN(AARCH64_A64_STLR, STLR),
    TRANS_FUNC_GEN(AARCH64_A64_STLR_i, STLR_i),
    TRANS_FUNC_GEN(AARCH64_A64_STP, STP),
    TRANS_FUNC_GEN(AARCH64_A64_STP_v, STP_v),
    TRANS_FUNC_GEN(AARCH64_A64_STR, STR),
    TRANS_FUNC_GEN(AARCH64_A64_STR_i, STR_i),
    TRANS_FUNC_GEN(AARCH64_A64_STR_v, STR_v),
    TRANS_FUNC_GEN(AARCH64_A64_STR_v_i, STR_v_i),
    TRANS_FUNC_GEN(AARCH64_A64_STXP, STXP),
    TRANS_FUNC_GEN(AARCH64_A64_STXR, STXR),
    TRANS_FUNC_GEN(AARCH64_A64_STZ2G, STZ2G),
    TRANS_FUNC_GEN(AARCH64_A64_STZG, STZG),
    TRANS_FUNC_GEN(AARCH64_A64_STZGM, STZGM),
    TRANS_FUNC_GEN(AARCH64_A64_ST_mult, ST_mult),
    TRANS_FUNC_GEN(AARCH64_A64_ST_single, ST_single),
    TRANS_FUNC_GEN(AARCH64_A64_SUBG_i, SUBG_i),
    TRANS_FUNC_GEN(AARCH64_A64_SUBS_i, SUBS_i),
    TRANS_FUNC_GEN(AARCH64_A64_SUB_i, SUB_i),
    TRANS_FUNC_GEN(AARCH64_A64_SVC, SVC),
    TRANS_FUNC_GEN(AARCH64_A64_SWP, SWP),
    TRANS_FUNC_GEN(AARCH64_A64_SYS, SYS),
    TRANS_FUNC_GEN(AARCH64_A64_TBZ, TBZ),
    TRANS_FUNC_GEN(AARCH64_A64_UBFM, UBFM),
    TRANS_FUNC_GEN(AARCH64_A64_WFE, WFE),
    TRANS_FUNC_GEN(AARCH64_A64_WFI, WFI),
    TRANS_FUNC_GEN(AARCH64_A64_XAFLAG, XAFLAG),
    TRANS_FUNC_GEN(AARCH64_A64_XPACLRI, XPACLRI),
    TRANS_FUNC_GEN(AARCH64_A64_YIELD, YIELD),
    TRANS_DISAS_FUNC_GEN(AARCH64_A64_DATA_PROC_REG, reg),
    TRANS_DISAS_FUNC_GEN(AARCH64_A64_DATA_PROC_SIMD_FD, simd_fp),
    TRANS_FUNC_GEN(AARCH64_A64_EXCP_ILLEGAL, EXCP_ILLEGAL),
    TRANS_FUNC_GEN(AARCH64_A64_EXCP_BTI, EXCP_BTI),
};

static void aarch64_tr_init_disas_context(DisasContext* dc,
    CPUState* cpu)
{
    CPUARMState* env = cpu->env_ptr;
    ARMCPU* arm_cpu = env_archcpu(env);
    CPUARMTBFlags tb_flags = arm_tbflags_from_tb(dc->base->tb);
    int bound, core_mmu_idx;

    dc->isar = &arm_cpu->isar;
    dc->condjmp = 0;
    dc->pc_save = dc->base->pc_first;
    dc->aarch64 = true;
    dc->thumb = false;
    dc->sctlr_b = 0;
    dc->be_data = EX_TBFLAG_ANY(tb_flags, BE_DATA) ? MO_BE : MO_LE;
    dc->condexec_mask = 0;
    dc->condexec_cond = 0;
    core_mmu_idx = EX_TBFLAG_ANY(tb_flags, MMUIDX);
    dc->mmu_idx = core_to_aa64_mmu_idx(core_mmu_idx);
    dc->tbii = EX_TBFLAG_A64(tb_flags, TBII);
    dc->tbid = EX_TBFLAG_A64(tb_flags, TBID);
    dc->tcma = EX_TBFLAG_A64(tb_flags, TCMA);
    dc->current_el = arm_mmu_idx_to_el(dc->mmu_idx);
#if !defined(CONFIG_USER_ONLY)
    dc->user = (dc->current_el == 0);
#endif
    dc->fp_excp_el = EX_TBFLAG_ANY(tb_flags, FPEXC_EL);
    dc->align_mem = EX_TBFLAG_ANY(tb_flags, ALIGN_MEM);
    dc->pstate_il = EX_TBFLAG_ANY(tb_flags, PSTATE__IL);
    dc->fgt_active = EX_TBFLAG_ANY(tb_flags, FGT_ACTIVE);
    dc->fgt_svc = EX_TBFLAG_ANY(tb_flags, FGT_SVC);
    dc->fgt_eret = EX_TBFLAG_A64(tb_flags, FGT_ERET);
    dc->sve_excp_el = EX_TBFLAG_A64(tb_flags, SVEEXC_EL);
    dc->sme_excp_el = EX_TBFLAG_A64(tb_flags, SMEEXC_EL);
    dc->vl = (EX_TBFLAG_A64(tb_flags, VL) + 1) * 16;
    dc->svl = (EX_TBFLAG_A64(tb_flags, SVL) + 1) * 16;
    dc->pauth_active = EX_TBFLAG_A64(tb_flags, PAUTH_ACTIVE);
    dc->bt = EX_TBFLAG_A64(tb_flags, BT);
    dc->btype = EX_TBFLAG_A64(tb_flags, BTYPE);
    dc->guarded_page = false;
    dc->unpriv = EX_TBFLAG_A64(tb_flags, UNPRIV);
    dc->ata = EX_TBFLAG_A64(tb_flags, ATA);
    dc->mte_active[0] = EX_TBFLAG_A64(tb_flags, MTE_ACTIVE);
    dc->mte_active[1] = EX_TBFLAG_A64(tb_flags, MTE0_ACTIVE);
    dc->pstate_sm = EX_TBFLAG_A64(tb_flags, PSTATE_SM);
    dc->pstate_za = EX_TBFLAG_A64(tb_flags, PSTATE_ZA);
    dc->sme_trap_nonstreaming = EX_TBFLAG_A64(tb_flags, SME_TRAP_NONSTREAMING);
    dc->naa = EX_TBFLAG_A64(tb_flags, NAA);
    dc->vec_len = 0;
    dc->vec_stride = 0;
    dc->cp_regs = arm_cpu->cp_regs;
    dc->features = env->features;
    dc->dcz_blocksize = arm_cpu->dcz_blocksize;

#ifdef CONFIG_USER_ONLY
    /* In sve_probe_page, we assume TBI is enabled. */
    assert(dc->tbid & 1);
#endif

    dc->lse2 = dc_isar_feature(aa64_lse2, dc);

    /* Single step state. The code-generation logic here is:
     *  SS_ACTIVE == 0:
     *   generate code with no special handling for single-stepping (except
     *   that anything that can make us go to SS_ACTIVE == 1 must end the TB;
     *   this happens anyway because those changes are all system register or
     *   PSTATE writes).
     *  SS_ACTIVE == 1, PSTATE.SS == 1: (active-not-pending)
     *   emit code for one insn
     *   emit code to clear PSTATE.SS
     *   emit code to generate software step exception for completed step
     *   end TB (as usual for having generated an exception)
     *  SS_ACTIVE == 1, PSTATE.SS == 0: (active-pending)
     *   emit code to generate a software step exception
     *   end the TB
     */
    dc->ss_active = EX_TBFLAG_ANY(tb_flags, SS_ACTIVE);
    dc->pstate_ss = EX_TBFLAG_ANY(tb_flags, PSTATE__SS);
    dc->is_ldex = false;

    /* Bound the number of insns to execute to those left on the page.  */
    bound = -(dc->base->pc_first | TARGET_PAGE_MASK) / 4;

    /* If architectural single step active, limit to 1.  */
    if (dc->ss_active) {
        bound = 1;
    }
    dc->base->max_insns = MIN(dc->base->max_insns, bound);
}

static void disas_a64_legacy(DisasContext* s, uint32_t insn)
{
    /* RMIF: 10111010000iiiiii00001nnnnn0IIII */
    if ((insn & 0xFFE07C10) == 0xBA000400) {
        s->insn_type = AARCH64_A64_RMIF;
        return;
    }
    /* Crypto patterns - check before legacy decode */
    if ((insn & 0xFF3E0C00) == 0x4E280800) {
        s->insn_type = AARCH64_A64_CRYPTO;
        return;
    }
    if ((insn & 0xFF208C00) == 0x5E000000) {
        s->insn_type = AARCH64_A64_CRYPTO;
        return;
    }
    if ((insn & 0xFF3E0C00) == 0x5E280800) {
        s->insn_type = AARCH64_A64_CRYPTO;
        return;
    }
    if ((insn & 0xFFE0B000) == 0xCE608000) {
        s->insn_type = AARCH64_A64_CRYPTO;
        return;
    }
    if ((insn & 0xFFFFF000) == 0xCEC08000) {
        s->insn_type = AARCH64_A64_CRYPTO;
        return;
    }
    if ((insn & 0xFF808000) == 0xCE000000) {
        s->insn_type = AARCH64_A64_CRYPTO;
        return;
    }
    if ((insn & 0xFFE00000) == 0xCE800000) {
        s->insn_type = AARCH64_A64_CRYPTO;
        return;
    }
    if ((insn & 0xFFE0C000) == 0xCE408000) {
        s->insn_type = AARCH64_A64_CRYPTO;
        return;
    }
    switch (extract32(insn, 25, 4)) {
        case 0x5:
        case 0xd: /* Data processing - register */
            s->insn_type = AARCH64_A64_DATA_PROC_REG;
            break;
        case 0x7:
        case 0xf: /* Data processing - SIMD and floating point */
            s->insn_type = AARCH64_A64_DATA_PROC_SIMD_FD;
            break;
        default:
            break;
    }
}

#ifdef CONFIG_LATA_TU
void get_last_info(TranslationBlock* tb, DisasContext* s)
{
    switch (s->insn_type) {
        case AARCH64_A64_B:
            tb->last_ir1_type = IR1_TYPE_JMP;
            tb->target_pc = s->pc_curr + ((arg_i)(s->arg.f_i)).imm;
            break;
        case AARCH64_A64_BR:
            tb->last_ir1_type = IR1_TYPE_JMPIN;
            break;
        case AARCH64_A64_BL:
            tb->last_ir1_type = IR1_TYPE_CALL;
            tb->target_pc = s->pc_curr + ((arg_i)(s->arg.f_i)).imm;
            break;
        case AARCH64_A64_BLR:
            tb->last_ir1_type = IR1_TYPE_CALLIN;
            break;
        case AARCH64_A64_B_cond:
            if (((arg_B_cond)(s->arg.f_decode_insn3211)).cond < 0x0e) {
                tb->last_ir1_type = IR1_TYPE_BRANCH;
                tb->target_pc = s->pc_curr +
                    ((arg_B_cond)(s->arg.f_decode_insn3211)).imm;
            } else {
                tb->last_ir1_type = IR1_TYPE_JMPIN;
            }
            break;
        case AARCH64_A64_TBZ:
            tb->last_ir1_type = IR1_TYPE_BRANCH;
            tb->target_pc = s->pc_curr + ((arg_tbz)(s->arg.f_tbz)).imm;
            break;
        case AARCH64_A64_CBZ:
            tb->last_ir1_type = IR1_TYPE_BRANCH;
            tb->target_pc = s->pc_curr + ((arg_cbz)(s->arg.f_cbz)).imm;
            break;
        case AARCH64_A64_RET:
            tb->last_ir1_type = IR1_TYPE_RET;
            break;
        case AARCH64_A64_SVC:
            tb->last_ir1_type = IR1_TYPE_SYSCALL;
            break;
        default:
            tb->last_ir1_type = IR1_TYPE_NORMAL;
            break;
    }
}
#endif

static void set_base_isjump(DisasContext* s)
{
    if (ir1_is_branch(s) || ir1_is_jmp(s) || ir1_is_call(s) || ir1_is_ret(s) || ir1_is_syscall(s)) {
        s->base->is_jmp = DISAS_NORETURN;
        return;
    }
    if (s->insn_type == AARCH64_A64_NULL) {
        s->base->is_jmp = DISAS_NORETURN;
        return;
    }
}

static DisasContext ir1_list[TCG_MAX_INSNS];
static DisasContextBase db_rel;

/*
    generate ir1_list
*/
DisasContext* get_ir1_list(CPUState* cpu, TranslationBlock* tb, vaddr pc, int max_insns)
{
    DisasContext* pir1 = NULL;

    uint32_t cflags = tb_cflags(tb);

    /* Initialize DisasContextBase */
    DisasContextBase* db = &db_rel;
    db->tb = tb;
    db->pc_first = pc;
    db->pc_next = pc;
    db->is_jmp = DISAS_NEXT;
    db->num_insns = 0;
    db->max_insns = max_insns;
    db->singlestep_enabled = cflags & CF_SINGLE_STEP;
    db->host_addr[0] = (void*)pc;
    db->host_addr[1] = NULL;

    tcg_debug_assert(db->is_jmp == DISAS_NEXT); /* no early exit */

    while (true) {
        max_insns = db->num_insns;
        pir1 = &ir1_list[max_insns];
        pir1->base = db;
        pir1->insn_type = AARCH64_A64_NULL;
        aarch64_tr_init_disas_context(pir1, cpu);
        tcg_debug_assert(db->is_jmp == DISAS_NEXT); /* no early exit */

        /* Disassemble one instruction.  The translate_insn hook should
           update db->pc_next and db->is_jmp to indicate what should be
           done next -- either exiting this loop or locate the start of
           the next instruction.  */
        if (db->num_insns == db->max_insns && (cflags & CF_LAST_IO)) {
            translate_aarch64_insn(pir1, cpu);
        } else {
            /* we should only see CF_MEMI_ONLY for io_recompile */
            tcg_debug_assert(!(cflags & CF_MEMI_ONLY));
            translate_aarch64_insn(pir1, cpu);
        }

#ifdef CONFIG_LATA_TU
        if (pir1->insn_type == AARCH64_A64_NULL) {
            tb->s_data->tu_tb_mode = TU_TB_MODE_BROKEN;
            tb->next_pc = tb->pc;
            db->pc_next = tb->pc;
            break;
        }
#endif

        db->num_insns++;

        /* Stop translation if translate_insn so indicated.  */
        if (db->is_jmp != DISAS_NEXT) {
            break;
        }

        /* Stop translation if the output buffer is full,
           or we have executed all of the allowed instructions.  */
        if (db->num_insns >= db->max_insns) {
            db->is_jmp = DISAS_TOO_MANY;
            break;
        }
    }

    tb->size = db->pc_next - db->pc_first;
    tb->icount = db->num_insns;

#ifndef CONFIG_LATA_TU
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM) && qemu_log_in_addr_range(db->pc_first)) {
        FILE* logfile = qemu_log_trylock();
        if (logfile && tb->icount) {
            fprintf(logfile, "IN: %s\n", lookup_symbol(db->pc_first));
            fprintf(logfile, "-----------------------------------------\n");

            target_disas(logfile, cpu, db->pc_first, db->tb->size);
            fprintf(logfile, "-----------------------------------------\n");
            qemu_log_unlock(logfile);
        }
    }
#endif

#ifdef CONFIG_LATA
    if (clearGprHigh) {
        uint32_t old = lsenv->tr_data->w_write_flag;
        if (old != 0) {
            printf("0x%lx :old:%x\n", db->pc_first, old);
            assert(old == 0);
        }
    }
#endif

#ifdef CONFIG_LATA_TU
    tb->next_pc = db->pc_next;
    get_last_info(tb, pir1);
#endif

    return ir1_list;
}

/*
    TB translate:replace original translate_insn funtion to store insn in ir1_list
    a) store insns information in ir1_list,tb->ir1 points to the first element of ir_list
*/
void target_disasm(struct TranslationBlock* tb, int* max_insns, CPUState* cpu)
{
    uint64_t pc = tb->pc;
    tb->ir1 = get_ir1_list(cpu, tb, pc, *max_insns);
#ifdef CONFIG_LATA_TU
    if (tb->ir1 && tb->icount) {
        DisasContext *ir1_copy = tu_ir1_alloc(tb->icount);

        memcpy(ir1_copy, tb->ir1, sizeof(DisasContext) * tb->icount);
        tb->ir1 = ir1_copy;
        tu_data->ir1_num_in_tu += tb->icount;
    }
#endif
    lata_df_analyze_tb(tb);
}

/* Decode one aarch64 instruction(just generate insns information,don't translate)
  a) use DisasContext to store information of each instruction
  b) use decode_ir1_a64.c.inc to generate insn_type and arg using translate_funtions
  c) determine whether it is jmp ins and mark DISAS_NORETURN if it is
*/
void translate_aarch64_insn(DisasContext* s, CPUState* cpu)
{
    CPUARMState* env = cpu->env_ptr;
    uint64_t pc = s->base->pc_next;
    uint32_t insn;

    /* Singlestep exceptions have the highest priority. */
    if (s->ss_active && !s->pstate_ss) {
        /* Singlestep state is Active-pending.
         * If we're in this state at the start of a TB then either
         *  a) we just took an exception to an EL which is being debugged
         *     and this is the first insn in the exception handler
         *  b) debug exceptions were masked and we just unmasked them
         *     without changing EL (eg by clearing PSTATE.D)
         * In either case we're going to take a swstep exception in the
         * "did not step an insn" case, and so the syndrome ISV and EX
         * bits should be zero.
         */
        lata_unallocated_encoding(s);
        return;
        s->base->is_jmp = DISAS_NORETURN;
        s->base->pc_next = pc + 4;
        return;
    }

    if (pc & 3) {
        /*
         * PC alignment fault.  This has priority over the instruction abort
         * that we would receive from a translation fault via arm_ldl_code.
         * This should only be possible after an indirect branch, at the
         * start of the TB.
         */
        lata_unallocated_encoding(s);
        return;
        s->base->is_jmp = DISAS_NORETURN;
        s->base->pc_next = QEMU_ALIGN_UP(pc, 4);
        return;
    }

    s->pc_curr = pc;
    insn = arm_ldl_code(env, s->base, pc, s->sctlr_b);
    s->insn = insn;
    s->base->pc_next = pc + 4;

    if (s->pstate_il) {
        s->insn_type = AARCH64_A64_EXCP_ILLEGAL;
        s->base->is_jmp = DISAS_NORETURN;
        return;
    }

    if (dc_isar_feature(aa64_bti, s)) {
        if (s->base->num_insns == 0) {
            s->guarded_page = lata_is_guarded_page(env, s);
            if (s->btype != 0 && s->guarded_page &&
                !lata_btype_destination_ok(insn, s->bt, s->btype)) {
                s->insn_type = AARCH64_A64_EXCP_BTI;
                s->base->is_jmp = DISAS_NORETURN;
                return;
            }
        } else {
            s->guarded_page = false;
        }
    }

    s->fp_access_checked = false;
    s->sve_access_checked = false;

    s->is_nonstreaming = false;

    // don't support sme and sve
    /* FCADD #90/#270 */
    if ((insn & 0xBF208C00) == 0x2E008400) {
        s->insn_type = AARCH64_A64_FCADD;
        goto skip_decode;
    }
    /* Check crypto instructions BEFORE decode_insn32 */
    {
        uint8_t ch = insn >> 24;
        if (ch == 0x4E || ch == 0x5E || ch == 0xCE) {
            bool is_cr = false;
            if ((insn & 0xFF3E0C00) == 0x4E280800)
                is_cr = true;
            else if ((insn & 0xFF208C00) == 0x5E000000)
                is_cr = true;
            else if ((insn & 0xFF3E0C00) == 0x5E280800)
                is_cr = true;
            else if ((insn & 0xFFE0B000) == 0xCE608000)
                is_cr = true;
            else if ((insn & 0xFFFFF000) == 0xCEC08000)
                is_cr = true;
            else if ((insn & 0xFF808000) == 0xCE000000)
                is_cr = true;
            else if ((insn & 0xFFE00000) == 0xCE800000)
                is_cr = true;
            else if ((insn & 0xFFE0C000) == 0xCE408000)
                is_cr = true;
            if (is_cr) {
                s->insn_type = AARCH64_A64_CRYPTO;
                goto skip_decode;
            }
        }
    }
    if (!decode_insn32(s, insn)) {
        disas_a64_legacy(s, insn);
    }
skip_decode:

#ifdef CONFIG_LATA_INSTS_PATTERN
    nzcv_use(s->base->tb, insn);
#endif

    // Determine whether the instruction is a jump type
    set_base_isjump(s);
}

/*ir1 -> ir2*/
bool tr_ir2_generate(struct TranslationBlock* tb)
{
    int i;
    int last_is_jmp = DISAS_NEXT;

    int ir1_nr = tb->icount;
    DisasContext* pir1 = (DisasContext*)tb->ir1;
    lata_df_begin_translate(tb);
    lata_vec_dirty_reset();
    for (i = 0; i < ir1_nr; ++i) {
#ifdef CONFIG_LATA_TU
        DisasContextBase tu_base = *pir1->base;
        tu_base.tb = tb;
        tu_base.pc_first = tb->pc;
        tu_base.pc_next = pir1->pc_curr + 4;
        tu_base.max_insns = ir1_nr;
        tu_base.num_insns = i;
        tu_base.is_jmp = DISAS_NEXT;
        pir1->base = &tu_base;
#endif
#ifdef CONFIG_LATA_INSTS_PATTERN
        /*Only check if the last two elements are CMP+B.COND*/
        if (i == ir1_nr - 2 && insts_pattern(pir1, pir1 + 1)) {
            tcg_ctx->gen_insn_end_off[i] = (lsenv->tr_data->real_ir2_inst_num) << 2;
            tcg_ctx->gen_insn_data[i * TARGET_INSN_START_WORDS] = pir1->pc_curr;
            lata_gpr_cache_end_insn();
            lata_df_advance_insn();
            last_is_jmp = DISAS_NORETURN;
            pir1 += 1; // update true pir1 for tb stop check
            break;
        }
#endif
        lata_debug_check_break_insn(pir1->pc_curr, pir1->insn,
                                    pir1->insn_type);
        if (lata_debug_should_trace_runtime(pir1->pc_curr)) {
            lata_gen_runtime_trace(pir1);
        }
        bool trans_success = translate_functions[pir1->insn_type](pir1);
        if (!trans_success) {
            lsassertm(0, "ir1_translate fail");
        }
        if (pir1->btype > 0 && pir1->base->is_jmp != DISAS_NORETURN) {
            lata_reset_btype(pir1);
        }
        last_is_jmp = pir1->base->is_jmp;
        lata_gpr_cache_end_insn();
        lata_df_advance_insn();
#ifndef CONFIG_LATA_TU
        tcg_ctx->gen_insn_end_off[i] = (lsenv->tr_data->real_ir2_inst_num) << 2;
        tcg_ctx->gen_insn_data[i * TARGET_INSN_START_WORDS] = pir1->pc_curr;
#endif
        pir1++;
    }

    /*tb stop function*/
    pir1--;
#ifdef CONFIG_LATA_TU
    DisasContextBase tail_base = *pir1->base;

    tail_base.tb = tb;
    tail_base.pc_first = tb->pc;
    tail_base.pc_next = pir1->pc_curr + 4;
    tail_base.max_insns = ir1_nr;
    tail_base.num_insns = ir1_nr;
    tail_base.is_jmp = last_is_jmp;
    pir1->base = &tail_base;
#endif
    switch (last_is_jmp) {
        case DISAS_NEXT:
        case DISAS_TOO_MANY:
            if (clearGprHigh) {
                for (int i = 0; i < 32; ++i) {
                    if (arm_la_map[i] >= 0) {
                        clear_gpr_high_for_boundary(i);
                    }
                }
            }
            gen_goto_tb(pir1, 1, 4);
            break;
        default:
        case DISAS_UPDATE_EXIT:
            lata_gen_a64_update_pc(pir1, 4);
            /* fall through */
        case DISAS_EXIT:
            lata_gen_exit_tb_ret_0(pir1);
            break;
        case DISAS_NORETURN:
            break;
    }

#ifdef CONFIG_LATA_TU
    gen_tu_unlink_stubs(tb);
#endif

    lata_df_end_translate();
    return true;
}

void arm_translate_init(void)
{
}
