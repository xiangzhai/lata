#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "lata.h"
#include "target/arm/lata/include/ir2-peephole.h"
#include "target/arm/lata/include/dataflow.h"
#include "lata-debug.h"

#include "exec/exec-all.h"
#include "qemu/cacheflush.h"
#include "qemu/log.h"
#include "env.h"
#ifdef CONFIG_LATA_TU
#include "tu.h"
#endif

void clear_gpr_high(int i);

//sp
//tp
//zero---unused
//a0-----goto_tb
//s8-----env 
//t0-t5--itemp
//FLAG---pstate
const int arm_la_map[] = {
    [armv8_x0] = la_ra,
    [armv8_x1] = la_a1,
    [armv8_x2] = la_a2,
    [armv8_x3] = la_a3,
    [armv8_x4] = la_a4,
    [armv8_x5] = la_a5,
    [armv8_x6] = la_a6,
    [armv8_x7] = la_a7,
    [armv8_x8] = la_fp,
    [armv8_x9] = la_t8,
    [armv8_x10] = la_t6,
    [armv8_x11] = -1,
    [armv8_x12] = -1,
    [armv8_x13] = -1,
    [armv8_x14] = -1,
    [armv8_x15] = -1,
    [armv8_x16] = -1,
    [armv8_x17] = -1,
    [armv8_x18] = -1,
    [armv8_x19] = la_s6,
    [armv8_x20] = la_s0,
    [armv8_x21] = la_s1,
    [armv8_x22] = la_s2,
    [armv8_x23] = la_s3,
    [armv8_x24] = la_s4,
    [armv8_x25] = -1,
    [armv8_x26] = -1,
    [armv8_x27] = -1,
    [armv8_x28] = la_s7,
    [armv8_x29] = la_t7,
    [armv8_x30] = la_s5,
    [armv8_xzr] = la_r21
};

const int arm_la_reverse_map[] = {
    [la_zero] = -1,
    [la_ra]  = armv8_x0,
    [la_sp]  = -1,
    [la_t7]  = armv8_x29,
    [la_s0]  = armv8_x20,
    [la_s1]  = armv8_x21,
    [la_s8]  = -1,
    [la_t8]  = armv8_x9,
    [la_a2]  = armv8_x2,
    [la_a3]  = armv8_x3,
    [la_a4]  = armv8_x4,
    [la_a5]  = armv8_x5,
    [la_a6]  = armv8_x6,
    [la_a7]  = armv8_x7,
    [la_s2]  = armv8_x22,
    [la_s3]  = armv8_x23,
    [la_s4]  = armv8_x24,
    [la_s5]  = armv8_x30,
    [la_s6]  = armv8_x19,
    [la_s7]  = armv8_x28,
    [la_t4]  = -1,
    [la_t5]  = -1,
    [la_t6]  = armv8_x10,
    [la_r21] = armv8_xzr,
    [la_tp] = -1,
    [la_a0] = -1,
    [la_a1] = armv8_x1,
    [la_t0] = -1,
    [la_t1] = -1,
    [la_t2] = -1,
    [la_t3] = -1,
    [la_fp] = armv8_x8 
};

const int arm_la_fmap[] = {
    [armv8_v0] = 0,
    [armv8_v1] = 1,
    [armv8_v2] = 2,
    [armv8_v3] = 3,
    [armv8_v4] = 4,
    [armv8_v5] = 5,
    [armv8_v6] = 6,
    [armv8_v7] = 7,
    [armv8_v8] = 8,
    [armv8_v9] = -1,
    [armv8_v10] = -1,
    [armv8_v11] = -1,
    [armv8_v12] = -1,
    [armv8_v13] = -1,
    [armv8_v14] = -1,
    [armv8_v15] = -1,
    [armv8_v16] = 16,
    [armv8_v17] = 17,
    [armv8_v18] = 18,
    [armv8_v19] = 19,
    [armv8_v20] = 20,
    [armv8_v21] = 21,
    [armv8_v22] = 22,
    [armv8_v23] = 23,
    [armv8_v24] = 24,
    [armv8_v25] = 25,
    [armv8_v26] = 26,
    [armv8_v27] = 27,
    [armv8_v28] = 28,
    [armv8_v29] = 29,
    [armv8_v30] = 30,
    [armv8_v31] = 31
};

const int arm_la_reverse_fmap[] = {
    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 3,
    [4] = 4,
    [5] = 5,
    [6] = 6,
    [7] = 7,
    [8] = 8,
    [9] = -1,
    [10] = -1,
    [11] = -1,
    [12] = -1,
    [13] = -1,
    [14] = -1,
    [la_fsmask] = -1,
    [16] = 16,
    [17] = 17,
    [18] = 18,
    [19] = 19,
    [20] = 20,
    [21] = 21,
    [22] = 22,
    [23] = 23,
    [24] = 24,
    [25] = 25,
    [26] = 26,
    [27] = 27,
    [28] = 28,
    [29] = 29,
    [30] = 30,
    [31] = 31

};

void lata(void);
__attribute__((constructor))
void lata(void){
    // printf("lata enabled\n");
}

__thread ENV *lsenv;
static __thread ENV lsenv_real;

static __thread TRANSLATION_DATA tr_data_real;
__thread TRANSLATION_DATA *tr_data;

bool lata_dump = 0;
uint64_t context_switch_bt_to_native;
uint64_t context_switch_native_to_bt_ret_0;
uint64_t context_switch_native_to_bt;

static void global_register_init(void)
{
    env_ir2_opnd = INIT_RA(IR2_OPND_GPR, reg_statics_map[S_ENV]);

    /* All LA reg */
    zero_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_zero);
    ra_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_ra);
    tp_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_tp);
    sp_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_sp);
    a0_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_a0);
    a1_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_a1);
    a2_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_a2);
    a3_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_a3);
    a4_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_a4);
    a5_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_a5);
    a6_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_a6);
    a7_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_a7);
    t0_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_t0);
    t1_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_t1);
    t2_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_t2);
    t3_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_t3);
    t4_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_t4);
    t5_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_t5);
    t6_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_t6);
    t7_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_t7);
    t8_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_t8);
    r21_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_r21);
    fp_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_fp);
    s0_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_s0);
    s1_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_s1);
    s2_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_s2);
    s3_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_s3);
    s4_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_s4);
    s5_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_s5);
    s6_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_s6);
    s7_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_s7);
    s8_ir2_opnd = INIT_RA(IR2_OPND_GPR, la_s8);
    fsmask_ir2_opnd = INIT_RA(IR2_OPND_FPR, la_fsmask); //mask for scalar
    fcsr_ir2_opnd = INIT_RA(IR2_OPND_FCSR, 0);
    fcsr1_ir2_opnd = INIT_RA(IR2_OPND_FCSR, 1);
    fcsr2_ir2_opnd = INIT_RA(IR2_OPND_FCSR, 2);
    fcsr3_ir2_opnd = INIT_RA(IR2_OPND_FCSR, 3);
    fcc0_ir2_opnd = INIT_RA(IR2_OPND_CC, 0);
    fcc1_ir2_opnd = INIT_RA(IR2_OPND_CC, 1);
    fcc2_ir2_opnd = INIT_RA(IR2_OPND_CC, 2);
    fcc3_ir2_opnd = INIT_RA(IR2_OPND_CC, 3);
    fcc4_ir2_opnd = INIT_RA(IR2_OPND_CC, 4);
    fcc5_ir2_opnd = INIT_RA(IR2_OPND_CC, 5);
    fcc6_ir2_opnd = INIT_RA(IR2_OPND_CC, 6);
    fcc7_ir2_opnd = INIT_RA(IR2_OPND_CC, 7);

    scr0_ir2_opnd = INIT_RA(IR2_OPND_SCR, 0);
    scr1_ir2_opnd = INIT_RA(IR2_OPND_SCR, 1);
    scr2_ir2_opnd = INIT_RA(IR2_OPND_SCR, 2);
    scr3_ir2_opnd = INIT_RA(IR2_OPND_SCR, 3);
}

void lata_tr_data_init(CPUArchState *env)
{
    lsenv = &lsenv_real;
    lsenv->cpu_state = env;
    lsenv->tr_data = &tr_data_real;
#ifdef CONFIG_LATA_TU
    tu_control_init();
#endif
    global_register_init();
}

void tr_init(void* tb)
{
    TRANSLATION_DATA *t = lsenv->tr_data;
    //int i = 0;

    t->curr_tb = tb;
    /* register allocation init */
    ra_free_all();

    /* reset ir2 array */
    if (t->ir2_inst_array == NULL) {
        lsassert(t->ir2_inst_num_max == 0);
        t->ir2_inst_array = (IR2_INST *)mm_calloc(400, sizeof(IR2_INST));
        t->ir2_inst_num_max = 400;
    }
    t->ir2_inst_num_current = 0;
    //uint64 k = &(t->ir2_inst_num_current);
    t->real_ir2_inst_num = 0;

    /* reset ir2 first/last/num */
    t->first_ir2 = NULL;
    t->last_ir2 = NULL;

    /* label number */
    t->label_num = 0;

}

void tr_fini(void)
{
    TRANSLATION_DATA *t = lsenv->tr_data;
    /* set current tb and ir1 */

    /* reset ir2 array */
    t->ir2_inst_num_current = 0;
    t->real_ir2_inst_num = 0;

    /* reset ir2 first/last/num */
    t->first_ir2 = NULL;
    t->last_ir2 = NULL;

    /* label number */
    t->label_num = 0;
}

#define EXTRA_SPACE             40
#define REG_LEN                 8
#define S0_EXTRA_SPACE          EXTRA_SPACE
#define S1_EXTRA_SPACE          (S0_EXTRA_SPACE + REG_LEN)
#define S2_EXTRA_SPACE          (S1_EXTRA_SPACE + REG_LEN)
#define S3_EXTRA_SPACE          (S2_EXTRA_SPACE + REG_LEN)
#define S4_EXTRA_SPACE          (S3_EXTRA_SPACE + REG_LEN)
#define S5_EXTRA_SPACE          (S4_EXTRA_SPACE + REG_LEN)
#define S6_EXTRA_SPACE          (S5_EXTRA_SPACE + REG_LEN)
#define S7_EXTRA_SPACE          (S6_EXTRA_SPACE + REG_LEN)
#define S8_EXTRA_SPACE          (S7_EXTRA_SPACE + REG_LEN)
#define FP_EXTRA_SPACE          (S8_EXTRA_SPACE + REG_LEN)
#define RA_EXTRA_SPACE          (FP_EXTRA_SPACE + REG_LEN)
#define FCSR_EXTRA_SPACE        (RA_EXTRA_SPACE + REG_LEN)


static void generate_context_switch_bt_to_native(void)
{
    la_addi_d(sp_ir2_opnd, sp_ir2_opnd, -256);

    /* save callee-saved LA registers. s0-s8 */
    la_st_d(s0_ir2_opnd, sp_ir2_opnd, S0_EXTRA_SPACE);
    la_st_d(s1_ir2_opnd, sp_ir2_opnd, S1_EXTRA_SPACE);
    la_st_d(s2_ir2_opnd, sp_ir2_opnd, S2_EXTRA_SPACE);
    la_st_d(s3_ir2_opnd, sp_ir2_opnd, S3_EXTRA_SPACE);
    la_st_d(s4_ir2_opnd, sp_ir2_opnd, S4_EXTRA_SPACE);
    la_st_d(s5_ir2_opnd, sp_ir2_opnd, S5_EXTRA_SPACE);
    la_st_d(s6_ir2_opnd, sp_ir2_opnd, S6_EXTRA_SPACE);
    la_st_d(s7_ir2_opnd, sp_ir2_opnd, S7_EXTRA_SPACE);
    la_st_d(s8_ir2_opnd, sp_ir2_opnd, S8_EXTRA_SPACE);

    /* save fp and ra */
    la_st_d(fp_ir2_opnd, sp_ir2_opnd, FP_EXTRA_SPACE);
    la_st_d(ra_ir2_opnd, sp_ir2_opnd, RA_EXTRA_SPACE);

    /* set env_opnd */
    la_mov64(env_ir2_opnd, a0_ir2_opnd);
    la_mov64(a0_ir2_opnd, a1_ir2_opnd);

    /* set pstate reg */
    la_ld_w(a7_ir2_opnd, env_ir2_opnd, env_offset_PSTATE());
    la_armmtflag(a7_ir2_opnd, 0x39);

    /* set fcsr, rm set by FPSCR[23:22], others was cleared */
    li_d(a5_ir2_opnd, env_offset_FPSCR());
    la_ldx_wu(a7_ir2_opnd, env_ir2_opnd, a5_ir2_opnd);
    la_bstrpick_d(a7_ir2_opnd, a7_ir2_opnd, 23, 22);
    li_d(a6_ir2_opnd, 1 << 6 | 3 << 4 | 2 << 2 | 0);
    la_slli_d(a7_ir2_opnd, a7_ir2_opnd, 1);
    la_srl_d(a7_ir2_opnd, a6_ir2_opnd, a7_ir2_opnd);
    la_andi(a7_ir2_opnd, a7_ir2_opnd, 0x3);
    la_slli_d(a7_ir2_opnd, a7_ir2_opnd, 8);
    la_movgr2fcsr(fcsr_ir2_opnd, a7_ir2_opnd);


    /* load gpr and fpr */
    for(int i = 0; i <= 31; ++i) {
        if (arm_la_fmap[i] >= 0) {
            la_vld(ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[i]), env_ir2_opnd, env_offset_fpr(i));
        }
    }
    for(int i = 0; i <= 31; ++i) {
        if(arm_la_map[i] > 0) {
            la_ld_d(ir2_opnd_new(IR2_OPND_GPR, arm_la_map[i]), env_ir2_opnd, env_offset_gpr(i));
        }
    }

    /* Initialize scalar mask register: keep the low 64-bit scalar payload,
     * including the sign bit of s/h values, and clear the high 64 bits. */
    la_vxor_v(fsmask_ir2_opnd, fsmask_ir2_opnd, fsmask_ir2_opnd);
    li_d(t0_ir2_opnd, UINT64_MAX);
    la_vinsgr2vr_d(fsmask_ir2_opnd, t0_ir2_opnd, 0);

    /* jmp to tb */
    la_jirl(zero_ir2_opnd, a0_ir2_opnd, 0);

}

static void generate_context_switch_native_to_bt(void)
{
    la_mov64(a0_ir2_opnd, zero_ir2_opnd);
    for(int i = 0; i <= 31; ++i) {
        if(arm_la_map[i] > 0) {
            la_st_d(ir2_opnd_new(IR2_OPND_GPR, arm_la_map[i]), env_ir2_opnd, env_offset_gpr(i));
        }
    }
    for(int i = 0; i <= 31; ++i) {
        if (arm_la_fmap[i] >= 0) {
            la_vst(ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[i]), env_ir2_opnd, env_offset_fpr(i));
        }
    }

    /* store pstate reg */
    la_armmfflag(t0_ir2_opnd, 0x39);
    la_st_w(t0_ir2_opnd, env_ir2_opnd, env_offset_PSTATE());
    
    /* store fcsr(rouding mode) to vfp.xregs[ARM_VFP_FPSCR] */
    la_movfcsr2gr(t0_ir2_opnd, fcsr3_ir2_opnd);
    li_d(t1_ir2_opnd, 2 << 6 | 1 << 4 | 3 << 2 | 0);
    la_srli_d(t0_ir2_opnd, t0_ir2_opnd, 7);
    la_srl_d(t0_ir2_opnd, t1_ir2_opnd, t0_ir2_opnd);
    la_andi(t0_ir2_opnd, t0_ir2_opnd, 0x3);
    li_d(t2_ir2_opnd, env_offset_FPSCR());
    la_ldx_wu(t1_ir2_opnd, env_ir2_opnd, t2_ir2_opnd);
    la_bstrins_d(t1_ir2_opnd, t0_ir2_opnd, 23, 22);
    la_stx_w(t1_ir2_opnd, env_ir2_opnd, t2_ir2_opnd);

    /* load callee-saved LA registers. s0-s8 */
    la_ld_d(s0_ir2_opnd, sp_ir2_opnd, S0_EXTRA_SPACE);
    la_ld_d(s1_ir2_opnd, sp_ir2_opnd, S1_EXTRA_SPACE);
    la_ld_d(s2_ir2_opnd, sp_ir2_opnd, S2_EXTRA_SPACE);
    la_ld_d(s3_ir2_opnd, sp_ir2_opnd, S3_EXTRA_SPACE);
    la_ld_d(s4_ir2_opnd, sp_ir2_opnd, S4_EXTRA_SPACE);
    la_ld_d(s5_ir2_opnd, sp_ir2_opnd, S5_EXTRA_SPACE);
    la_ld_d(s6_ir2_opnd, sp_ir2_opnd, S6_EXTRA_SPACE);
    la_ld_d(s7_ir2_opnd, sp_ir2_opnd, S7_EXTRA_SPACE);
    la_ld_d(s8_ir2_opnd, sp_ir2_opnd, S8_EXTRA_SPACE);

    /* load fp and ra */
    la_ld_d(fp_ir2_opnd, sp_ir2_opnd, FP_EXTRA_SPACE);
    la_ld_d(ra_ir2_opnd, sp_ir2_opnd, RA_EXTRA_SPACE);

    la_addi_d(sp_ir2_opnd, sp_ir2_opnd, 256);

    /* TODO: clear fcsr*/
    la_movgr2fcsr(fcsr_ir2_opnd, zero_ir2_opnd);

    la_jirl(zero_ir2_opnd, ra_ir2_opnd, 0);
}



/* bt -> native */
int lata_gen_prologue(TCGContext *tcg_ctx)
{
    lsassert(context_switch_bt_to_native == 0);
    void *code_buf_rw = tcg_ctx->code_ptr;
    const void *code_buf_rx = tcg_splitwx_to_rx(code_buf_rw);
    context_switch_bt_to_native = (uint64_t)code_buf_rx;

    if (lata_dump)
        qemu_log("[LATA] context_switch_bt_to_native = %p\n",
                (void *)context_switch_bt_to_native);

    tr_init(NULL);
    generate_context_switch_bt_to_native();
//    int ins_nr = la_encode(tcg_ctx, code_buf_rw);
    int ins_nr = tr_ir2_assemble(code_buf_rw);
    tr_fini();

    return ins_nr;
}

/* native -> bt */
int lata_gen_epilogue(TCGContext *tcg_ctx)
{
    lsassert(context_switch_native_to_bt == 0);
    void *code_buf_rw = tcg_ctx->code_ptr;
    const void *code_buf_rx = tcg_splitwx_to_rx(code_buf_rw);
    context_switch_native_to_bt_ret_0 = (uint64_t)code_buf_rx;
    context_switch_native_to_bt = (uint64_t)code_buf_rx + 4;

    if (lata_dump)
        qemu_log("[LATA] context_switch_native_to_bt = %p\n",
                (void *)context_switch_native_to_bt);

    tr_init(NULL);
    generate_context_switch_native_to_bt();
    int ins_nr = tr_ir2_assemble(code_buf_rw);
    tr_fini();

    return ins_nr;
}

void label_dispose(void)
{
    /* 1. record the positions of label */
    int *label_num_to_ir2_num =
        (int *)alloca(lsenv->tr_data->label_num * 4 + 20);
    memset(label_num_to_ir2_num, -1, lsenv->tr_data->label_num * 4 + 20);
    int ir2_num = 0;
    IR2_INST *ir2_current = lsenv->tr_data->first_ir2;
    while (ir2_current != NULL) {
        if (ir2_current->_opcode == LISA_LABEL) {
            int label_num = ir2_opnd_label_id(&ir2_current->_opnd[0]);
            lsassertm(label_num_to_ir2_num[label_num] == -1,
                      "label %d is in multiple positions\n", label_num);
            label_num_to_ir2_num[label_num] = ir2_num;
        } else if (ir2_current->_opcode == LISA_X86_INST) {
            /* will not be assembled */
        } else {
            ir2_num++;
        }
        ir2_current = ir2_next(ir2_current);
    }

    /* 2. resolve the offset of successor linkage code */
    /* @jmp_target_arg recoed the jmp  inst position */
    /* @jmp_reset_offset record the successor inst of jmp(exclude delay slot).
     */
    /*                   when the tb is removed from buffer. the jmp inst use
     */
    /*                   this position to revert the original "fall through".
     */
    {
        TranslationBlock *tb = lsenv->tr_data->curr_tb;

        /* prologue/epilogue has no tb */
        if (tb) {
            /* ctx->jmp_insn_offset point to tb->jmp_target_arg */
            int label_id_0 = tb->jmp_reset_offset[0];
            if (label_id_0 != TB_JMP_OFFSET_INVALID) {
                tb->jmp_insn_offset[0] =
                    (label_num_to_ir2_num[label_id_0] << 2);
                tb->jmp_reset_offset[0] =
                    (label_num_to_ir2_num[label_id_0] << 2) + B_STUB_SIZE;
                // tb->jmp_target_addr[0] = (label_num_to_ir2_num[label_id_0] << 2);
            }

            int label_id_1 = tb->jmp_reset_offset[1];
            if (label_id_1 != TB_JMP_OFFSET_INVALID) {
                tb->jmp_insn_offset[1] =
                    (label_num_to_ir2_num[label_id_1] << 2);
                tb->jmp_reset_offset[1] =
                    (label_num_to_ir2_num[label_id_1] << 2) + B_STUB_SIZE;
                // tb->jmp_target_addr[1] = (label_num_to_ir2_num[label_id_1] << 2);
            }

#ifdef CONFIG_LATA_INSTS_PATTERN
            label_id_0 = tb->nzcv_save[0];
            if (label_id_0 != TB_JMP_OFFSET_INVALID) {
                tb->nzcv_save[0] = (label_num_to_ir2_num[label_id_0] << 2);
            }

            label_id_1 = tb->nzcv_save[1];
            if (label_id_1 != TB_JMP_OFFSET_INVALID) {
                tb->nzcv_save[1] = (label_num_to_ir2_num[label_id_1] << 2);
            }
#endif
#ifdef CONFIG_LATA_TU
            if (tu_use_jmp(tb)) {
                for (int i = 0; i < 2; i++) {
                    LataTUEdge *edge = &tb->tu_edges[i];
                    int label_id = edge->branch_offset;
                    if (label_id != LATA_TU_EDGE_OFFSET_INVALID) {
                        lsassert(label_id > 0 && label_id <= lsenv->tr_data->label_num);
                        lsassertm(label_num_to_ir2_num[label_id] != -1,
                                  "TU jump label %d is not inserted\n",
                                  label_id);
                        edge->branch_offset =
                            (label_num_to_ir2_num[label_id] << 2);
                    }
                }

                for (int i = 0; i < 2; i++) {
                    LataTUEdge *edge = &tb->tu_edges[i];
                    if (edge->unlink_stub_offset != TU_UNLINK_STUB_INVALID) {
                        int label_id = edge->unlink_stub_offset;
                        lsassert(label_id > 0 && label_id <= lsenv->tr_data->label_num);
                        lsassertm(label_num_to_ir2_num[label_id] != -1,
                                  "TU unlink label %d is not inserted\n",
                                  label_id);
                        edge->unlink_stub_offset =
                            (label_num_to_ir2_num[label_id] << 2);
                    }
                }
            }
#endif
        }
    }

    /* 3. resolve the branch instructions */
    ir2_num = 0;
    ir2_current = lsenv->tr_data->first_ir2;
    while (ir2_current != NULL) {
        IR2_OPCODE opcode = ir2_current->_opcode;
        if (ir2_opcode_is_branch(opcode) || ir2_opcode_is_f_branch(opcode)) {
            IR2_OPND *label_opnd = NULL;
            if (ir2_current->_opcode == LISA_B ||
                ir2_current->_opcode == LISA_BL) {
                label_opnd = &ir2_current->_opnd[0];
            } else if (ir2_opcode_is_branch_with_3opnds(opcode)) {
                label_opnd = &ir2_current->_opnd[2];
            } else if (ir2_opcode_is_f_branch(opcode) ||
                       ir2_opcode_is_branch_with_2opnds(opcode)) {
                label_opnd = &ir2_current->_opnd[1];
            }
            if(label_opnd && ir2_opnd_is_label(label_opnd)) {
                int label_num = label_opnd->_label_id;
                lsassert(label_num > 0 && label_num <= lsenv->tr_data->label_num);
                int target_ir2_num = label_num_to_ir2_num[label_num];
                lsassertm(target_ir2_num != -1, "label %d is not inserted\n",
                          label_num);
                ir2_opnd_convert_label_to_imm(label_opnd,
                                              target_ir2_num - ir2_num);
            }
        }

        if (ir2_current->_opcode != LISA_LABEL &&
            ir2_current->_opcode != LISA_X86_INST) {
            ir2_num++;
        }
        ir2_current = ir2_next(ir2_current);
    }
}

int tr_ir2_assemble(const void *code_start_addr)
{
    if (lata_dump || option_lata_dump_host) {
        qemu_log("[LATA] Assemble IR2.\n");
    }

    /* 1. assign temp register to physical register */
    /* now, temp register is physical register */

    lata_ir2_peephole_run();

    /* 2. label dispose */
    label_dispose();

    /* 3. assemble */
    IR2_INST *pir2 = lsenv->tr_data->first_ir2;

    void *code_addr = (void *) code_start_addr;
    int code_nr = 0;

    while (pir2 != NULL) {
        if (ir2_opcode(pir2) != LISA_LABEL &&
            ir2_opcode(pir2) != LISA_X86_INST) {
            uint32 result = ir2_assemble(pir2);

            if (lata_dump || option_lata_dump_host) {
                lata_debug_dump_assembled_ir2(pir2->_id, code_addr, result,
                                              pir2);
            }

            *(uint32 *)code_addr = result;
            code_addr = code_addr + 4;
            code_nr += 1;
        }
        pir2 = ir2_next(pir2);
    }

    return code_nr;
}

static void lata_flush_writes_before_helper(void)
{
    if (!lsenv || !lsenv->tr_data || !lsenv->tr_data->w_write_flag) {
        return;
    }

    for (int i = 0; i <= 30; ++i) {
        if (arm_la_map[i] > 0) {
            clear_gpr_high(i);
        }
    }
}

void lata_gen_call_helper_prologue(TCGContext *tcg_ctx)
{
    lata_df_mark_helper_boundary();
    lata_flush_writes_before_helper();

    for(int i = 0; i <= 31; ++i) {
        if(arm_la_map[i] > 0) {
            la_st_d(ir2_opnd_new(IR2_OPND_GPR, arm_la_map[i]), env_ir2_opnd, env_offset_gpr(i));
        }
    }

    for(int i = 0; i <= 31; ++i) {
        if (arm_la_fmap[i] >= 0) {
            la_vst(ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[i]), env_ir2_opnd, env_offset_fpr(i));
        }
        // if(arm_la_fmap[i] >= 0) {
        //     li_d(t0_ir2_opnd, env_offset_fpr(i));
        //     la_vstx(ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[i]), env_ir2_opnd, t0_ir2_opnd);
        // }
    }

    /* store pstate reg */
    la_armmfflag(t0_ir2_opnd, 0x39);
    la_st_w(t0_ir2_opnd, env_ir2_opnd, env_offset_PSTATE());
    
    /* store fcsr(rouding mode) to vfp.xregs[ARM_VFP_FPSCR] */
    la_movfcsr2gr(t0_ir2_opnd, fcsr3_ir2_opnd);
    li_d(t1_ir2_opnd, 2 << 6 | 1 << 4 | 3 << 2 | 0);
    la_srli_d(t0_ir2_opnd, t0_ir2_opnd, 7);
    la_srl_d(t0_ir2_opnd, t1_ir2_opnd, t0_ir2_opnd);
    la_andi(t0_ir2_opnd, t0_ir2_opnd, 0x3);
    li_d(t2_ir2_opnd, env_offset_FPSCR());
    la_ldx_wu(t1_ir2_opnd, env_ir2_opnd, t2_ir2_opnd);
    la_bstrins_d(t1_ir2_opnd, t0_ir2_opnd, 23, 22);
    la_stx_w(t1_ir2_opnd, env_ir2_opnd, t2_ir2_opnd);

    /* Accumulate FCSR0 exception flags (bits 20:16) → float_exception_flags.
     * LA64 FCSR FLAGS field (5-bit, FCSR[20:16]):
     *   bit4=INVALID, bit3=DIV0, bit2=OVERFLOW, bit1=UNDERFLOW, bit0=INEXACT
     * ARM softfloat flags:
     *   bit0=invalid, bit1=divbyzero, bit2=overflow, bit3=underflow, bit4=inexact
     * These are bit-reversed: LA64[4]→ARM[0], LA64[3]→ARM[1],
     *   LA64[2]→ARM[2], LA64[1]→ARM[3], LA64[0]→ARM[4].
     * Build ARM flags: (t0&16)>>4 | (t0&8)>>1 | (t0&4) | (t0&2)<<1 | (t0&1)<<4
     * Simplifies to: (t0&16)>>4 + (t0&8)>>2 + (t0&4) + (t0&2)<<2 + (t0&1)<<4
     * Controlled by -fp_precise option (default: enabled). */
    la_movfcsr2gr(t0_ir2_opnd, fcsr_ir2_opnd);
    la_bstrpick_d(t0_ir2_opnd, t0_ir2_opnd, 20, 16);  /* t0 = LA64 FLAGS[4:0] */
    /* Extract each bit and place at ARM position */
    la_srli_d(t1_ir2_opnd, t0_ir2_opnd, 4);            /* LA64[4]→ARM[0] */
    la_andi(t1_ir2_opnd, t1_ir2_opnd, 1);
    la_srli_d(t2_ir2_opnd, t0_ir2_opnd, 2);
    la_andi(t2_ir2_opnd, t2_ir2_opnd, 2);              /* LA64[3]→ARM[1] */
    la_or(t1_ir2_opnd, t1_ir2_opnd, t2_ir2_opnd);
    la_andi(t2_ir2_opnd, t0_ir2_opnd, 4);              /* LA64[2]→ARM[2] */
    la_or(t1_ir2_opnd, t1_ir2_opnd, t2_ir2_opnd);
    la_slli_d(t2_ir2_opnd, t0_ir2_opnd, 2);
    la_andi(t2_ir2_opnd, t2_ir2_opnd, 8);              /* LA64[1]→ARM[3] */
    la_or(t1_ir2_opnd, t1_ir2_opnd, t2_ir2_opnd);
    la_slli_d(t2_ir2_opnd, t0_ir2_opnd, 4);
    la_andi(t2_ir2_opnd, t2_ir2_opnd, 16);             /* LA64[0]→ARM[4] */
    la_or(t1_ir2_opnd, t1_ir2_opnd, t2_ir2_opnd);
    /* Accumulate: float_exception_flags |= t1 */
    li_d(t2_ir2_opnd, env_offset_fpstatus() + offsetof(float_status, float_exception_flags));
    la_ldx_w(t0_ir2_opnd, env_ir2_opnd, t2_ir2_opnd);
    la_or(t0_ir2_opnd, t0_ir2_opnd, t1_ir2_opnd);
    la_stx_w(t0_ir2_opnd, env_ir2_opnd, t2_ir2_opnd);

    /* clear fcsr */
    la_movgr2fcsr(fcsr_ir2_opnd, zero_ir2_opnd);
}

void lata_gen_call_helper_prologue_no_flags(TCGContext *tcg_ctx)
{
    lata_df_mark_helper_boundary();
    lata_flush_writes_before_helper();

    for(int i = 0; i <= 31; ++i) {
        if(arm_la_map[i] > 0) {
            la_st_d(ir2_opnd_new(IR2_OPND_GPR, arm_la_map[i]), env_ir2_opnd, env_offset_gpr(i));
        }
    }

    for(int i = 0; i <= 31; ++i) {
        if (arm_la_fmap[i] >= 0) {
            la_vst(ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[i]), env_ir2_opnd, env_offset_fpr(i));
        }
    }
}

void lata_gen_call_helper_epilogue(TCGContext *tcg_ctx)
{
    /* set pstate reg */
    la_ld_w(a7_ir2_opnd, env_ir2_opnd, env_offset_PSTATE());
    la_armmtflag(a7_ir2_opnd, 0x39);

    /* set fcsr, rm set by FPSCR[23:22], others was cleared */
    li_d(a5_ir2_opnd, env_offset_FPSCR());
    la_ldx_wu(a7_ir2_opnd, env_ir2_opnd, a5_ir2_opnd);
    la_bstrpick_d(a7_ir2_opnd, a7_ir2_opnd, 23, 22);
    li_d(a6_ir2_opnd, 1 << 6 | 3 << 4 | 2 << 2 | 0);
    la_slli_d(a7_ir2_opnd, a7_ir2_opnd, 1);
    la_srl_d(a7_ir2_opnd, a6_ir2_opnd, a7_ir2_opnd);
    la_andi(a7_ir2_opnd, a7_ir2_opnd, 0x3);
    la_slli_d(a7_ir2_opnd, a7_ir2_opnd, 8);
    la_movgr2fcsr(fcsr_ir2_opnd, a7_ir2_opnd);

    for(int i = 0; i <= 31; ++i) {
        if (arm_la_fmap[i] >= 0) {
            la_vld(ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[i]), env_ir2_opnd, env_offset_fpr(i));
        }
        // if(arm_la_fmap[i] >= 0) {
        //     li_d(a7_ir2_opnd, env_offset_fpr(i));
        //     la_vldx(ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[i]), env_ir2_opnd, a7_ir2_opnd);
        // }
    }

    for(int i = 0; i <= 31; ++i) {
        if(arm_la_map[i] > 0) {
            la_ld_d(ir2_opnd_new(IR2_OPND_GPR, arm_la_map[i]), env_ir2_opnd, env_offset_gpr(i));
        }
    }
}

void lata_gen_call_helper_epilogue_no_flags(TCGContext *tcg_ctx)
{
    for(int i = 0; i <= 31; ++i) {
        if (arm_la_fmap[i] >= 0) {
            la_vld(ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[i]), env_ir2_opnd, env_offset_fpr(i));
        }
    }

    for(int i = 0; i <= 31; ++i) {
        if(arm_la_map[i] > 0) {
            la_ld_d(ir2_opnd_new(IR2_OPND_GPR, arm_la_map[i]), env_ir2_opnd, env_offset_gpr(i));
        }
    }
}

static inline uint32_t lata_fam_hash(uint64_t pc)
{
    return (pc ^ (pc >> TB_JMP_CACHE_BITS)) & (TB_JMP_CACHE_SIZE - 1);
}

static inline uint32_t lata_fam_tb_cflags(TranslationBlock *tb)
{
    return tb_cflags(tb) & ~CF_INVALID;
}

QEMU_BUILD_BUG_ON(sizeof(LataFAMEntry) != 32);

static bool lata_fam_tb_cacheable(TranslationBlock *tb)
{
    uint32_t cflags = tb_cflags(tb);

    if (option_fam_jmp_cache < 0) {
        return false;
    }
    if (cflags & (CF_COUNT_MASK | CF_INVALID | CF_NO_GOTO_TB |
                  CF_NO_GOTO_PTR | CF_SINGLE_STEP | CF_LAST_IO |
                  CF_MEMI_ONLY | CF_USE_ICOUNT | CF_NOIRQ | CF_PCREL)) {
        return false;
    }
    return true;
}

static void lata_fam_clear_entry(LataFAMEntry *entry)
{
    qatomic_set(&entry->host_ptr, NULL);
    qatomic_set(&entry->tb, NULL);
    entry->pc = 0;
    entry->cs_base = 0;
    entry->flags_cflags = 0;
}

static bool lata_fam_entry_has_tb(LataFAMCache *cache, LataFAMEntry *entry,
                                  uint32_t index, TranslationBlock *tb,
                                  uint32_t cflags)
{
    if (entry->pc != tb->pc || entry->cs_base != tb->cs_base ||
        entry->flags != tb->flags || entry->cflags != cflags) {
        return false;
    }

    if (cache->fast_tbs) {
        return qatomic_load_acquire(&cache->fast_tbs[index]) == tb &&
               qatomic_load_acquire(&entry->host_ptr) == tb->tc.ptr;
    }
    return qatomic_load_acquire(&entry->tb) == tb;
}

bool lata_fam_init(CPUArchState *env)
{
    LataFAMCache *cache;
    size_t size;

    lata_fam_destroy(env);
    env->lata_fam_cache = NULL;
    env->lata_cpu_state = env_cpu(env);

    if (option_fam_jmp_cache < 0) {
        return true;
    }

    size = sizeof(*cache) + sizeof(cache->entries[0]) * TB_JMP_CACHE_SIZE;
    cache = g_malloc0(size);
    cache->size = TB_JMP_CACHE_SIZE;
    cache->mask = TB_JMP_CACHE_SIZE - 1;
    if (option_fam_jmp_cache > 0) {
        cache->fast_tbs = g_new0(TranslationBlock *, TB_JMP_CACHE_SIZE);
    }
    env->lata_fam_cache = cache;
    return true;
}

void lata_fam_destroy(CPUArchState *env)
{
    LataFAMCache *cache = env->lata_fam_cache;

    if (cache) {
        g_free(cache->fast_tbs);
        g_free(cache);
    }
    env->lata_fam_cache = NULL;
}

void lata_fam_clear_all(CPUArchState *env)
{
    LataFAMCache *cache = env->lata_fam_cache;

    if (!cache) {
        return;
    }

    for (uint32_t i = 0; i < cache->size; i++) {
        lata_fam_clear_entry(&cache->entries[i]);
    }
    if (cache->fast_tbs) {
        memset(cache->fast_tbs, 0,
               sizeof(cache->fast_tbs[0]) * cache->size);
    }
    lata_debug_note_fam_clear_all();
}

void lata_fam_clear_page(CPUArchState *env, uint64_t page_addr)
{
    LataFAMCache *cache = env->lata_fam_cache;
    uint64_t page = page_addr & TARGET_PAGE_MASK;

    if (!cache) {
        return;
    }

    for (uint32_t i = 0; i < cache->size; i++) {
        LataFAMEntry *entry = &cache->entries[i];
        TranslationBlock *tb = cache->fast_tbs ?
            qatomic_load_acquire(&cache->fast_tbs[i]) :
            qatomic_load_acquire(&entry->tb);
        void *host_ptr = qatomic_load_acquire(&entry->host_ptr);
        bool live = tb || host_ptr;
        bool entry_matches = (entry->pc & TARGET_PAGE_MASK) == page;
        bool tb_matches = tb && (tb->pc & TARGET_PAGE_MASK) == page;

        if (live && (entry_matches || tb_matches)) {
            lata_fam_clear_entry(entry);
            if (cache->fast_tbs) {
                qatomic_set(&cache->fast_tbs[i], NULL);
            }
            lata_debug_note_fam_invalidate();
        }
    }
}

void lata_fam_clear_all_cpus(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        lata_fam_clear_all(cpu->env_ptr);
    }
}

void lata_fam_add_tb(CPUArchState *env, TranslationBlock *tb)
{
    LataFAMCache *cache = env->lata_fam_cache;
    LataFAMEntry *entry;
    uint32_t cflags;
    uint32_t index;

    if (!cache || !tb || !tb->tc.ptr || !lata_fam_tb_cacheable(tb)) {
        return;
    }

    cflags = lata_fam_tb_cflags(tb);
    index = lata_fam_hash(tb->pc) & cache->mask;
    entry = &cache->entries[index];
    if (lata_fam_entry_has_tb(cache, entry, index, tb, cflags)) {
        return;
    }
    if (entry->pc || qatomic_load_acquire(&entry->tb) ||
        qatomic_load_acquire(&entry->host_ptr)) {
        lata_debug_note_fam_overwrite();
    }
    lata_fam_clear_entry(entry);
    if (cache->fast_tbs) {
        qatomic_set(&cache->fast_tbs[index], NULL);
    }
    entry->pc = tb->pc;
    entry->cs_base = tb->cs_base;
    entry->flags = tb->flags;
    entry->cflags = cflags;
    if (cache->fast_tbs) {
        qatomic_store_release(&cache->fast_tbs[index], tb);
        qatomic_store_release(&entry->host_ptr, tb->tc.ptr);
    } else {
        qatomic_store_release(&entry->tb, tb);
    }
    lata_debug_note_fam_add(option_fam_jmp_cache > 0);
}

void lata_fam_invalidate_tb(CPUArchState *env, TranslationBlock *tb)
{
    LataFAMCache *cache = env->lata_fam_cache;
    LataFAMEntry *entry;
    uint32_t cflags;
    uint32_t index;

    if (!cache || !tb) {
        return;
    }

    cflags = tb_cflags(tb) & ~CF_INVALID;
    index = lata_fam_hash(tb->pc) & cache->mask;
    entry = &cache->entries[index];
    if (entry->pc != tb->pc || entry->cs_base != tb->cs_base ||
        entry->flags != tb->flags || entry->cflags != cflags) {
        return;
    }

    if (cache->fast_tbs) {
        if (qatomic_load_acquire(&cache->fast_tbs[index]) != tb) {
            return;
        }
    } else if (qatomic_load_acquire(&entry->tb) != tb) {
        return;
    }

    lata_fam_clear_entry(entry);
    if (cache->fast_tbs) {
        qatomic_set(&cache->fast_tbs[index], NULL);
    }
    lata_debug_note_fam_invalidate();
}

static bool lata_fam_branch_disp_fits(uintptr_t fix_addr, uintptr_t target)
{
    int64_t disp = ((int64_t)target - (int64_t)fix_addr) >> 2;

    return disp >= -(1 << 25) && disp < (1 << 25);
}

static bool lata_fam_patch_direct_branch(TranslationBlock *tb, int n,
                                         TranslationBlock *target)
{
    uintptr_t fix_addr;
    uintptr_t target_addr;
    uint32_t *fix_rw;
    uint32_t insn;
    int64_t disp;

    if (tb->jmp_insn_offset[n] == TB_JMP_OFFSET_INVALID ||
        !target || !target->tc.ptr) {
        return false;
    }

    fix_addr = (uintptr_t)tb->tc.ptr + tb->jmp_insn_offset[n];
    target_addr = (uintptr_t)target->tc.ptr;
    insn = *(uint32_t *)fix_addr;
    if ((insn & 0xfc000000) != 0x50000000 &&
        (insn & 0xfe00001f) != (0x18000000 | 4)) {
        return false;
    }

    if (lata_fam_branch_disp_fits(fix_addr, target_addr)) {
        disp = ((int64_t)target_addr - (int64_t)fix_addr) >> 2;
        insn = 0x50000000;
        insn |= ((uint32_t)disp & 0xffff) << 10;
        insn |= ((uint32_t)disp >> 16) & 0x3ff;
    } else {
        uintptr_t slot = (uintptr_t)&tb->jmp_target_addr[n];
        intptr_t slot_disp = ((intptr_t)slot - (intptr_t)fix_addr) >> 2;

        if (slot_disp < -(1 << 19) || slot_disp >= (1 << 19)) {
            return false;
        }
        insn = 0x18000000 | 4;
        insn |= ((uint32_t)slot_disp & 0xfffff) << 5;
    }
    fix_rw = (uint32_t *)(fix_addr - tcg_splitwx_diff);
    tb->jmp_target_addr[n] = target_addr;
    qatomic_set(fix_rw, insn);
    flush_idcache_range(fix_addr, (uintptr_t)fix_rw, 4);
    return true;
}

void lata_fam_prelink_tb(TranslationBlock *tb)
{
    if (!tb || option_fam_jmp_cache < 0) {
        return;
    }

    for (int n = 0; n < 2; n++) {
        TranslationBlock *target = tb->lata_prelink_tb[n];
        uintptr_t old;

        if (!target || !target->tc.ptr ||
            tb->jmp_reset_offset[n] == TB_JMP_OFFSET_INVALID ||
            tb->jmp_insn_offset[n] == TB_JMP_OFFSET_INVALID) {
            continue;
        }

        qemu_spin_lock(&target->jmp_lock);
        if (target->cflags & CF_INVALID) {
            qemu_spin_unlock(&target->jmp_lock);
            continue;
        }

        old = qatomic_cmpxchg(&tb->jmp_dest[n], (uintptr_t)NULL,
                              (uintptr_t)target);
        if (old) {
            qemu_spin_unlock(&target->jmp_lock);
            continue;
        }

        if (!lata_fam_patch_direct_branch(tb, n, target)) {
            qatomic_set(&tb->jmp_dest[n], (uintptr_t)NULL);
            qemu_spin_unlock(&target->jmp_lock);
            continue;
        }

        tb->jmp_list_next[n] = target->jmp_list_head;
        target->jmp_list_head = (uintptr_t)tb | n;
        qemu_spin_unlock(&target->jmp_lock);
    }
}

TranslationBlock *lata_fam_lookup_tb(CPUArchState *env, uint64_t pc,
                                     uint64_t cs_base, uint32_t flags,
                                     uint32_t cflags)
{
    LataFAMCache *cache = env ? env->lata_fam_cache : NULL;
    TranslationBlock *tb;
    uint32_t index;

    if (!cache || option_fam_jmp_cache < 0) {
        return NULL;
    }

    cflags &= ~CF_INVALID;
    index = lata_fam_hash(pc) & cache->mask;
    LataFAMEntry *entry = &cache->entries[index];
    uint32_t tb_cflags;

    if (cache->fast_tbs) {
        tb = qatomic_load_acquire(&cache->fast_tbs[index]);
    } else {
        tb = qatomic_load_acquire(&entry->tb);
    }
    if (!tb || entry->pc != pc || entry->cs_base != cs_base ||
        entry->flags != flags || entry->cflags != cflags ||
        tb->pc != pc || tb->cs_base != cs_base || tb->flags != flags) {
        return NULL;
    }

    tb_cflags = lata_fam_tb_cflags(tb);
    if (tb_cflags != cflags || (tb->cflags & CF_INVALID)) {
        return NULL;
    }
    return tb->tc.ptr ? tb : NULL;
}

/* gpr同时为src和dst, 使用alloc_gpr_src,并且需要store回去 */
IR2_OPND alloc_gpr_src(int i) {
    if(i==31){
        return ir2_opnd_new(IR2_OPND_GPR, la_zero);
    }
    if (arm_la_map[i] >= 0) {
        return ir2_opnd_new(IR2_OPND_GPR, arm_la_map[i]);
    } else {
        IR2_OPND t = ra_alloc_itemp();
        la_ld_d(t, env_ir2_opnd, env_offset_gpr(i));
        return t;
    }
}

IR2_OPND alloc_gpr_src_sp(int i) {
    if (arm_la_map[i] >= 0) {
        return ir2_opnd_new(IR2_OPND_GPR, arm_la_map[i]);
    } else {
        IR2_OPND t = ra_alloc_itemp();
        la_ld_d(t, env_ir2_opnd, env_offset_gpr(i));
        return t;
    }
}

IR2_OPND alloc_gpr_dst(int i) {
    if(i==31){
        return ir2_opnd_new(IR2_OPND_GPR, la_zero);
    }
    if (arm_la_map[i] >= 0) {
        return ir2_opnd_new(IR2_OPND_GPR, arm_la_map[i]);
    } else {
        return ra_alloc_itemp();
    }
}

IR2_OPND alloc_gpr_dst_sp(int i) {
    if (arm_la_map[i] >= 0) {
        return ir2_opnd_new(IR2_OPND_GPR, arm_la_map[i]);
    } else {
        return ra_alloc_itemp();
    }
}

/* la_zero作为目的寄存器不需要写回 */
void store_gpr_dst(int i, IR2_OPND opnd) {
    if (arm_la_map[i] < 0 && opnd.val != 0) {
        la_st_d(opnd, env_ir2_opnd, env_offset_gpr(i));
    }   
}

/* la_zero写回 */
void store_gpr_zero(int i) {
    if (arm_la_map[i] < 0) {
        la_st_d(zero_ir2_opnd, env_ir2_opnd, env_offset_gpr(i));
    }else{
        IR2_OPND reg_d = alloc_gpr_dst(i);
        la_ori(reg_d, zero_ir2_opnd, 0);
        free_alloc_gpr(reg_d);
    }   
}

/* la_zero不会被映射，但也不是临时寄存器 */
void free_alloc_gpr(IR2_OPND opnd) {
    if (arm_la_reverse_map[opnd.val] == -1 && opnd.val != 0) {
        ra_free_temp(opnd);
    }
}

// fpr
IR2_OPND alloc_fpr_src(int i) {
    if (arm_la_fmap[i] >= 0) {
        return ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[i]);
    } else {
        IR2_OPND t = ra_alloc_ftemp();
        // IR2_OPND offset = ra_alloc_itemp();

        // li_d(offset, env_offset_fpr(i));
        // la_vldx(t, env_ir2_opnd, offset);
        // int offset = env_offset_fpr(i);
        // assert(offset >= -(1 << 11) && offset <= (1 << 11) - 1 );
        la_vld(t, env_ir2_opnd, env_offset_fpr(i));

        // ra_free_temp(offset);
        return t;
    }
}

IR2_OPND alloc_fpr_dst(int i) {
    if (arm_la_fmap[i] >= 0) {
        return ir2_opnd_new(IR2_OPND_FPR, arm_la_fmap[i]);
    } else {
        return ra_alloc_ftemp();
    }
}

void store_fpr_dst(int i, IR2_OPND opnd) {
    if (arm_la_fmap[i] < 0) {
        // int offset = env_offset_fpr(i);
        // assert(offset >= -(1 << 11) && offset <= (1 << 11) - 1 );
        la_vst(opnd, env_ir2_opnd, env_offset_fpr(i));
        // IR2_OPND offset = ra_alloc_itemp();

        // li_d(offset, env_offset_fpr(i));
        // la_vstx(opnd, env_ir2_opnd, offset);

        // ra_free_temp(offset);
    }
}

void free_alloc_fpr(IR2_OPND opnd) {
    if (arm_la_reverse_fmap[opnd.val] == -1) {
        ra_free_temp(opnd);
    }
}
