#include "qemu/osdep.h"

#include "exec/log.h"
#include "target/arm/lata/include/ir2-peephole.h"
#include "target/arm/lata/include/lata.h"
#include "target/arm/lata/include/lata-options.h"
#include "target/arm/lata/include/reg-map.h"

typedef enum LataPeepholeAction {
    LATA_PH_KEEP,
    LATA_PH_REMOVE_HIGH_CLEAR,
    LATA_PH_REMOVE_ADDR_WRAP,
    LATA_PH_REMOVE_NOOP,
    LATA_PH_REWRITE_MOVE_CHAIN,
    LATA_PH_COMBINE_ADDI,
    LATA_PH_WINDOW_FOLD,
} LataPeepholeAction;

typedef enum LataIROpAccess {
    LATA_IR2_ACCESS_NONE,
    LATA_IR2_ACCESS_READ,
    LATA_IR2_ACCESS_WRITE,
    LATA_IR2_ACCESS_READWRITE,
} LataIROpAccess;

typedef enum LataPeepholePassResult {
    LATA_PASS_NO_CHANGE,
    LATA_PASS_RESCAN_CURRENT,
    LATA_PASS_CONTINUE_NEXT,
} LataPeepholePassResult;

typedef struct LataIR2RegAccess {
    uint32_t gpr_use;
    uint32_t gpr_def;
    uint32_t fpr_use;
    uint32_t fpr_def;
    bool may_have_side_effects;
    bool control_boundary;
    bool memory_boundary;
    bool unknown_boundary;
} LataIR2RegAccess;

typedef struct LataIR2OpClass {
    bool is_control;
    bool is_memory;
    bool is_simple_gpr_alu;
    bool is_gpr_to_fpr;
    bool is_fpr_to_gpr;
    bool is_load;
    bool is_store;
} LataIR2OpClass;
/*
 * TB assembly may run concurrently for different guest threads.  These
 * scratch arrays describe the IR2 stream currently being optimized, so they
 * must not be shared between threads.
 */
static __thread LataIR2PeepholeStats peephole_stats;
static __thread uint32_t *protected_raw_branch_gen;
static __thread int protected_raw_branch_gen_len;
static __thread uint32_t protected_raw_branch_gen_current;
static __thread int *raw_branch_old_id_to_index;
static __thread int *raw_branch_old_index_to_id;
static __thread int *raw_branch_entry_target;
static __thread int raw_branch_entry_count;
static __thread int raw_branch_old_count;
static __thread int raw_branch_scratch_cap;
static __thread bool raw_branch_protection_ready;
static __thread int *reloc_new_id_to_index;
static __thread int reloc_new_id_to_index_cap;

/*
 * Every peephole pass asks for the same per-instruction register access facts.
 * Cache them by IR2 id for the duration of one peephole run; a generation
 * counter avoids clearing the cache between translation blocks, and the cache
 * is invalidated whenever a pass rewrites an instruction's register operands.
 */
static __thread LataIR2RegAccess *access_cache;
static __thread uint32_t *access_cache_gen;
static __thread int access_cache_len;
static __thread uint32_t access_cache_current_gen;

/*
 * Boundary classification depends only on the IR2 opcode, so precompute it
 * once.  This lets the passes answer the very common "is this a window
 * boundary / control boundary?" question with a table lookup instead of
 * recomputing per-instruction access facts.
 */
#define LATA_OPB_CONTROL      (1u << 0)
#define LATA_OPB_MEMORY       (1u << 1)
#define LATA_OPB_SIDE_EFFECT  (1u << 2)
#define LATA_OPB_UNKNOWN      (1u << 3)
#define LATA_OPB_WINDOW       (LATA_OPB_CONTROL | LATA_OPB_MEMORY | \
                               LATA_OPB_SIDE_EFFECT | LATA_OPB_UNKNOWN)

static uint8_t opcode_boundary_flags[LISA_ENDING + 1];
/*
 * Operand position holding the PC-relative target for every branch opcode,
 * or -1 for instructions that are not PC-relative branches.  Branch tests run
 * for every IR2 instruction during each peephole run, so answer them with a
 * table lookup instead of a chain of opcode predicates.
 */
static int8_t pc_branch_operand_index[LISA_ENDING + 1];
static gsize opcode_boundary_once;

static void opcode_boundary_init(void);

static void access_cache_begin(int max_id)
{
    opcode_boundary_init();
    if (access_cache_len < max_id) {
        int old_len = access_cache_len;

        access_cache = g_renew(LataIR2RegAccess, access_cache, max_id);
        access_cache_gen = g_renew(uint32_t, access_cache_gen, max_id);
        memset(access_cache_gen + old_len, 0,
               sizeof(*access_cache_gen) * (max_id - old_len));
        access_cache_len = max_id;
    }
    access_cache_current_gen++;
    if (access_cache_current_gen == 0) {
        if (access_cache_len) {
            memset(access_cache_gen, 0,
                   sizeof(*access_cache_gen) * access_cache_len);
        }
        access_cache_current_gen = 1;
    }
}

/* Hot-path copies of ir2_next()/ir2_prev() so the pass loops can inline them. */
static inline IR2_INST *peephole_next(const IR2_INST *ir2)
{
    if (ir2->_next == -1) {
        return NULL;
    }
    return lsenv->tr_data->ir2_inst_array + ir2->_next;
}

static inline IR2_INST *peephole_prev(const IR2_INST *ir2)
{
    if (ir2->_prev == -1) {
        return NULL;
    }
    return lsenv->tr_data->ir2_inst_array + ir2->_prev;
}

static bool ir2_is_zero_gpr(const IR2_OPND *opnd)
{
    return ir2_opnd_is_ireg(opnd) && ir2_opnd_base_reg_num(opnd) == la_zero;
}

static bool ir2_is_same_ireg(const IR2_OPND *a, const IR2_OPND *b)
{
    return ir2_opnd_is_ireg(a) && ir2_opnd_is_ireg(b) && ir2_opnd_cmp(a, b);
}

static bool ir2_imm_is(const IR2_INST *ir2, int opnd, int imm)
{
    return opnd < ir2->op_count && ir2_opnd_is_imm(&ir2->_opnd[opnd]) &&
           ir2_opnd_imm(&ir2->_opnd[opnd]) == imm;
}

static bool si12_fits(int64_t value)
{
    return value >= -2048 && value <= 2047;
}

static bool ir2_is_meta(const IR2_INST *ir2)
{
    return ir2_opcode(ir2) == LISA_LABEL || ir2_opcode(ir2) == LISA_X86_INST;
}

static bool ir2_opcode_is_control(IR2_OPCODE opcode)
{
    return ir2_opcode_is_branch(opcode) || ir2_opcode_is_f_branch(opcode) ||
           opcode == LISA_JIRL || opcode == LISA_BL ||
           opcode == LISA_JISCR0 || opcode == LISA_JISCR1;
}

static inline IR2_OPND *pc_relative_branch_opnd(IR2_INST *ir2)
{
    int opnd = pc_branch_operand_index[(uint16_t)ir2->_opcode];

    return opnd < 0 ? NULL : &ir2->_opnd[opnd];
}

static bool ir2_opcode_is_barrier(IR2_OPCODE opcode)
{
    switch (opcode) {
    case LISA_BREAK:
    case LISA_DBGCALL:
    case LISA_SYSCALL:
    case LISA_HYPCALL:
    case LISA_DBAR:
    case LISA_IBAR:
    case LISA_LL_W:
    case LISA_LL_D:
    case LISA_SC_W:
    case LISA_SC_D:
    case LISA_SC_Q:
        return true;
    default:
        return false;
    }
}

static bool ir2_opcode_is_implicit_state(IR2_OPCODE opcode)
{
    switch (opcode) {
    case LISA_GR2SCR:
    case LISA_SCR2GR:
    case LISA_RDTIMEL_W:
    case LISA_RDTIMEH_W:
    case LISA_RDTIME_D:
    case LISA_CPUCFG:
    case LISA_ARMMFFLAG:
    case LISA_ARMMTFLAG:
    case LISA_MOVGR2FCSR:
    case LISA_MOVFCSR2GR:
    case LISA_MOVFR2CF:
    case LISA_MOVCF2FR:
    case LISA_MOVGR2CF:
    case LISA_MOVCF2GR:
    case LISA_FCMP_COND_S:
    case LISA_FCMP_COND_D:
    case LISA_VFCMP_COND_S:
    case LISA_VFCMP_COND_D:
    case LISA_XVFCMP_COND_S:
    case LISA_XVFCMP_COND_D:
        return true;
    default:
        return false;
    }
}

static bool ir2_opcode_is_gpr_to_fpr(IR2_OPCODE opcode)
{
    return opcode == LISA_MOVGR2FR_W || opcode == LISA_MOVGR2FR_D ||
           opcode == LISA_MOVGR2FRH_W ||
           (opcode >= LISA_VINSGR2VR_B && opcode <= LISA_VINSGR2VR_D) ||
           (opcode >= LISA_XVINSGR2VR_W && opcode <= LISA_XVINSGR2VR_D);
}

static bool ir2_opcode_is_fpr_to_gpr(IR2_OPCODE opcode)
{
    return opcode == LISA_MOVFR2GR_S || opcode == LISA_MOVFR2GR_D ||
           opcode == LISA_MOVFRH2GR_S ||
           (opcode >= LISA_VPICKVE2GR_B && opcode <= LISA_VPICKVE2GR_DU) ||
           (opcode >= LISA_XVPICKVE2GR_W && opcode <= LISA_XVPICKVE2GR_DU);
}

static bool ir2_opcode_is_simple_gpr_alu(IR2_OPCODE opcode)
{
    switch (opcode) {
    case LISA_CLO_W:
    case LISA_CLZ_W:
    case LISA_CTO_W:
    case LISA_CTZ_W:
    case LISA_CLO_D:
    case LISA_CLZ_D:
    case LISA_CTO_D:
    case LISA_CTZ_D:
    case LISA_REVB_2H:
    case LISA_REVB_4H:
    case LISA_REVB_2W:
    case LISA_REVB_D:
    case LISA_REVH_2W:
    case LISA_REVH_D:
    case LISA_BITREV_4B:
    case LISA_BITREV_8B:
    case LISA_BITREV_W:
    case LISA_BITREV_D:
    case LISA_EXT_W_H:
    case LISA_EXT_W_B:
    case LISA_ALSL_W:
    case LISA_ALSL_WU:
    case LISA_BYTEPICK_W:
    case LISA_BYTEPICK_D:
    case LISA_ADD_W:
    case LISA_ADD_D:
    case LISA_SUB_W:
    case LISA_SUB_D:
    case LISA_SLT:
    case LISA_SLTU:
    case LISA_MASKEQZ:
    case LISA_MASKNEZ:
    case LISA_NOR:
    case LISA_AND:
    case LISA_OR:
    case LISA_XOR:
    case LISA_ORN:
    case LISA_ANDN:
    case LISA_SLL_W:
    case LISA_SRL_W:
    case LISA_SRA_W:
    case LISA_SLL_D:
    case LISA_SRL_D:
    case LISA_SRA_D:
    case LISA_ROTR_B:
    case LISA_ROTR_H:
    case LISA_ROTR_W:
    case LISA_ROTR_D:
    case LISA_MUL_W:
    case LISA_MULH_W:
    case LISA_MULH_WU:
    case LISA_MUL_D:
    case LISA_MULH_D:
    case LISA_MULH_DU:
    case LISA_MULW_D_W:
    case LISA_MULW_D_WU:
    case LISA_DIV_W:
    case LISA_MOD_W:
    case LISA_DIV_WU:
    case LISA_MOD_WU:
    case LISA_DIV_D:
    case LISA_MOD_D:
    case LISA_DIV_DU:
    case LISA_MOD_DU:
    case LISA_CRC_W_B_W:
    case LISA_CRC_W_H_W:
    case LISA_CRC_W_W_W:
    case LISA_CRC_W_D_W:
    case LISA_CRCC_W_B_W:
    case LISA_CRCC_W_H_W:
    case LISA_CRCC_W_W_W:
    case LISA_CRCC_W_D_W:
    case LISA_ALSL_D:
    case LISA_BSTRINS_W:
    case LISA_BSTRPICK_W:
    case LISA_BSTRINS_D:
    case LISA_BSTRPICK_D:
    case LISA_SLTI:
    case LISA_SLTUI:
    case LISA_ADDI_W:
    case LISA_ADDI_D:
    case LISA_LU52I_D:
    case LISA_ANDI:
    case LISA_ORI:
    case LISA_XORI:
    case LISA_ADDU16I_D:
    case LISA_LU12I_W:
    case LISA_LU32I_D:
        return true;
    default:
        return false;
    }
}

static void opcode_boundary_init(void)
{
    if (!g_once_init_enter(&opcode_boundary_once)) {
        return;
    }

    for (int i = 0; i <= LISA_ENDING; i++) {
        IR2_OPCODE opcode = (IR2_OPCODE)i;
        bool is_load = la_ir2_opcode_is_load(opcode);
        bool is_store = la_ir2_opcode_is_store(opcode);
        int branch_opnd = -1;

        if (opcode == LISA_B || opcode == LISA_BL) {
            branch_opnd = 0;
        } else if (ir2_opcode_is_branch_with_2opnds(opcode) ||
                   ir2_opcode_is_f_branch(opcode)) {
            branch_opnd = 1;
        } else if (ir2_opcode_is_branch_with_3opnds(opcode)) {
            branch_opnd = 2;
        }
        pc_branch_operand_index[i] = branch_opnd;
        bool memory = is_load || is_store ||
                      (opcode >= LISA_LDX_B && opcode <= LISA_XVSTX) ||
                      (opcode >= LISA_AMSWAP_W && opcode <= LISA_AMMIN_DB_DU) ||
                      (opcode >= LISA_FLDGT_S && opcode <= LISA_STLE_D);
        bool control = opcode == LISA_LABEL || opcode == LISA_X86_INST ||
                       ir2_opcode_is_control(opcode);
        bool side_effect = control || memory ||
                           ir2_opcode_is_barrier(opcode) ||
                           ir2_opcode_is_implicit_state(opcode);
        bool unknown = !ir2_opcode_is_simple_gpr_alu(opcode) &&
                       !side_effect && opcode < LISA_FADD_S;
        uint8_t flags = 0;

        if (control) {
            flags |= LATA_OPB_CONTROL;
        }
        if (memory) {
            flags |= LATA_OPB_MEMORY;
        }
        if (side_effect) {
            flags |= LATA_OPB_SIDE_EFFECT;
        }
        if (unknown) {
            flags |= LATA_OPB_UNKNOWN;
        }
        if (control || memory || side_effect || unknown) {
            flags |= LATA_OPB_WINDOW;
        }
        opcode_boundary_flags[i] = flags;
    }

    g_once_init_leave(&opcode_boundary_once, 1);
}

static void ir2_classify_opcode(IR2_OPCODE opcode, LataIR2OpClass *cls)
{
    cls->is_load = la_ir2_opcode_is_load(opcode);
    cls->is_store = la_ir2_opcode_is_store(opcode);
    cls->is_memory = cls->is_load || cls->is_store ||
                     (opcode >= LISA_LDX_B && opcode <= LISA_XVSTX) ||
                     (opcode >= LISA_AMSWAP_W && opcode <= LISA_AMMIN_DB_DU) ||
                     (opcode >= LISA_FLDGT_S && opcode <= LISA_STLE_D);
    cls->is_control = ir2_opcode_is_control(opcode);
    cls->is_simple_gpr_alu = ir2_opcode_is_simple_gpr_alu(opcode);
    cls->is_gpr_to_fpr = ir2_opcode_is_gpr_to_fpr(opcode);
    cls->is_fpr_to_gpr = ir2_opcode_is_fpr_to_gpr(opcode);
}

static LataIROpAccess gpr_op_access(IR2_OPCODE opcode, int opnd,
                                    const LataIR2OpClass *cls)
{
    if (opcode == LISA_BSTRINS_W || opcode == LISA_BSTRINS_D) {
        if (opnd == 0) {
            return LATA_IR2_ACCESS_READWRITE;
        }
        return opnd == 1 ? LATA_IR2_ACCESS_READ : LATA_IR2_ACCESS_NONE;
    }

    switch (opcode) {
    case LISA_LU12I_W:
    case LISA_PCADDI:
    case LISA_PCALAU12I:
    case LISA_PCADDU12I:
    case LISA_PCADDU18I:
    case LISA_MOVFCSR2GR:
        return opnd == 0 ? LATA_IR2_ACCESS_WRITE : LATA_IR2_ACCESS_NONE;
    case LISA_LU32I_D:
        return opnd == 0 ? LATA_IR2_ACCESS_READWRITE : LATA_IR2_ACCESS_NONE;
    case LISA_MOVGR2FCSR:
    case LISA_ARMMTFLAG:
        return opnd == 0 ? LATA_IR2_ACCESS_READ : LATA_IR2_ACCESS_NONE;
    default:
        break;
    }

    if (cls->is_gpr_to_fpr) {
        return opnd == 1 ? LATA_IR2_ACCESS_READ : LATA_IR2_ACCESS_NONE;
    }
    if (cls->is_fpr_to_gpr) {
        return opnd == 0 ? LATA_IR2_ACCESS_WRITE : LATA_IR2_ACCESS_NONE;
    }

    if (cls->is_control) {
        if (opcode == LISA_JIRL) {
            return opnd == 0 ? LATA_IR2_ACCESS_WRITE :
                   opnd == 1 ? LATA_IR2_ACCESS_READ : LATA_IR2_ACCESS_NONE;
        }
        return LATA_IR2_ACCESS_READ;
    }

    if (cls->is_memory) {
        return opnd == 0 && cls->is_load ?
               LATA_IR2_ACCESS_WRITE : LATA_IR2_ACCESS_READ;
    }

    if (cls->is_simple_gpr_alu) {
        return opnd == 0 ? LATA_IR2_ACCESS_WRITE : LATA_IR2_ACCESS_READ;
    }

    return LATA_IR2_ACCESS_READWRITE;
}

static LataIROpAccess fpr_op_access(IR2_OPCODE opcode, int opnd,
                                    const LataIR2OpClass *cls)
{
    if (cls->is_store || opcode == LISA_MOVFR2GR_S ||
        opcode == LISA_MOVFR2GR_D || opcode == LISA_MOVFRH2GR_S ||
        opcode == LISA_MOVFR2CF) {
        return LATA_IR2_ACCESS_READ;
    }
    if (cls->is_load || opcode == LISA_MOVGR2FR_W ||
        opcode == LISA_MOVGR2FR_D || opcode == LISA_MOVGR2FRH_W ||
        opcode == LISA_MOVCF2FR) {
        return opnd == 0 ? LATA_IR2_ACCESS_WRITE : LATA_IR2_ACCESS_READ;
    }
    if (cls->is_gpr_to_fpr) {
        return opnd == 0 ? LATA_IR2_ACCESS_READWRITE : LATA_IR2_ACCESS_NONE;
    }
    if (cls->is_fpr_to_gpr) {
        return opnd == 1 ? LATA_IR2_ACCESS_READ : LATA_IR2_ACCESS_NONE;
    }
    return opnd == 0 ? LATA_IR2_ACCESS_WRITE : LATA_IR2_ACCESS_READ;
}

static inline void access_mark_gpr(LataIR2RegAccess *access, int reg,
                            LataIROpAccess kind)
{
    if (reg < 0 || reg >= 32 || reg == la_zero) {
        return;
    }
    if (kind == LATA_IR2_ACCESS_READ || kind == LATA_IR2_ACCESS_READWRITE) {
        access->gpr_use |= 1u << reg;
    }
    if (kind == LATA_IR2_ACCESS_WRITE || kind == LATA_IR2_ACCESS_READWRITE) {
        access->gpr_def |= 1u << reg;
    }
}

static inline void access_mark_fpr(LataIR2RegAccess *access, int reg,
                            LataIROpAccess kind)
{
    if (reg < 0 || reg >= 32) {
        return;
    }
    if (kind == LATA_IR2_ACCESS_READ || kind == LATA_IR2_ACCESS_READWRITE) {
        access->fpr_use |= 1u << reg;
    }
    if (kind == LATA_IR2_ACCESS_WRITE || kind == LATA_IR2_ACCESS_READWRITE) {
        access->fpr_def |= 1u << reg;
    }
}

static LataIR2RegAccess ir2_compute_access(IR2_INST *ir2)
{
    LataIR2RegAccess access = { 0 };
    IR2_OPCODE opcode = ir2_opcode(ir2);
    LataIR2OpClass cls;

    uint8_t flags = opcode_boundary_flags[(uint16_t)opcode];

    ir2_classify_opcode(opcode, &cls);

    access.control_boundary = flags & LATA_OPB_CONTROL;
    access.memory_boundary = flags & LATA_OPB_MEMORY;
    access.may_have_side_effects = flags & LATA_OPB_SIDE_EFFECT;
    access.unknown_boundary = flags & LATA_OPB_UNKNOWN;

    for (int i = 0; i < ir2->op_count; i++) {
        IR2_OPND *opnd = &ir2->_opnd[i];

        if (opnd->_type == IR2_OPND_GPR) {
            access_mark_gpr(&access, opnd->_reg_num,
                            gpr_op_access(opcode, i, &cls));
        } else if (opnd->_type == IR2_OPND_FPR) {
            access_mark_fpr(&access, opnd->_reg_num,
                            fpr_op_access(opcode, i, &cls));
        }
    }
    return access;
}

static inline const LataIR2RegAccess *ir2_get_access(IR2_INST *ir2)
{
    static __thread LataIR2RegAccess uncached;
    int id = ir2_get_id(ir2);

    if (id >= 0 && id < access_cache_len) {
        if (access_cache_gen[id] == access_cache_current_gen) {
            return &access_cache[id];
        }
        access_cache[id] = ir2_compute_access(ir2);
        access_cache_gen[id] = access_cache_current_gen;
        return &access_cache[id];
    }
    uncached = ir2_compute_access(ir2);
    return &uncached;
}

static void ir2_invalidate_access(IR2_INST *ir2)
{
    int id = ir2_get_id(ir2);

    if (id >= 0 && id < access_cache_len) {
        access_cache_gen[id] = 0;
    }
}

static inline bool ir2_is_window_boundary(const IR2_INST *ir2)
{
    return opcode_boundary_flags[(uint16_t)ir2->_opcode] & LATA_OPB_WINDOW;
}

static inline bool ir2_is_control_boundary(const IR2_INST *ir2)
{
    return opcode_boundary_flags[(uint16_t)ir2->_opcode] & LATA_OPB_CONTROL;
}

static int build_assembled_index_map(int *id_to_index, int *index_to_id,
                                     int max_id)
{
    int index = 0;

    for (IR2_INST *it = lsenv->tr_data->first_ir2; it; it = peephole_next(it)) {
        int id = ir2_get_id(it);

        if (id >= 0 && id < max_id && !ir2_is_meta(it)) {
            id_to_index[id] = index;
            if (index_to_id) {
                index_to_id[index] = id;
            }
            index++;
        }
    }
    return index;
}

static void ensure_raw_branch_scratch(int max_id)
{
    if (raw_branch_scratch_cap < max_id) {
        int old_cap = raw_branch_scratch_cap;

        protected_raw_branch_gen =
            g_renew(uint32_t, protected_raw_branch_gen, max_id);
        raw_branch_old_id_to_index =
            g_renew(int, raw_branch_old_id_to_index, max_id);
        raw_branch_old_index_to_id =
            g_renew(int, raw_branch_old_index_to_id, max_id);
        raw_branch_entry_target = g_renew(int, raw_branch_entry_target, max_id);
        memset(protected_raw_branch_gen + old_cap, 0,
               sizeof(*protected_raw_branch_gen) * (max_id - old_cap));
        raw_branch_scratch_cap = max_id;
    }
}

static void ensure_raw_branch_protection(void)
{
    TRANSLATION_DATA *t = lsenv->tr_data;
    int max_id = t->ir2_inst_num_current;
    int index = 0;

    if (raw_branch_protection_ready) {
        return;
    }
    raw_branch_protection_ready = true;

    ensure_raw_branch_scratch(max_id);
    protected_raw_branch_gen_len = max_id;
    if (++protected_raw_branch_gen_current == 0) {
        if (protected_raw_branch_gen_len) {
            memset(protected_raw_branch_gen, 0,
                   sizeof(*protected_raw_branch_gen) *
                   protected_raw_branch_gen_len);
        }
        protected_raw_branch_gen_current = 1;
    }
    raw_branch_entry_count = 0;

    /*
     * Build the assembled-index map and record every raw (immediate-offset)
     * branch in one walk.  Earlier versions walked the whole IR2 list a second
     * time just to classify branches, and cleared the scratch arrays to -1
     * across the whole id range on every TB.  Neither is needed: every branch
     * instruction is still live here, and every id read during relocation is
     * either a live instruction or a protected (never removed) branch target.
     */
    for (IR2_INST *it = t->first_ir2; it; it = peephole_next(it)) {
        int id = ir2_get_id(it);
        IR2_OPND *opnd;

        if (id < 0 || id >= max_id || ir2_is_meta(it)) {
            continue;
        }

        raw_branch_old_id_to_index[id] = index;
        raw_branch_old_index_to_id[index] = id;

        opnd = pc_relative_branch_opnd(it);
        if (opnd && ir2_opnd_is_imm(opnd)) {
            raw_branch_entry_target[raw_branch_entry_count] =
                index + ir2_opnd_imm(opnd);
            raw_branch_entry_count++;
        }
        index++;
    }
    raw_branch_old_count = index;

    for (int i = 0; i < raw_branch_entry_count; i++) {
        int target_index = raw_branch_entry_target[i];

        if (target_index >= 0 && target_index < raw_branch_old_count) {
            int target_id = raw_branch_old_index_to_id[target_index];

            if (target_id >= 0 && target_id < max_id) {
                protected_raw_branch_gen[target_id] =
                    protected_raw_branch_gen_current;
            }
        }
    }
}

static inline bool ir2_is_protected_raw_branch_target(IR2_INST *ir2)
{
    int id;

    ensure_raw_branch_protection();
    id = ir2_get_id(ir2);

    return id >= 0 && id < protected_raw_branch_gen_len &&
           protected_raw_branch_gen &&
           protected_raw_branch_gen[id] == protected_raw_branch_gen_current;
}

static void relocate_raw_branches(void)
{
    TRANSLATION_DATA *t = lsenv->tr_data;
    int max_id = t->ir2_inst_num_current;
    int *new_id_to_index;

    if (reloc_new_id_to_index_cap < max_id) {
        reloc_new_id_to_index =
            g_renew(int, reloc_new_id_to_index, max_id);
        reloc_new_id_to_index_cap = max_id;
    }
    new_id_to_index = reloc_new_id_to_index;

    /* Every live id and every protected branch target is filled in here. */
    build_assembled_index_map(new_id_to_index, NULL, max_id);

    for (IR2_INST *it = t->first_ir2; it; it = peephole_next(it)) {
        IR2_OPND *opnd = pc_relative_branch_opnd(it);
        int id = ir2_get_id(it);

        if (!opnd || !ir2_opnd_is_imm(opnd) || id < 0 || id >= max_id ||
            raw_branch_old_id_to_index[id] < 0 || new_id_to_index[id] < 0) {
            continue;
        }

        int old_target_index = raw_branch_old_id_to_index[id] +
                               ir2_opnd_imm(opnd);
        int new_target_index = old_target_index;

        if (old_target_index >= 0 && old_target_index < raw_branch_old_count) {
            int target_id = raw_branch_old_index_to_id[old_target_index];

            if (target_id < 0 || target_id >= max_id ||
                new_id_to_index[target_id] < 0) {
                continue;
            }
            new_target_index = new_id_to_index[target_id];
        }

        opnd->_imm32 = new_target_index - new_id_to_index[id];
    }
}

static void clear_raw_branch_protection(void)
{
    /*
     * The scratch arrays are reused across translation blocks; only the
     * lengths need to be reset so the next run starts from a clean state.
     */
    protected_raw_branch_gen_len = 0;
    raw_branch_entry_count = 0;
    raw_branch_old_count = 0;
    raw_branch_protection_ready = false;
}

static void stats_record(LataPeepholeAction action)
{
    switch (action) {
    case LATA_PH_REMOVE_HIGH_CLEAR:
        peephole_stats.removed_total++;
        peephole_stats.removed_high_clear++;
        break;
    case LATA_PH_REMOVE_ADDR_WRAP:
        peephole_stats.removed_total++;
        peephole_stats.removed_addr_wrap++;
        break;
    case LATA_PH_REMOVE_NOOP:
        peephole_stats.removed_total++;
        peephole_stats.removed_noop++;
        break;
    case LATA_PH_REWRITE_MOVE_CHAIN:
        peephole_stats.rewritten_total++;
        peephole_stats.rewritten_move_chain++;
        break;
    case LATA_PH_COMBINE_ADDI:
        peephole_stats.removed_total++;
        peephole_stats.rewritten_total++;
        peephole_stats.combined_addi++;
        break;
    case LATA_PH_WINDOW_FOLD:
        peephole_stats.folded_window++;
        break;
    case LATA_PH_KEEP:
        break;
    }
}

static void remove_ir2(IR2_INST *ir2, LataPeepholeAction action)
{
    lsassert(!ir2_is_protected_raw_branch_target(ir2));
    ir2_remove(ir2);
    stats_record(action);
}

static bool is_self_bstrpick(IR2_INST *ir2, int msb, int lsb)
{
    if (ir2_opcode(ir2) != LISA_BSTRPICK_D &&
        ir2_opcode(ir2) != LISA_BSTRPICK_W) {
        return false;
    }
    if (!ir2_is_same_ireg(&ir2->_opnd[0], &ir2->_opnd[1])) {
        return false;
    }
    return ir2_imm_is(ir2, 2, msb) && ir2_imm_is(ir2, 3, lsb);
}

static bool is_self_high_clear(IR2_INST *ir2)
{
    return is_self_bstrpick(ir2, 31, 0);
}

static bool is_self_addr_wrap(IR2_INST *ir2)
{
    return ir2_opcode(ir2) == LISA_BSTRPICK_D && is_self_bstrpick(ir2, 47, 0);
}

static bool same_high_clear(IR2_INST *a, IR2_INST *b)
{
    return is_self_high_clear(a) && is_self_high_clear(b) &&
           ir2_opcode(a) == ir2_opcode(b) &&
           ir2_opnd_cmp(&a->_opnd[0], &b->_opnd[0]);
}

static bool same_addr_wrap(IR2_INST *a, IR2_INST *b)
{
    return is_self_addr_wrap(a) && is_self_addr_wrap(b) &&
           ir2_opnd_cmp(&a->_opnd[0], &b->_opnd[0]);
}

static bool is_self_addi_d(IR2_INST *ir2)
{
    return ir2_opcode(ir2) == LISA_ADDI_D &&
           ir2_is_same_ireg(&ir2->_opnd[0], &ir2->_opnd[1]);
}

static LataPeepholePassResult fold_window_candidate(IR2_INST *ir2,
                                                    IR2_INST *candidate)
{
    if (!same_high_clear(ir2, candidate) &&
        !same_addr_wrap(ir2, candidate) &&
        !(is_self_addi_d(ir2) && is_self_addi_d(candidate))) {
        return LATA_PASS_NO_CHANGE;
    }
    if (ir2_is_protected_raw_branch_target(candidate)) {
        return LATA_PASS_NO_CHANGE;
    }
    if (same_high_clear(ir2, candidate)) {
        remove_ir2(candidate, LATA_PH_REMOVE_HIGH_CLEAR);
        stats_record(LATA_PH_WINDOW_FOLD);
        return LATA_PASS_RESCAN_CURRENT;
    }
    if (same_addr_wrap(ir2, candidate)) {
        remove_ir2(candidate, LATA_PH_REMOVE_ADDR_WRAP);
        stats_record(LATA_PH_WINDOW_FOLD);
        return LATA_PASS_RESCAN_CURRENT;
    }
    if (is_self_addi_d(ir2) && is_self_addi_d(candidate) &&
        ir2_opnd_cmp(&ir2->_opnd[0], &candidate->_opnd[0])) {
        int64_t imm = (int64_t)ir2_opnd_imm(&ir2->_opnd[2]) +
                      ir2_opnd_imm(&candidate->_opnd[2]);

        if (si12_fits(imm)) {
            ir2->_opnd[2]._imm32 = imm;
            remove_ir2(candidate, LATA_PH_COMBINE_ADDI);
            stats_record(LATA_PH_WINDOW_FOLD);
            return LATA_PASS_RESCAN_CURRENT;
        }
    }
    return LATA_PASS_NO_CHANGE;
}

static LataPeepholePassResult pass_small_window(IR2_INST *ir2)
{
    IR2_INST *scan_end = ir2;
    IR2_OPCODE opcode = ir2_opcode(ir2);

    /*
     * Only self-masking BSTRPICKs and self-ADDI.D are candidates here.  Test
     * the opcode first so the common instruction pays a single comparison
     * instead of building a full register-access fact.
     */
    if (opcode != LISA_BSTRPICK_D && opcode != LISA_BSTRPICK_W &&
        opcode != LISA_ADDI_D) {
        return LATA_PASS_NO_CHANGE;
    }
    if (!(is_self_high_clear(ir2) || is_self_addr_wrap(ir2) ||
          is_self_addi_d(ir2)) ||
        ir2_is_window_boundary(ir2)) {
        return LATA_PASS_NO_CHANGE;
    }

    unsigned reg = ir2_opnd_base_reg_num(&ir2->_opnd[0]);
    if (reg >= 32 || reg == la_zero) {
        return LATA_PASS_NO_CHANGE;
    }
    for (int i = 0; i < 8 && scan_end; i++) {
        scan_end = peephole_next(scan_end);
    }

    for (IR2_INST *it = peephole_next(ir2), *last = NULL;
         it && last != it && scan_end != it;
         last = it, it = peephole_next(it)) {
        const LataIR2RegAccess *access;
        LataPeepholePassResult result;

        if (ir2_is_window_boundary(it)) {
            return LATA_PASS_NO_CHANGE;
        }

        result = fold_window_candidate(ir2, it);
        if (result != LATA_PASS_NO_CHANGE) {
            return result;
        }

        access = ir2_get_access(it);
        if ((access->gpr_use | access->gpr_def) & (1u << reg)) {
            return LATA_PASS_NO_CHANGE;
        }
    }
    return LATA_PASS_NO_CHANGE;
}

static LataPeepholePassResult pass_duplicate_bstrpick(IR2_INST *ir2)
{
    IR2_OPCODE opcode = ir2_opcode(ir2);
    IR2_INST *next;

    if (opcode != LISA_BSTRPICK_D && opcode != LISA_BSTRPICK_W) {
        return LATA_PASS_NO_CHANGE;
    }
    next = peephole_next(ir2);
    if (!next || ir2_is_window_boundary(ir2) || ir2_is_window_boundary(next)) {
        return LATA_PASS_NO_CHANGE;
    }
    if (same_high_clear(ir2, next)) {
        if (ir2_is_protected_raw_branch_target(next)) {
            return LATA_PASS_NO_CHANGE;
        }
        remove_ir2(next, LATA_PH_REMOVE_HIGH_CLEAR);
        return LATA_PASS_RESCAN_CURRENT;
    }
    if (same_addr_wrap(ir2, next)) {
        if (ir2_is_protected_raw_branch_target(next)) {
            return LATA_PASS_NO_CHANGE;
        }
        remove_ir2(next, LATA_PH_REMOVE_ADDR_WRAP);
        return LATA_PASS_RESCAN_CURRENT;
    }
    return LATA_PASS_NO_CHANGE;
}

static bool is_self_add_zero(IR2_INST *ir2)
{
    IR2_OPCODE opcode = ir2_opcode(ir2);

    if (opcode == LISA_ADDI_D &&
        ir2_is_same_ireg(&ir2->_opnd[0], &ir2->_opnd[1]) &&
        ir2_imm_is(ir2, 2, 0)) {
        return true;
    }
    if ((opcode == LISA_ADD_D || opcode == LISA_OR || opcode == LISA_XOR) &&
        ir2_is_same_ireg(&ir2->_opnd[0], &ir2->_opnd[1]) &&
        ir2_is_zero_gpr(&ir2->_opnd[2])) {
        return true;
    }
    if ((opcode == LISA_ADD_D || opcode == LISA_OR || opcode == LISA_XOR) &&
        ir2_is_same_ireg(&ir2->_opnd[0], &ir2->_opnd[2]) &&
        ir2_is_zero_gpr(&ir2->_opnd[1])) {
        return true;
    }
    return false;
}

static LataPeepholePassResult pass_remove_noop(IR2_INST *ir2)
{
    IR2_OPCODE opcode = ir2_opcode(ir2);
    IR2_INST *prev;
    IR2_INST *next;

    if (opcode != LISA_ADDI_D && opcode != LISA_ADD_D &&
        opcode != LISA_OR && opcode != LISA_XOR) {
        return LATA_PASS_NO_CHANGE;
    }
    prev = peephole_prev(ir2);
    next = peephole_next(ir2);

    if (ir2_is_window_boundary(ir2) ||
        (prev && ir2_is_control_boundary(prev)) ||
        (next && ir2_is_control_boundary(next))) {
        return LATA_PASS_NO_CHANGE;
    }
    if (is_self_add_zero(ir2) && !ir2_is_protected_raw_branch_target(ir2)) {
        remove_ir2(ir2, LATA_PH_REMOVE_NOOP);
        return LATA_PASS_CONTINUE_NEXT;
    }
    return LATA_PASS_NO_CHANGE;
}

static bool is_mov_gpr_zero(IR2_INST *ir2)
{
    return ir2_opcode(ir2) == LISA_OR &&
           ir2_opnd_is_ireg(&ir2->_opnd[0]) &&
           ((ir2_opnd_is_ireg(&ir2->_opnd[1]) &&
             ir2_is_zero_gpr(&ir2->_opnd[2])) ||
            (ir2_opnd_is_ireg(&ir2->_opnd[2]) &&
             ir2_is_zero_gpr(&ir2->_opnd[1])));
}

static IR2_OPND *mov_gpr_src(IR2_INST *ir2)
{
    if (ir2_is_zero_gpr(&ir2->_opnd[2])) {
        return &ir2->_opnd[1];
    }
    return &ir2->_opnd[2];
}

static LataPeepholePassResult pass_move_chain(IR2_INST *ir2)
{
    IR2_INST *next;

    if (ir2_opcode(ir2) != LISA_OR) {
        return LATA_PASS_NO_CHANGE;
    }
    next = peephole_next(ir2);
    if (!next || ir2_is_window_boundary(ir2) || ir2_is_window_boundary(next)) {
        return LATA_PASS_NO_CHANGE;
    }
    if (ir2_is_protected_raw_branch_target(next)) {
        return LATA_PASS_NO_CHANGE;
    }
    if (!is_mov_gpr_zero(ir2) || !is_mov_gpr_zero(next)) {
        return LATA_PASS_NO_CHANGE;
    }
    IR2_OPND *src = mov_gpr_src(ir2);
    IR2_OPND *next_src = mov_gpr_src(next);

    if (!ir2_opnd_cmp(next_src, &ir2->_opnd[0]) ||
        ir2_opnd_cmp(&next->_opnd[0], &ir2->_opnd[0]) ||
        ir2_opnd_cmp(next_src, src)) {
        return LATA_PASS_NO_CHANGE;
    }

    *next_src = *src;
    ir2_invalidate_access(next);
    stats_record(LATA_PH_REWRITE_MOVE_CHAIN);
    return LATA_PASS_RESCAN_CURRENT;
}

static LataPeepholePassResult pass_combine_addi(IR2_INST *ir2)
{
    IR2_INST *next;

    if (ir2_opcode(ir2) != LISA_ADDI_D) {
        return LATA_PASS_NO_CHANGE;
    }
    next = peephole_next(ir2);
    if (!next || ir2_opcode(next) != LISA_ADDI_D ||
        ir2_is_window_boundary(ir2) || ir2_is_window_boundary(next)) {
        return LATA_PASS_NO_CHANGE;
    }
    if (!ir2_is_same_ireg(&ir2->_opnd[0], &ir2->_opnd[1]) ||
        !ir2_is_same_ireg(&next->_opnd[0], &next->_opnd[1]) ||
        !ir2_opnd_cmp(&ir2->_opnd[0], &next->_opnd[0])) {
        return LATA_PASS_NO_CHANGE;
    }

    int64_t imm = (int64_t)ir2_opnd_imm(&ir2->_opnd[2]) +
                  ir2_opnd_imm(&next->_opnd[2]);
    if (!si12_fits(imm) || ir2_is_protected_raw_branch_target(next)) {
        return LATA_PASS_NO_CHANGE;
    }

    ir2->_opnd[2]._imm32 = imm;
    ir2_remove(next);
    stats_record(LATA_PH_COMBINE_ADDI);
    return LATA_PASS_RESCAN_CURRENT;
}

/*
 * The individual passes only match a few opcodes and only ever change the
 * current instruction or look forward.  Running them from one forward walk
 * therefore performs the same folds as the old seven full-list passes while
 * touching each instruction once.  Per-opcode dispatch keeps the expensive
 * register-access checks off instructions no pass can rewrite.
 */
static LataPeepholePassResult run_combined_pass(IR2_INST *ir2)
{
    LataPeepholePassResult result;

    peephole_stats.passes++;

    switch (ir2_opcode(ir2)) {
    case LISA_BSTRPICK_D:
    case LISA_BSTRPICK_W:
        result = pass_duplicate_bstrpick(ir2);
        if (result == LATA_PASS_NO_CHANGE) {
            result = pass_small_window(ir2);
        }
        return result;
    case LISA_ADDI_D:
        result = pass_remove_noop(ir2);
        if (result == LATA_PASS_NO_CHANGE) {
            result = pass_combine_addi(ir2);
        }
        if (result == LATA_PASS_NO_CHANGE) {
            result = pass_small_window(ir2);
        }
        return result;
    case LISA_ADD_D:
    case LISA_XOR:
        return pass_remove_noop(ir2);
    case LISA_OR:
        result = pass_remove_noop(ir2);
        if (result == LATA_PASS_NO_CHANGE) {
            result = pass_move_chain(ir2);
        }
        return result;
    default:
        return LATA_PASS_NO_CHANGE;
    }
}

void lata_ir2_peephole_run(void)
{
    IR2_INST *ir2;
    uint64_t removed_before = peephole_stats.removed_total;

    peephole_stats.runs++;

    access_cache_begin(lsenv->tr_data->ir2_inst_num_current);

    ir2 = lsenv->tr_data->first_ir2;
    while (ir2) {
        IR2_INST *next = peephole_next(ir2);
        LataPeepholePassResult result = run_combined_pass(ir2);

        if (result == LATA_PASS_RESCAN_CURRENT) {
            continue;
        }
        if (result == LATA_PASS_CONTINUE_NEXT) {
            /* The current instruction was removed, so use the successor that
             * was captured before the pass ran. */
            ir2 = next;
            continue;
        }
        ir2 = next;
    }
    /*
     * Relative branch operands are measured in assembled instruction indices.
     * Those indices only move when an instruction is actually removed, so the
     * relocation scan is a no-op for the common case where peephole found
     * nothing to fold away.
     */
    if (peephole_stats.removed_total != removed_before) {
        relocate_raw_branches();
    }
    clear_raw_branch_protection();
}

const LataIR2PeepholeStats *lata_ir2_peephole_get_stats(void)
{
    return &peephole_stats;
}

void lata_ir2_peephole_dump_stats(void)
{
    if (!option_lata_peephole_stats) {
        return;
    }

    qemu_log("[LATA] IR2 peephole runs=%" PRIu64
             " passes=%" PRIu64
             " removed=%" PRIu64
             " rewritten=%" PRIu64
             " high_clear=%" PRIu64
             " addr_wrap=%" PRIu64
             " noop=%" PRIu64
             " move_chain=%" PRIu64
             " addi=%" PRIu64
             " window=%" PRIu64 "\n",
             peephole_stats.runs,
             peephole_stats.passes,
             peephole_stats.removed_total,
             peephole_stats.rewritten_total,
             peephole_stats.removed_high_clear,
             peephole_stats.removed_addr_wrap,
             peephole_stats.removed_noop,
             peephole_stats.rewritten_move_chain,
             peephole_stats.combined_addi,
             peephole_stats.folded_window);
}
