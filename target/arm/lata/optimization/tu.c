#include "qemu/osdep.h"
#include "qemu/log.h"
#include "exec/tb-flush.h"
#include "target/arm/tcg/translate.h"
#include "target/arm/tcg/arm_ldst.h"
#include "accel/tcg/internal.h"
#include "lata.h"
#include "ir2.h"
#include "env.h"
#include "common.h"
#include "ir1.h"
#include "tcg/tcg.h"
#include "qemu/cacheflush.h"
#include "target/arm/lata/include/translate-a64.h"
#include "target/arm/lata/include/lata-debug.h"
#include "tu.h"
#include "disas/disas.h"

#ifdef CONFIG_LATA_TU
#ifdef CONFIG_SOFTMMU
#define assert_memory_lock()
#else
#define assert_memory_lock() tcg_debug_assert(have_mmap_lock())
#endif

static __thread TUControl tu_data_rel;
__thread TUControl *tu_data;
static __thread uint32_t search_buff_offset[MAX_TB_IN_TU];
static __thread DisasContext tu_ir1_list[MAX_TB_IN_TU * TCG_MAX_INSNS];

DisasContext *tu_get_ir1_list(uint32_t offset)
{
    lsassert(offset < MAX_TB_IN_TU * TCG_MAX_INSNS);
    return &tu_ir1_list[offset];
}

static inline void tu_trees_reset(void)
{
    /* Increment the refcount first so that destroy acts as a reset */
    g_tree_ref(tu_data->tree);
    g_tree_destroy(tu_data->tree);
}

TranslationBlock *tu_tree_lookup(target_ulong pc)
{
    TranslationBlock key = {.pc = pc};
    return (TranslationBlock *)g_tree_lookup(tu_data->tree, &key);
}

static gint gpc_cmp(gconstpointer ap, gconstpointer bp)
{
    const TranslationBlock *a = (TranslationBlock *)ap;
    const TranslationBlock *b = (TranslationBlock *)bp;

    return (a->pc < b->pc) ? -1 : (a->pc > b->pc);
}

static void tu_tree_insert(TranslationBlock *tb)
{
    g_tree_insert(tu_data->tree, tb, tb);
}

static inline void tu_trees_init(void)
{
    tu_data->tree = g_tree_new(gpc_cmp);
}

void tu_control_init(void)
{
    tu_data = &tu_data_rel;
    tu_data->ir1_num_in_tu = 0;
    tu_data->tb_num = 0;
    tu_data->curr_num = 0;
    tu_trees_init();

    return;
}

static inline void tu_push_back(TranslationBlock *tb)
{
    if (!tb) {
        return;
    }
    TranslationBlock** tb_list = tu_data->tb_list;
    uint32_t* tb_num_in_tu = &tu_data->tb_num;

    tb_list[(*tb_num_in_tu)++] = tb;
}

static inline const void *qm_tb_get_code_cache(void *tb)
{
    struct TranslationBlock *ptb = (struct TranslationBlock *)tb;
    return ptb->tc.ptr;
}

int translate_tb_in_tu(struct TranslationBlock *tb)
{
    tb->tc.ptr = tcg_splitwx_to_rx(tcg_ctx->code_gen_ptr);
    tcg_ctx->gen_tb = tb;
    return tr_translate_tb(tb);
}

static inline void tu_enough_space(CPUState *cpu)
{
    if (unlikely(tcg_ctx->code_gen_ptr + MAX_TU_SIZE >= tcg_ctx->code_gen_highwater)) {
        tb_flush(cpu);
        mmap_unlock();
        /* Make the execution loop process the flush as soon as possible.  */
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
    tcg_ctx->gen_insn_data = tcg_malloc(sizeof(uint64_t) * MAX_TB_IN_TU * TCG_MAX_INSNS * TARGET_INSN_START_WORDS);
}

void lata_tu_edge_reset(TranslationBlock *tb, int n)
{
    LataTUEdge *edge = &tb->tu_edges[n];

    edge->kind = LATA_TU_EDGE_NONE;
    edge->branch_kind = LATA_TU_BRANCH_NONE;
    edge->state = LATA_TU_EDGE_EMPTY;
    edge->fallback_reason = LATA_TU_FALLBACK_NONE;
    edge->guest_pc = 0;
    edge->target_tb = NULL;
    edge->branch_offset = LATA_TU_EDGE_OFFSET_INVALID;
    edge->unlink_stub_offset = TU_UNLINK_STUB_INVALID;
    edge->branch_island_offset = LATA_TU_EDGE_OFFSET_INVALID;
    edge->saved_insn = 0;
    edge->fallback_guest_pc = 0;
    edge->local_unlink_stub_offset = TU_UNLINK_STUB_INVALID;
}

void lata_tu_tb_reset_edges(TranslationBlock *tb)
{
    tb->tu_has_edges = false;
    lata_tu_edge_reset(tb, TU_TB_INDEX_NEXT);
    lata_tu_edge_reset(tb, TU_TB_INDEX_TARGET);
}

static void lata_tu_mark_tb_fallback(TranslationBlock *tb,
                                     LataTUFallbackReason reason)
{
    if (!tb || reason == LATA_TU_FALLBACK_NONE) {
        return;
    }
    tb->tu_fallback_reason = reason;
    lata_debug_note_tu_fallback(reason);
}

static void lata_tu_drop_edge(TranslationBlock *tb, int n,
                              LataTUFallbackReason reason)
{
    if (!tb) {
        return;
    }
    tb->next_tb[n] = NULL;
    tb->tu_edges[n].fallback_reason = reason;
    lata_tu_mark_tb_fallback(tb, reason);
}

static void lata_tu_drop_all_edges(TranslationBlock *tb,
                                   LataTUFallbackReason reason)
{
    lata_tu_drop_edge(tb, TU_TB_INDEX_NEXT, reason);
    lata_tu_drop_edge(tb, TU_TB_INDEX_TARGET, reason);
}

bool lata_tu_edge_active(TranslationBlock *tb, int n)
{
    return tb && tb->tu_edges[n].state != LATA_TU_EDGE_EMPTY;
}

static LataTUEdgeKind lata_tu_edge_kind_for_index(int n)
{
    return n == TU_TB_INDEX_NEXT ? LATA_TU_EDGE_NEXT : LATA_TU_EDGE_TARGET;
}

void lata_tu_edge_set_target(TranslationBlock *tb, int n,
                             TranslationBlock *target_tb)
{
    LataTUEdge *edge = &tb->tu_edges[n];

    edge->kind = lata_tu_edge_kind_for_index(n);
    edge->target_tb = target_tb;
    edge->guest_pc = target_tb ? target_tb->pc : 0;
    edge->fallback_reason = LATA_TU_FALLBACK_NONE;
}

static void lata_tu_edge_emit_common(TranslationBlock *tb, int n,
                                     uint32_t label_id,
                                     uint64_t fallback_guest_pc,
                                     LataTUBranchKind branch_kind)
{
    LataTUEdge *edge = &tb->tu_edges[n];
    LataTUEdgeState old_state = edge->state;

    edge->kind = lata_tu_edge_kind_for_index(n);
    edge->branch_kind = branch_kind;
    edge->state = LATA_TU_EDGE_EMITTED;
    edge->branch_offset = label_id;
    edge->fallback_guest_pc = fallback_guest_pc;
    tb->tu_has_edges = true;
    lata_debug_trace_tu_edge_state(tb, n, old_state, edge->state, "emit");
}

void lata_tu_edge_emit_branch(TranslationBlock *tb, int n, uint32_t label_id,
                              uint64_t fallback_guest_pc)
{
    lata_tu_edge_emit_common(tb, n, label_id, fallback_guest_pc,
                             LATA_TU_BRANCH_B);
}

void lata_tu_edge_emit_cond_branch(TranslationBlock *tb, int n,
                                   uint32_t label_id,
                                   uint64_t fallback_guest_pc,
                                   LataTUBranchKind branch_kind)
{
    lata_tu_edge_emit_common(tb, n, label_id, fallback_guest_pc, branch_kind);
}

void lata_tu_edge_set_unlink_stub(TranslationBlock *tb, int n,
                                  uint32_t label_id)
{
    tb->tu_edges[n].unlink_stub_offset = label_id;
}

bool lata_tu_edges_share_unlink_stub(TranslationBlock *tb)
{
    return tb->tu_edges[TU_TB_INDEX_TARGET].unlink_stub_offset ==
           tb->tu_edges[TU_TB_INDEX_NEXT].unlink_stub_offset;
}

bool lata_tu_edge_is_unlinked(TranslationBlock *tb, int n)
{
    return tb && tb->tu_edges[n].state == LATA_TU_EDGE_UNLINKED;
}

void lata_tu_mark_relink_pending(TranslationBlock *tb, int n)
{
    if (lata_tu_edge_is_unlinked(tb, n)) {
        LataTUEdgeState old_state = tb->tu_edges[n].state;

        tb->tu_edges[n].state = LATA_TU_EDGE_RELINK_PENDING;
        lata_debug_trace_tu_edge_state(tb, n, old_state,
                                       tb->tu_edges[n].state,
                                       "mark-relink");
    }
}

bool lata_tu_edge_need_relink(TranslationBlock *tb, int n)
{
    return tb && tb->tu_edges[n].state == LATA_TU_EDGE_RELINK_PENDING;
}

static void tu_reset_tb(TranslationBlock *tb)
{
    qemu_spin_init(&tb->jmp_lock);
    tb->jmp_dest[0] = (uintptr_t)NULL;
    tb->jmp_dest[1] = (uintptr_t)NULL;
    tb->jmp_list_head = (uintptr_t)NULL;
    tb->jmp_list_next[0] = (uintptr_t)NULL;
    tb->jmp_list_next[1] = (uintptr_t)NULL;

    /* init top in and top out */
    tb->jmp_reset_offset[0] = TB_JMP_OFFSET_INVALID;
    tb->jmp_reset_offset[1] = TB_JMP_OFFSET_INVALID;
    tb_set_page_addr0(tb, -1);
    tb_set_page_addr1(tb, -1);
#ifdef CONFIG_LATA_INSTS_PATTERN
    tb->nzcv_save[0] = TB_JMP_OFFSET_INVALID;
    tb->nzcv_save[1] = TB_JMP_OFFSET_INVALID;
    tb->nzcv_use = true ;
#endif
    tb->tc.offset_in_tu = 0;
    tb->next_pc = 0;
    tb->target_pc = 0;
    tb->tu_fallback_reason = LATA_TU_FALLBACK_NONE;
    tb->s_data->tu_id = 0;
    tb->s_data->is_first_tb = 0;
    tb->last_ir1_type = 0;
    tb->s_data->tu_tb_mode = TU_TB_MODE_NONE;
    lata_tu_tb_reset_edges(tb);

}

/* Create a TB and initialize it. */
static TranslationBlock* tb_create(CPUState *cpu, uint64_t pc,
        uint64_t cs_base, uint32_t flags, int cflags,
        int max_insns, bool is_first_tb)
{
    TranslationBlock* tb;
    tb = tcg_tb_alloc_full(tcg_ctx);
    if (unlikely(!tb)) {
        fprintf(stderr, "tb flush\n");
        /* exit(-1); */
        /* flush must be done */
        tb_flush(cpu);
        mmap_unlock();
        /* Make the execution loop process the flush as soon as possible.  */
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }        
    tu_reset_tb(tb);
    tb->pc = pc;
    tb->cs_base = cs_base;
    tb->flags = flags;
    tb->cflags = cflags;
    tb->last_ir1_type = 0;
    tb->env = cpu->env_ptr;
    tb->s_data->is_first_tb = is_first_tb;
    target_disasm(tb, &max_insns, cpu);

    if (tb->icount == 0 || tb->s_data->tu_tb_mode == TU_TB_MODE_BROKEN ) {
        return NULL;
    }    

    tu_tree_insert(tb);
    return tb;
}

static inline int tb_sort_cmp(const void *ap, const void *bp)
{
    const TranslationBlock *a = *(const TranslationBlock **)ap;
    const TranslationBlock *b = *(const TranslationBlock **)bp;
    return a->pc < b->pc ? -1 : a->pc > b->pc;
}

static inline target_ulong get_page(target_ulong pc)
{
    return pc & TARGET_PAGE_MASK;
}

static inline bool tu_can_link_to_tb(TranslationBlock *tb)
{
    return tb && tb->last_ir1_type != IR1_TYPE_SYSCALL &&
           tb->last_ir1_type != IR1_TYPE_CALL &&
           tb->last_ir1_type != IR1_TYPE_CALLIN &&
           tb->last_ir1_type != IR1_TYPE_RET &&
           tb->last_ir1_type != IR1_TYPE_JMPIN;
}

static inline void tu_drop_link_to_tb(TranslationBlock **tbp)
{
    TranslationBlock *tb = *tbp;
    if (!tu_can_link_to_tb(tb)) {
        if (tb) {
            tb->s_data->tu_tb_mode = TU_TB_MODE_SWITCH_TO_TB;
        }
        *tbp = NULL;
    }
}

static TranslationBlock *tu_lookup_or_create_tb(CPUState *cpu, target_ulong pc,
        target_ulong cs_base, uint32_t flags, int cflags, int max_insns)
{
    TranslationBlock *tb = tu_tree_lookup(pc);

    if (!tb) {
        tb = tb_htable_lookup(cpu, pc, cs_base, flags, cflags);
    }
    if (!tb) {
        tb = tb_create(cpu, pc, cs_base, flags, cflags, max_insns, false);
        tu_push_back(tb);
    }
    return tb;
}

static TranslationBlock *tu_lookup_tb(CPUState *cpu, target_ulong pc,
        target_ulong cs_base, uint32_t flags, int cflags)
{
    TranslationBlock *tb = tu_tree_lookup(pc);

    if (!tb) {
        tb = tb_htable_lookup(cpu, pc, cs_base, flags, cflags);
    }
    return tb;
}

static inline void get_tu_queue(CPUState *cpu,
		 target_ulong cs_base, uint32_t flags,
		 int cflags, int max_insns)
{
    uint64_t ir1_next_pc, ir1_target_pc;
    TranslationBlock** tb_list = tu_data->tb_list;
    uint32_t *tb_num_in_tu = &tu_data->tb_num;
    TranslationBlock *next_tb, *target_tb, *tb;
    for (int i = 0; i <  *tb_num_in_tu && *tb_num_in_tu < MAX_TB_IN_TU - 1; i++) {
        tb = tb_list[i];
        if (tb->s_data->tu_tb_mode == TU_TB_MODE_SWITCH_TO_TB) {
            continue;
        }
        ir1_next_pc = tb->next_pc;
        ir1_target_pc = tb->target_pc;
        switch (tb->last_ir1_type) {
        case IR1_TYPE_CALL:
            lata_tu_mark_tb_fallback(tb,
                LATA_TU_FALLBACK_UNSUPPORTED_TERMINATOR);
            break;
        case IR1_TYPE_BRANCH:
            lsassert(ir1_next_pc);
            lsassert(ir1_target_pc);
            if (get_page(tb->pc) != get_page(ir1_next_pc) ||
                get_page(tb->pc) != get_page(ir1_target_pc)) {
                lata_tu_drop_all_edges(tb, LATA_TU_FALLBACK_CROSS_PAGE);
                break;
            }

            next_tb = tu_lookup_tb(cpu, ir1_next_pc, cs_base, flags, cflags);
            target_tb = tu_lookup_tb(cpu, ir1_target_pc, cs_base, flags, cflags);
            if ((next_tb && !tu_can_link_to_tb(next_tb)) ||
                (target_tb && !tu_can_link_to_tb(target_tb))) {
                lata_tu_drop_all_edges(tb,
                    LATA_TU_FALLBACK_TARGET_NOT_TRANSLATABLE);
                break;
            }

            if (!next_tb) {
                next_tb = tb_create(cpu, ir1_next_pc, cs_base, flags,
                                    cflags, max_insns, false);
                if (!tu_can_link_to_tb(next_tb)) {
                    next_tb->s_data->tu_tb_mode = TU_TB_MODE_SWITCH_TO_TB;
                    lata_tu_drop_all_edges(tb,
                        LATA_TU_FALLBACK_TARGET_NOT_TRANSLATABLE);
                    break;
                }
                tu_push_back(next_tb);
            }

            if (!target_tb) {
                target_tb = tb_create(cpu, ir1_target_pc, cs_base, flags,
                                      cflags, max_insns, false);
                if (!tu_can_link_to_tb(target_tb)) {
                    target_tb->s_data->tu_tb_mode = TU_TB_MODE_SWITCH_TO_TB;
                    lata_tu_drop_all_edges(tb,
                        LATA_TU_FALLBACK_TARGET_NOT_TRANSLATABLE);
                    break;
                }
                tu_push_back(target_tb);
            }

            tb->next_tb[TU_TB_INDEX_NEXT] = next_tb;
            tb->next_tb[TU_TB_INDEX_TARGET] = target_tb;
            break;
        case IR1_TYPE_JMP:
            lsassert(ir1_target_pc);
            if (get_page(tb->pc) == get_page(ir1_target_pc)) {
                target_tb = tu_lookup_or_create_tb(cpu, ir1_target_pc,
                                                   cs_base, flags, cflags,
                                                   max_insns);
                tu_drop_link_to_tb(&target_tb);
                tb->next_tb[TU_TB_INDEX_TARGET] = target_tb;
            } else {
                lata_tu_drop_edge(tb, TU_TB_INDEX_TARGET,
                                  LATA_TU_FALLBACK_CROSS_PAGE);
            }
            break;
        case IR1_TYPE_CALLIN:
        case IR1_TYPE_SYSCALL:
            lata_tu_mark_tb_fallback(tb,
                LATA_TU_FALLBACK_UNSUPPORTED_TERMINATOR);
            break;
        case IR1_TYPE_NORMAL:
            lsassert(ir1_next_pc);
            if (get_page(tb->pc) == get_page(ir1_next_pc)) {
                next_tb = tu_lookup_or_create_tb(cpu, ir1_next_pc, cs_base,
                                                 flags, cflags, max_insns);
                tu_drop_link_to_tb(&next_tb);
                tb->next_tb[TU_TB_INDEX_NEXT] = next_tb;
            } else {
                lata_tu_drop_edge(tb, TU_TB_INDEX_NEXT,
                                  LATA_TU_FALLBACK_CROSS_PAGE);
            }
            break;
        case IR1_TYPE_RET:
        case IR1_TYPE_JMPIN:
            lata_tu_mark_tb_fallback(tb,
                LATA_TU_FALLBACK_UNSUPPORTED_TERMINATOR);
            break;
        default:
            lsassert(0);
        }
    }

/* Note: *tb_num_in_tu maybe greater than MAX_TB_IN_TU. */
    if (*tb_num_in_tu > MAX_TB_IN_TU) {
        lsassert(0);
    }
}

static void tu_set_tb_to_translate_context(TranslationBlock *tb,
                                           LataTUFallbackReason reason)
{
    lata_tu_drop_all_edges(tb, reason);
    tb->s_data->tu_tb_mode = TU_TB_MODE_SWITCH_TO_TB;
    lata_tu_tb_reset_edges(tb);
    lata_tu_mark_tb_fallback(tb, reason);
}

static void lata_tu_recompute_tail_info(TranslationBlock *tb)
{
    DisasContext *last_ir1;

    if (!tb->ir1 || tb->icount == 0) {
        tu_set_tb_to_translate_context(tb,
                                       LATA_TU_FALLBACK_INVALID_TARGET);
        return;
    }

    last_ir1 = (DisasContext *)tb->ir1 + tb->icount - 1;
    tb->next_pc = last_ir1->pc_curr + 4;
    tb->target_pc = 0;
    tb->last_ir1_type = IR1_TYPE_NORMAL;
    get_last_info(tb, last_ir1);
    tb->size = tb->next_pc - tb->pc;
}

static void tu_split_tb(TranslationBlock *pre_tb, TranslationBlock *tb)
{
    bool spilt_success = false;
    DisasContext *pre_s = (DisasContext *)pre_tb->ir1;
    uint32_t split_icount = 0;
    target_ulong pre_pc, tb_pc = ((DisasContext *)tb->ir1)->pc_curr;

    if (pre_tb->icount < tb->icount) {
        for (int i = 0; i < pre_tb->icount; i++) {
            pre_pc = (pre_s + i)->pc_curr;
            if (pre_pc == tb_pc) {
                spilt_success = true;
                split_icount = i;
                break;
            }
        }
    } else if (pre_tb->icount > tb->icount) {
        uint32_t th_firs_inst = pre_tb->icount - tb->icount;
        lsassert(th_firs_inst <= pre_tb->icount);
        pre_pc = (pre_s + th_firs_inst)->pc_curr;
        if (pre_pc == tb_pc) {
            spilt_success = true;
            split_icount = th_firs_inst;
        }
    } else {
        lsassert(0);
    }

    if (spilt_success) {
        /* tb->tu_start_mode = TU_TB_START_NORMAL; */
        lsassert(split_icount > 0 && split_icount < pre_tb->icount);
        pre_tb->icount = split_icount;
        lata_tu_recompute_tail_info(pre_tb);
        pre_tb->next_tb[TU_TB_INDEX_NEXT] = tb;
        pre_tb->next_tb[TU_TB_INDEX_TARGET] = NULL;
        lata_tu_tb_reset_edges(pre_tb);
        lata_tu_edge_set_target(pre_tb, TU_TB_INDEX_NEXT, tb);
        pre_tb->isplit = 1;
    } else {
        /*Can't judge pre_tb or tb was broken.*/
        tu_set_tb_to_translate_context(pre_tb,
                                       LATA_TU_FALLBACK_OVERLAP_SPLIT_FAILED);
        tu_set_tb_to_translate_context(tb,
                                       LATA_TU_FALLBACK_OVERLAP_SPLIT_FAILED);
    }
}

void solve_tb_overlap(TranslationBlock **tb_list, int max_insns)
{
    TranslationBlock *pre_tb = tb_list[0];
    TranslationBlock *tb;
    uint32_t tb_num_in_tu = tu_data->tb_num;
    for (int i = 1; i < tb_num_in_tu; i++) {
        tb = tb_list[i];
        tb->isplit = 0;
        if (pre_tb->s_data->tu_tb_mode == TU_TB_MODE_BROKEN) {
            assert(0);
            pre_tb = tb;
            continue;
        }
        /* judge if TB need split
         * pre_tb-------->pc + 0
         *                pc + 1
         *                pc + 2
         * tb------------>pc + 3
         *                pc + 4
         *                pc + 5
         * pre_tb_next--->pc + 6
         */
        if (tb->pc < pre_tb->next_pc && tb->pc > pre_tb->pc) {
            /* when split prefix ins, translate it two times.
             *
             * pre_tb--------> lock
             * tb------------> add
             *                 ...
             * tb_end--------> jmp
             *
             */
            if (pre_tb->icount == tb->icount) {
                /* pre_tb dont link in TU */
                lata_tu_drop_all_edges(pre_tb, LATA_TU_FALLBACK_OVERLAP_PREFIX);
                lata_tu_tb_reset_edges(pre_tb);
                pre_tb->s_data->tu_tb_mode = TU_TB_MODE_SWITCH_TO_TB;
                pre_tb = tb;
                continue;
            }
            if (pre_tb->icount < tb->icount) {
                /*Can't judge pre_tb or tb was broken.*/
                tu_set_tb_to_translate_context(pre_tb,
                                               LATA_TU_FALLBACK_OVERLAP_PREFIX);
                tu_set_tb_to_translate_context(tb,
                                               LATA_TU_FALLBACK_OVERLAP_PREFIX);
                pre_tb = tb;
                continue;
            }
            /*if pre_tb is splited, unlink pre_tb in tu */
            lata_tu_drop_all_edges(pre_tb, LATA_TU_FALLBACK_OVERLAP_PREFIX);

            /*When pre_tb->icount achive max_insns, the end addresses of two TBS are different*/
            if (pre_tb->icount == max_insns) {
                lata_tu_tb_reset_edges(pre_tb);
            } else {
                tu_split_tb(pre_tb, tb);
            }
            /* Note: some message of pre_tb last ir1 ins is not modify */
        }
        if (pre_tb->s_data->tu_tb_mode != TU_TB_MODE_BROKEN) {
            pre_tb = tb;
        }
    }
}

static void tu_compact_translatable_tbs(TranslationBlock **tb_list)
{
    uint32_t out = 0;

    for (uint32_t i = 0; i < tu_data->tb_num; i++) {
        TranslationBlock *tb = tb_list[i];
        if (tb->s_data->tu_tb_mode == TU_TB_MODE_SWITCH_TO_TB) {
            continue;
        }
        tb_list[out++] = tb;
    }
    tu_data->tb_num = out;
}

static bool tu_tb_is_translatable(TranslationBlock *tb,
                                  TranslationBlock **tb_list)
{
    for (uint32_t i = 0; i < tu_data->tb_num; i++) {
        if (tb_list[i] == tb &&
            tb->s_data->tu_tb_mode != TU_TB_MODE_SWITCH_TO_TB) {
            return true;
        }
    }
    return false;
}

static bool tu_tb_edge_in_range(TranslationBlock *tb, int n,
                                TranslationBlock *edge)
{
    target_ulong edge_pc = edge ? edge->pc : 0;

    switch (tb->last_ir1_type) {
    case IR1_TYPE_BRANCH:
        return n == TU_TB_INDEX_NEXT ? edge_pc == tb->next_pc :
                                       edge_pc == tb->target_pc;
    case IR1_TYPE_NORMAL:
        return n == TU_TB_INDEX_NEXT && edge_pc == tb->next_pc;
    case IR1_TYPE_JMP:
        return n == TU_TB_INDEX_TARGET && edge_pc == tb->target_pc;
    default:
        return false;
    }
}

static void tu_sanitize_edges(TranslationBlock **tb_list)
{
    for (uint32_t i = 0; i < tu_data->tb_num; i++) {
        TranslationBlock *tb = tb_list[i];
        bool next_ok = tb->next_tb[TU_TB_INDEX_NEXT] &&
            tu_tb_is_translatable(tb->next_tb[TU_TB_INDEX_NEXT], tb_list) &&
            tu_tb_edge_in_range(tb, TU_TB_INDEX_NEXT,
                                tb->next_tb[TU_TB_INDEX_NEXT]);
        bool target_ok = tb->next_tb[TU_TB_INDEX_TARGET] &&
            tu_tb_is_translatable(tb->next_tb[TU_TB_INDEX_TARGET], tb_list) &&
            tu_tb_edge_in_range(tb, TU_TB_INDEX_TARGET,
                                tb->next_tb[TU_TB_INDEX_TARGET]);

        switch (tb->last_ir1_type) {
        case IR1_TYPE_BRANCH:
            if (!next_ok || !target_ok) {
                lata_tu_drop_all_edges(tb,
                    LATA_TU_FALLBACK_EDGE_PC_MISMATCH);
            }
            break;
        case IR1_TYPE_NORMAL:
            if (!next_ok) {
                lata_tu_drop_edge(tb, TU_TB_INDEX_NEXT,
                                  LATA_TU_FALLBACK_EDGE_PC_MISMATCH);
            }
            tb->next_tb[TU_TB_INDEX_TARGET] = NULL;
            break;
        case IR1_TYPE_JMP:
            tb->next_tb[TU_TB_INDEX_NEXT] = NULL;
            if (!target_ok) {
                lata_tu_drop_edge(tb, TU_TB_INDEX_TARGET,
                                  LATA_TU_FALLBACK_EDGE_PC_MISMATCH);
            }
            break;
        default:
            lata_tu_drop_all_edges(tb,
                LATA_TU_FALLBACK_UNSUPPORTED_TERMINATOR);
            break;
        }
        lata_tu_tb_reset_edges(tb);
        if (tb->next_tb[TU_TB_INDEX_NEXT]) {
            lata_tu_edge_set_target(tb, TU_TB_INDEX_NEXT,
                                    tb->next_tb[TU_TB_INDEX_NEXT]);
        }
        if (tb->next_tb[TU_TB_INDEX_TARGET]) {
            lata_tu_edge_set_target(tb, TU_TB_INDEX_TARGET,
                                    tb->next_tb[TU_TB_INDEX_TARGET]);
        }
    }
}

/*explore tbs in tu*/
static TranslationBlock *tb_explore(CPUState *cpu,
                              target_ulong pc, uint64_t cs_base,
                              uint32_t flags, int cflags)
{
    TranslationBlock** tb_list = tu_data->tb_list;
    uint32_t *tb_num_in_tu = &tu_data->tb_num;
    uint32_t *ir1_num_in_tu = &tu_data->ir1_num_in_tu;
    int max_insns;

    max_insns = cflags & CF_COUNT_MASK;
    if (max_insns == 0) {
        max_insns = TCG_MAX_INSNS;
    }
    if (max_insns > TCG_MAX_INSNS) {
        max_insns = TCG_MAX_INSNS;
    }
    if (cpu->singlestep_enabled) {
        max_insns = 1;
    }
    *tb_num_in_tu = 0;
    *ir1_num_in_tu = 0;

    tu_enough_space(cpu);
    /* the entry used as return value*/

    TranslationBlock *entry = tb_create(cpu, pc, cs_base,
            flags, cflags, max_insns, true);
    tu_push_back(entry);            
    /* Search same-page direct successors. Calls, indirect branches and
     * syscalls remain TU boundaries until the TU-specific unlink path is
     * rebuilt.
     */
    get_tu_queue(cpu, cs_base, flags, cflags, max_insns);

    /* sort tbs by PC */
    qsort(tb_list, *tb_num_in_tu, sizeof(TranslationBlock *), tb_sort_cmp);

    /* Some TBS may overlap. We split these overlapping TBS. */
    solve_tb_overlap(tb_list, max_insns);
    tu_compact_translatable_tbs(tb_list);
    tu_sanitize_edges(tb_list);

    for (int i = 0; i < *tb_num_in_tu; i++){
        /* record tu pc and tb_num */
        tb_list[i]->s_data->tu_id = tb_list[0]->pc;
    }

    return entry;

}

static inline int64_t tu_branch_disp(uintptr_t fix_addr, uintptr_t target)
{
    return ((int64_t)target - (int64_t)fix_addr) >> 2;
}

static inline bool tu_branch_disp_fits(uintptr_t fix_addr, uintptr_t target,
                                       int bits)
{
    int64_t disp = tu_branch_disp(fix_addr, target);

    return disp >= -(1 << (bits - 1)) && disp < (1 << (bits - 1));
}

bool tu_use_jmp(TranslationBlock *tb)
{
    return tb && tb->tu_has_edges;
}

static bool lata_tu_edge_emitted(TranslationBlock *tb, int n)
{
    return tb && tb->tu_edges[n].branch_offset != LATA_TU_EDGE_OFFSET_INVALID;
}

static bool tu_patch_b(uintptr_t fix_addr, uintptr_t target)
{
    int64_t disp = tu_branch_disp(fix_addr, target);
    uint32_t *fix_rw = (uint32_t *)(fix_addr - tcg_splitwx_diff);
    uint32_t insn = *(uint32_t *)fix_addr;

    if (!tu_branch_disp_fits(fix_addr, target, 26)) {
        return false;
    }

    insn &= 0xfc000000;
    insn |= ((uint32_t)disp & 0xffff) << 10;
    insn |= ((uint32_t)disp >> 16) & 0x3ff;
    qatomic_set(fix_rw, insn);
    flush_idcache_range(fix_addr, (uintptr_t)fix_rw, 4);
    return true;
}

static uintptr_t tu_b_target(uintptr_t insn_addr, uint32_t insn)
{
    uint32_t imm = ((insn >> 10) & 0xffff) | ((insn & 0x3ff) << 16);
    int32_t disp = sextract32(imm, 0, 26);

    return insn_addr + ((intptr_t)disp << 2);
}

static bool tu_patch_as_b(uintptr_t fix_addr, uintptr_t target)
{
    int64_t disp = tu_branch_disp(fix_addr, target);
    uint32_t *fix_rw = (uint32_t *)(fix_addr - tcg_splitwx_diff);
    uint32_t insn = 0x50000000;

    if (!tu_branch_disp_fits(fix_addr, target, 26)) {
        return false;
    }

    insn |= ((uint32_t)disp & 0xffff) << 10;
    insn |= ((uint32_t)disp >> 16) & 0x3ff;
    qatomic_set(fix_rw, insn);
    flush_idcache_range(fix_addr, (uintptr_t)fix_rw, 4);
    return true;
}

static bool tu_patch_bcc16(uintptr_t fix_addr, uintptr_t target)
{
    int64_t disp = tu_branch_disp(fix_addr, target);
    uint32_t *fix_rw = (uint32_t *)(fix_addr - tcg_splitwx_diff);
    uint32_t insn = *(uint32_t *)fix_addr;

    if (!tu_branch_disp_fits(fix_addr, target, 16)) {
        return false;
    }

    insn &= ~(0xffffu << 10);
    insn |= ((uint32_t)disp & 0xffff) << 10;
    qatomic_set(fix_rw, insn);
    flush_idcache_range(fix_addr, (uintptr_t)fix_rw, 4);
    return true;
}

static bool tu_patch_bcc20(uintptr_t fix_addr, uintptr_t target)
{
    int64_t disp = tu_branch_disp(fix_addr, target);
    uint32_t *fix_rw = (uint32_t *)(fix_addr - tcg_splitwx_diff);
    uint32_t insn = *(uint32_t *)fix_addr;

    if (!tu_branch_disp_fits(fix_addr, target, 20)) {
        return false;
    }

    insn &= ~((0xffffu << 10) | 0x1fu);
    insn |= ((uint32_t)disp & 0xffff) << 10;
    insn |= ((uint32_t)disp >> 16) & 0x1f;
    qatomic_set(fix_rw, insn);
    flush_idcache_range(fix_addr, (uintptr_t)fix_rw, 4);
    return true;
}

static uint32_t lata_tu_emit_branch_island(TranslationBlock *tb)
{
    qatomic_set(&tcg_ctx->code_gen_ptr, (void *)
        ROUND_UP((uintptr_t)tcg_ctx->code_gen_ptr, CODE_GEN_ALIGN));

    uint8_t *dst_rw = tcg_ctx->code_gen_ptr;
    uintptr_t dst_rx = (uintptr_t)tcg_splitwx_to_rx(dst_rw);
    uint32_t *dst_insn = (uint32_t *)dst_rw;

    qatomic_set(dst_insn, 0x50000000);
    qatomic_set(&tcg_ctx->code_gen_ptr,
                (void *)ROUND_UP((uintptr_t)dst_rw + 4, CODE_GEN_ALIGN));
    return dst_rx - (uintptr_t)tb->tc.ptr;
}

static bool lata_tu_patch_cond_via_island(TranslationBlock *tb,
                                          LataTUEdge *edge,
                                          uintptr_t target)
{
    uintptr_t fix_addr = (uintptr_t)tb->tc.ptr + edge->branch_offset;
    uintptr_t island_addr;
    uint32_t fix_insn = *(uint32_t *)fix_addr;

    if (edge->branch_island_offset == LATA_TU_EDGE_OFFSET_INVALID) {
        edge->branch_island_offset = lata_tu_emit_branch_island(tb);
    }
    island_addr = (uintptr_t)tb->tc.ptr + edge->branch_island_offset;

    if (!tu_branch_disp_fits(island_addr, target, 26)) {
        edge->fallback_reason = LATA_TU_FALLBACK_ISLAND_RANGE;
        return false;
    }

    if ((fix_insn & 0xF8000000) == 0x40000000) {
        if (!tu_branch_disp_fits(fix_addr, island_addr, 20)) {
            edge->fallback_reason = LATA_TU_FALLBACK_BRANCH_RANGE;
            return false;
        }
    } else if (!tu_branch_disp_fits(fix_addr, island_addr, 16)) {
        edge->fallback_reason = LATA_TU_FALLBACK_BRANCH_RANGE;
        return false;
    }

    if (!tu_patch_b(island_addr, target)) {
        edge->fallback_reason = LATA_TU_FALLBACK_ISLAND_RANGE;
        return false;
    }

    if ((fix_insn & 0xF8000000) == 0x40000000) {
        if (!tu_patch_bcc20(fix_addr, island_addr)) {
            return false;
        }
    } else {
        if (!tu_patch_bcc16(fix_addr, island_addr)) {
            return false;
        }
    }

    return true;
}

static bool lata_tu_patch_edge_to_target(TranslationBlock *tb,
                                         LataTUEdge *edge,
                                         uintptr_t target)
{
    uintptr_t fix_addr = (uintptr_t)tb->tc.ptr + edge->branch_offset;
    uint32_t *fix_rw = (uint32_t *)(fix_addr - tcg_splitwx_diff);
    uint32_t fix_insn = *(uint32_t *)fix_addr;

    if (edge->saved_insn) {
        qatomic_set(fix_rw, edge->saved_insn);
        fix_insn = edge->saved_insn;
    }

    if ((fix_insn & 0xFC000000) == 0x50000000) {
        return tu_patch_b(fix_addr, target);
    }
    if ((fix_insn & 0xF0000000) >= 0x50000000 &&
        (fix_insn & 0xF0000000) <= 0x60000000) {
        return tu_patch_bcc16(fix_addr, target) ||
               lata_tu_patch_cond_via_island(tb, edge, target);
    }
    if ((fix_insn & 0xF8000000) == 0x40000000) {
        return tu_patch_bcc20(fix_addr, target) ||
               lata_tu_patch_cond_via_island(tb, edge, target);
    }
    return false;
}

static bool lata_tu_edge_patch_site_valid(TranslationBlock *tb,
                                          LataTUEdge *edge)
{
    uintptr_t tb_start;
    uintptr_t tb_end;

    if (!tb || !tb->tc.ptr ||
        edge->branch_offset == LATA_TU_EDGE_OFFSET_INVALID) {
        return false;
    }

    tb_start = (uintptr_t)tb->tc.ptr;
    tb_end = tb_start + tb->tc.size;
    return tb_start + edge->branch_offset >= tb_start &&
           tb_start + edge->branch_offset < tb_end;
}

static bool lata_tu_edge_unlink_stub_valid(TranslationBlock *tb,
                                           LataTUEdge *edge,
                                           uintptr_t tu_code_end)
{
    uintptr_t tb_start;
    uintptr_t stub_addr;

    if (!tb || !tb->tc.ptr ||
        edge->unlink_stub_offset == TU_UNLINK_STUB_INVALID) {
        return false;
    }

    tb_start = (uintptr_t)tb->tc.ptr;
    stub_addr = tb_start + edge->unlink_stub_offset;
    return stub_addr >= tb_start && stub_addr < tu_code_end;
}

static uintptr_t lata_tu_map_moved_addr(uintptr_t old_addr,
                                        const uintptr_t *old_rx,
                                        const uintptr_t *new_rx,
                                        const uint32_t *size,
                                        uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        if (size[i] != 0 &&
            old_addr >= old_rx[i] && old_addr < old_rx[i] + size[i]) {
            return new_rx[i] + old_addr - old_rx[i];
        }
    }
    return old_addr;
}

static void lata_tu_relocate_direct_branches(uintptr_t old_rx,
                                             uintptr_t new_rx,
                                             size_t size,
                                             const uintptr_t *old_map_rx,
                                             const uintptr_t *new_map_rx,
                                             const uint32_t *map_size,
                                             uint32_t map_count)
{
    for (size_t off = 0; off + 4 <= size; off += 4) {
        uint32_t insn = *(uint32_t *)(new_rx + off);
        uintptr_t old_target, new_target;

        if ((insn & 0xFC000000) != 0x50000000) {
            continue;
        }

        old_target = tu_b_target(old_rx + off, insn);
        if (old_target == context_switch_native_to_bt) {
            new_target = context_switch_native_to_bt;
        } else {
            new_target = lata_tu_map_moved_addr(old_target, old_map_rx,
                                                new_map_rx, map_size,
                                                map_count);
        }

        if (new_target == old_target && new_rx + off == old_rx + off) {
            continue;
        }

        lsassertm(tu_patch_b(new_rx + off, new_target),
                  "TU direct branch is out of range after code movement\n");
    }
}

static uint32_t lata_tu_hot_size(TranslationBlock *tb)
{
    uint32_t hot_size = tb->tc.size;

    for (int n = 0; n < 2; n++) {
        uint32_t stub_offset = tb->tu_edges[n].unlink_stub_offset;

        if (stub_offset != TU_UNLINK_STUB_INVALID &&
            stub_offset < hot_size) {
            hot_size = stub_offset;
        }
    }
    return hot_size;
}

static void lata_tu_move_unlink_stubs_to_cold_tail(TranslationBlock **tb_list,
                                                   uint32_t tb_num_in_tu)
{
    uint8_t *tmp_buffer;
    uint32_t tmp_buffer_size = 0;
    uintptr_t old_hot_rx[MAX_TB_IN_CACHE] = { 0 };
    uintptr_t new_hot_rx[MAX_TB_IN_CACHE] = { 0 };
    uint32_t hot_size[MAX_TB_IN_CACHE] = { 0 };
    uint32_t cold_start[MAX_TB_IN_CACHE] = { 0 };
    uint32_t cold_size[MAX_TB_IN_CACHE] = { 0 };
    uintptr_t old_cold_rx[MAX_TB_IN_CACHE] = { 0 };
    uintptr_t new_cold_rx[MAX_TB_IN_CACHE] = { 0 };
    uintptr_t old_map_rx[MAX_TB_IN_CACHE * 2] = { 0 };
    uintptr_t new_map_rx[MAX_TB_IN_CACHE * 2] = { 0 };
    uint32_t map_size[MAX_TB_IN_CACHE * 2] = { 0 };
    uint32_t map_count = 0;
    uintptr_t curr_rx;

    if (tb_num_in_tu <= 1) {
        return;
    }

    qatomic_set(&tcg_ctx->code_gen_ptr, (void *)
        ROUND_UP((uintptr_t)tcg_ctx->code_gen_ptr, CODE_GEN_ALIGN));
    tmp_buffer = tcg_ctx->code_gen_ptr;

    for (uint32_t i = 0; i < tb_num_in_tu; i++) {
        TranslationBlock *tb = tb_list[i];
        uint32_t tb_hot_size = lata_tu_hot_size(tb);
        uint32_t tb_cold_size = tb->tc.size - tb_hot_size;

        old_hot_rx[i] = (uintptr_t)tb->tc.ptr;
        hot_size[i] = tb_hot_size;
        if (tb_cold_size == 0) {
            continue;
        }

        cold_start[i] = tmp_buffer_size;
        cold_size[i] = tb_cold_size;
        old_cold_rx[i] = (uintptr_t)tb->tc.ptr + tb_hot_size;
        memcpy(tmp_buffer + cold_start[i],
               (void *)((uintptr_t)tb->tc.ptr + tb_hot_size - tcg_splitwx_diff),
               tb_cold_size);
        tmp_buffer_size += tb_cold_size;

        for (int n = 0; n < 2; n++) {
            LataTUEdge *edge = &tb->tu_edges[n];

            if (edge->unlink_stub_offset == TU_UNLINK_STUB_INVALID) {
                continue;
            }
            lsassertm(edge->unlink_stub_offset >= tb_hot_size,
                      "TU unlink stub is before hot code end\n");
            edge->unlink_stub_offset =
                cold_start[i] + edge->unlink_stub_offset - tb_hot_size;
        }

        tb->tc.size = tb_hot_size;
        tb->codesize = tb_hot_size;
    }

    if (tmp_buffer_size == 0) {
        return;
    }

    curr_rx = (uintptr_t)tb_list[0]->tc.ptr + tb_list[0]->tc.size;
    new_hot_rx[0] = (uintptr_t)tb_list[0]->tc.ptr;
    tb_list[0]->tc.offset_in_tu = 0;
    for (uint32_t i = 1; i < tb_num_in_tu; i++) {
        TranslationBlock *tb = tb_list[i];
        uintptr_t old_rx = (uintptr_t)tb->tc.ptr;

        if (old_rx != curr_rx) {
            memmove((void *)(curr_rx - tcg_splitwx_diff),
                    (void *)(old_rx - tcg_splitwx_diff), tb->tc.size);
            tb->tc.ptr = (void *)curr_rx;
        }
        new_hot_rx[i] = curr_rx;
        tb->tc.offset_in_tu = curr_rx - (uintptr_t)tb_list[0]->tc.ptr;
        curr_rx += tb->tc.size;
    }

    memcpy((void *)(curr_rx - tcg_splitwx_diff), tmp_buffer, tmp_buffer_size);

    for (uint32_t i = 0; i < tb_num_in_tu; i++) {
        if (hot_size[i] != 0 && old_hot_rx[i] != new_hot_rx[i]) {
            old_map_rx[map_count] = old_hot_rx[i];
            new_map_rx[map_count] = new_hot_rx[i];
            map_size[map_count] = hot_size[i];
            map_count++;
        }
        if (cold_size[i] != 0) {
            new_cold_rx[i] = curr_rx + cold_start[i];
            old_map_rx[map_count] = old_cold_rx[i];
            new_map_rx[map_count] = new_cold_rx[i];
            map_size[map_count] = cold_size[i];
            map_count++;
        }
    }

    for (uint32_t i = 0; i < tb_num_in_tu; i++) {
        TranslationBlock *tb = tb_list[i];

        if (hot_size[i] != 0) {
            lata_tu_relocate_direct_branches(old_hot_rx[i], new_hot_rx[i],
                                             hot_size[i], old_map_rx,
                                             new_map_rx, map_size,
                                             map_count);
        }
        if (cold_size[i] != 0) {
            lata_tu_relocate_direct_branches(old_cold_rx[i], new_cold_rx[i],
                                             cold_size[i], old_map_rx,
                                             new_map_rx, map_size,
                                             map_count);
        }

        for (int n = 0; n < 2; n++) {
            LataTUEdge *edge = &tb->tu_edges[n];

            if (edge->unlink_stub_offset == TU_UNLINK_STUB_INVALID) {
                continue;
            }
            edge->unlink_stub_offset =
                new_cold_rx[i] + edge->unlink_stub_offset -
                cold_start[i] - (uintptr_t)tb->tc.ptr;
        }
    }

    qatomic_set(&tcg_ctx->code_gen_ptr, (void *)
        ROUND_UP(curr_rx + tmp_buffer_size - tcg_splitwx_diff, CODE_GEN_ALIGN));
}

bool lata_tu_relink_edge(TranslationBlock *tb, int n,
                         TranslationBlock *target_tb)
{
    LataTUEdge *edge = &tb->tu_edges[n];
    uintptr_t old;

    if (!lata_tu_edge_need_relink(tb, n)) {
        return false;
    }
    if (!target_tb || target_tb->tc.ptr == NULL ||
        (target_tb->cflags & CF_INVALID)) {
        return false;
    }
    if (edge->guest_pc && edge->guest_pc != target_tb->pc) {
        return false;
    }
    if (edge->branch_offset == LATA_TU_EDGE_OFFSET_INVALID) {
        return false;
    }

    old = qatomic_cmpxchg(&tb->jmp_dest[n], (uintptr_t)NULL,
                          (uintptr_t)target_tb);
    if (old != (uintptr_t)NULL) {
        return false;
    }

    if (!lata_tu_edge_patch_site_valid(tb, edge)) {
        qatomic_set(&tb->jmp_dest[n], (uintptr_t)NULL);
        edge->fallback_reason = LATA_TU_FALLBACK_INVALID_TARGET;
        lata_debug_note_tu_fallback(LATA_TU_FALLBACK_INVALID_TARGET);
        return false;
    }

    if (!lata_tu_patch_edge_to_target(tb, edge,
                                      (uintptr_t)target_tb->tc.ptr)) {
        qatomic_set(&tb->jmp_dest[n], (uintptr_t)NULL);
        edge->fallback_reason = LATA_TU_FALLBACK_BRANCH_RANGE;
        lata_debug_note_tu_fallback(LATA_TU_FALLBACK_BRANCH_RANGE);
        return false;
    }
    edge->target_tb = target_tb;
    edge->guest_pc = target_tb->pc;
    edge->saved_insn = *(uint32_t *)((uintptr_t)tb->tc.ptr +
                                    edge->branch_offset);
    LataTUEdgeState old_state = edge->state;

    edge->state = LATA_TU_EDGE_LINKED;
    lata_debug_trace_tu_edge_state(tb, n, old_state, edge->state, "relink");
    lata_debug_note_tu_edge_relinked();

    tb->jmp_list_next[n] = target_tb->jmp_list_head;
    target_tb->jmp_list_head = (uintptr_t)tb | n;
    return true;
}

void tu_unlink_branch(TranslationBlock *tb, int n)
{
    LataTUEdge *edge = &tb->tu_edges[n];
    uintptr_t tu_code_end = (uintptr_t)tcg_splitwx_to_rx(tcg_ctx->code_gen_ptr);

    if (!lata_tu_edge_emitted(tb, n) ||
        edge->branch_offset == LATA_TU_EDGE_OFFSET_INVALID ||
        edge->unlink_stub_offset == TU_UNLINK_STUB_INVALID) {
        return;
    }
    if (!lata_tu_edge_patch_site_valid(tb, edge) ||
        !lata_tu_edge_unlink_stub_valid(tb, edge, tu_code_end)) {
        return;
    }

    uintptr_t fix_addr = (uintptr_t)tb->tc.ptr + edge->branch_offset;
    uintptr_t stub_addr = (uintptr_t)tb->tc.ptr + edge->unlink_stub_offset;
    uint32_t fix_insn = *(uint32_t *)fix_addr;
    LataTUEdgeState old_state = edge->state;

    if ((fix_insn & 0xFC000000) == 0x50000000) {
        if (!tu_patch_b(fix_addr, stub_addr)) {
            edge->fallback_reason = LATA_TU_FALLBACK_BRANCH_RANGE;
            lata_debug_note_tu_fallback(LATA_TU_FALLBACK_BRANCH_RANGE);
            return;
        }
        edge->state = LATA_TU_EDGE_UNLINKED;
        lata_debug_trace_tu_edge_state(tb, n, old_state, edge->state,
                                       "unlink");
        lata_debug_note_tu_edge_unlinked();
        return;
    }

    lsassertm(lata_tu_edges_share_unlink_stub(tb),
              "TU conditional unlink requires a shared fallback stub\n");
    if (!tu_patch_as_b(fix_addr, stub_addr)) {
        edge->fallback_reason = LATA_TU_FALLBACK_BRANCH_RANGE;
        lata_debug_note_tu_fallback(LATA_TU_FALLBACK_BRANCH_RANGE);
        return;
    }
    edge->state = LATA_TU_EDGE_UNLINKED;
    lata_debug_trace_tu_edge_state(tb, n, old_state, edge->state, "unlink");
    lata_debug_note_tu_edge_unlinked();
}

static void tu_register_edge(TranslationBlock *tb, int n,
                             TranslationBlock *tb_next)
{
    uintptr_t old;

    qemu_spin_lock(&tb_next->jmp_lock);
    if (tb_next->cflags & CF_INVALID) {
        qemu_spin_unlock(&tb_next->jmp_lock);
        return;
    }

    old = qatomic_cmpxchg(&tb->jmp_dest[n], (uintptr_t)NULL,
                          (uintptr_t)tb_next);
    if (old) {
        qemu_spin_unlock(&tb_next->jmp_lock);
        return;
    }

    tb->jmp_list_next[n] = tb_next->jmp_list_head;
    tb_next->jmp_list_head = (uintptr_t)tb | n;
    qemu_spin_unlock(&tb_next->jmp_lock);
}

static target_ulong lata_tu_expected_edge_pc(TranslationBlock *tb, int n)
{
    switch (tb->last_ir1_type) {
    case IR1_TYPE_BRANCH:
        return n == TU_TB_INDEX_NEXT ? tb->next_pc : tb->target_pc;
    case IR1_TYPE_NORMAL:
        return n == TU_TB_INDEX_NEXT ? tb->next_pc : 0;
    case IR1_TYPE_JMP:
        return n == TU_TB_INDEX_TARGET ? tb->target_pc : 0;
    default:
        return 0;
    }
}

static void lata_tu_validate_edge_for_finalization(TranslationBlock *tb, int n,
                                                   TranslationBlock *target_tb,
                                                   uintptr_t tu_code_end)
{
    LataTUEdge *edge = &tb->tu_edges[n];
    target_ulong expected_pc = lata_tu_expected_edge_pc(tb, n);

    lsassertm(target_tb && target_tb->tc.ptr,
              "TU edge finalization requires a translated target TB\n");
    lsassertm(expected_pc && target_tb->pc == expected_pc,
              "TU edge target PC does not match origin TB metadata\n");
    lsassertm(edge->guest_pc == 0 || edge->guest_pc == target_tb->pc,
              "TU edge guest PC does not match target TB\n");
    lsassertm(lata_tu_edge_patch_site_valid(tb, edge),
              "TU edge branch offset is outside origin TB hot code\n");
    lsassertm(edge->unlink_stub_offset == TU_UNLINK_STUB_INVALID ||
              lata_tu_edge_unlink_stub_valid(tb, edge, tu_code_end),
              "TU edge unlink stub offset is outside TU code\n");
}

static bool lata_tu_patch_edge_to_unlink_stub(TranslationBlock *tb, int n)
{
    LataTUEdge *edge = &tb->tu_edges[n];
    uintptr_t fix_addr;
    uintptr_t stub_addr;
    uint32_t fix_insn;

    if (!lata_tu_edge_emitted(tb, n) ||
        edge->branch_offset == LATA_TU_EDGE_OFFSET_INVALID ||
        edge->unlink_stub_offset == TU_UNLINK_STUB_INVALID) {
        return false;
    }
    if (!lata_tu_edge_patch_site_valid(tb, edge) ||
        !lata_tu_edge_unlink_stub_valid(
            tb, edge, (uintptr_t)tcg_splitwx_to_rx(tcg_ctx->code_gen_ptr))) {
        return false;
    }

    fix_addr = (uintptr_t)tb->tc.ptr + edge->branch_offset;
    stub_addr = (uintptr_t)tb->tc.ptr + edge->unlink_stub_offset;
    fix_insn = *(uint32_t *)fix_addr;

    if ((fix_insn & 0xFC000000) == 0x50000000) {
        return tu_patch_b(fix_addr, stub_addr);
    }
    return tu_patch_as_b(fix_addr, stub_addr);
}

static void lata_tu_finalize_edges(TranslationBlock **tb_list,
                                   uint32_t tb_num_in_tu)
{
    uintptr_t tu_code_end = (uintptr_t)tcg_splitwx_to_rx(tcg_ctx->code_gen_ptr);

    for (uint32_t i = 0; i < tb_num_in_tu; i++) {
        TranslationBlock *tb = tb_list[i];

        for (int n = 0; n < 2; n++) {
            LataTUEdge *edge = &tb->tu_edges[n];
            TranslationBlock *target_tb = edge->target_tb ?
                edge->target_tb : tb->next_tb[n];

            if (!lata_tu_edge_emitted(tb, n)) {
                continue;
            }

            lata_tu_validate_edge_for_finalization(tb, n, target_tb,
                                                   tu_code_end);
            if (!tu_relocat_branch(tb, n)) {
                LataTUFallbackReason reason = edge->fallback_reason;

                if (lata_tu_patch_edge_to_unlink_stub(tb, n)) {
                    edge->state = LATA_TU_EDGE_UNLINKED;
                    lata_debug_note_tu_edge_unlinked();
                } else {
                    lata_tu_drop_edge(tb, n, reason);
                }
                lata_debug_note_tu_fallback(reason);
            }
        }
    }
}

/* Fix a TU-internal edge after the target TB has been translated. */
bool tu_relocat_branch(TranslationBlock *tb, int n)
{
    LataTUEdge *edge = &tb->tu_edges[n];
    TranslationBlock *tb_next = edge->target_tb ? edge->target_tb :
        tb->next_tb[n];
    bool use_tu_edge = lata_tu_edge_emitted(tb, n);
    uint32_t jmp_offset = use_tu_edge ? edge->branch_offset :
        tb->jmp_insn_offset[n];

    if (jmp_offset == (use_tu_edge ? LATA_TU_EDGE_OFFSET_INVALID :
                                      TB_JMP_OFFSET_INVALID)) {
        return false;
    }
    lsassert(tb_next && tb_next->tc.ptr);

    uintptr_t fix_addr = (uintptr_t)tb->tc.ptr + jmp_offset;
    uint fix_insn = *(uint *)fix_addr;

    if ((fix_insn & 0xFC000000) == 0x50000000) { /* b */
        if (use_tu_edge && tu_patch_b(fix_addr, (uintptr_t)tb_next->tc.ptr)) {
            edge->saved_insn = *(uint32_t *)fix_addr;
            edge->state = LATA_TU_EDGE_LINKED;
            lata_debug_note_tu_edge_linked();
            tu_register_edge(tb, n, tb_next);
            return true;
        }
        if (use_tu_edge) {
            edge->fallback_reason = LATA_TU_FALLBACK_BRANCH_RANGE;
            return false;
        }
        tb_set_jmp_target(tb, n, (uintptr_t)tb_next->tc.ptr);
        return true;
    } else if ((fix_insn & 0xF0000000) >= 0x50000000 &&
               (fix_insn & 0xF0000000) <= 0x60000000) {
        bool direct = tu_patch_bcc16(fix_addr, (uintptr_t)tb_next->tc.ptr);
        bool island = direct ? false :
            lata_tu_patch_cond_via_island(tb, edge,
                                          (uintptr_t)tb_next->tc.ptr);
        if (!direct && !island) {
            edge->fallback_reason =
                edge->branch_island_offset == LATA_TU_EDGE_OFFSET_INVALID ?
                LATA_TU_FALLBACK_BRANCH_RANGE : LATA_TU_FALLBACK_ISLAND_RANGE;
            return false;
        }
        edge->saved_insn = *(uint32_t *)fix_addr;
        edge->state = LATA_TU_EDGE_LINKED;
        lata_debug_note_tu_edge_linked();
        tu_register_edge(tb, n, tb_next);
        return true;
    } else if ((fix_insn & 0xF8000000) == 0x40000000) {
        bool direct = tu_patch_bcc20(fix_addr, (uintptr_t)tb_next->tc.ptr);
        bool island = direct ? false :
            lata_tu_patch_cond_via_island(tb, edge,
                                          (uintptr_t)tb_next->tc.ptr);
        if (!direct && !island) {
            edge->fallback_reason =
                edge->branch_island_offset == LATA_TU_EDGE_OFFSET_INVALID ?
                LATA_TU_FALLBACK_BRANCH_RANGE : LATA_TU_FALLBACK_ISLAND_RANGE;
            return false;
        }
        edge->saved_insn = *(uint32_t *)fix_addr;
        edge->state = LATA_TU_EDGE_LINKED;
        lata_debug_note_tu_edge_linked();
        tu_register_edge(tb, n, tb_next);
        return true;
    }
    edge->fallback_reason = LATA_TU_FALLBACK_INVALID_TARGET;
    return false;
}

/* translate tu from ir1->ir2 and link tbs if next_tb in tu*/
void translate_tu(TranslationBlock **tb_list)
{
    uint32_t tb_num_in_tu = tu_data->tb_num;
    if (tb_num_in_tu == 0) {
        return;
    }
    int gen_code_size;
    TranslationBlock *tb;

    qatomic_set(&tcg_ctx->code_gen_ptr, (void *)
            ROUND_UP((uintptr_t)tcg_ctx->code_gen_ptr, CODE_GEN_ALIGN));

    for (uint32_t i = 0; i < tb_num_in_tu; i++) {
        tu_data->curr_num = i;
        tb = tb_list[i];
        lata_tu_tb_reset_edges(tb);
        if (tb->next_tb[TU_TB_INDEX_NEXT]) {
            lata_tu_edge_set_target(tb, TU_TB_INDEX_NEXT,
                                    tb->next_tb[TU_TB_INDEX_NEXT]);
        }
        if (tb->next_tb[TU_TB_INDEX_TARGET]) {
            lata_tu_edge_set_target(tb, TU_TB_INDEX_TARGET,
                                    tb->next_tb[TU_TB_INDEX_TARGET]);
        }
        gen_code_size = translate_tb_in_tu(tb);
        qatomic_set(&tcg_ctx->code_gen_ptr, (void *)ROUND_UP((uintptr_t)tcg_ctx->code_gen_ptr + gen_code_size, CODE_GEN_ALIGN));
        tb->tc.size = gen_code_size;
        tb->codesize = gen_code_size;
        tb->tc.offset_in_tu = tb->tc.ptr - tb_list[0]->tc.ptr;
        /* init original jump addresses which have been set during tcg_gen_code() */
        if (tb->jmp_reset_offset[0] != TB_JMP_OFFSET_INVALID) {
            tb_reset_jump(tb, 0);
        }
        if (tb->jmp_reset_offset[1] != TB_JMP_OFFSET_INVALID) {
            tb_reset_jump(tb, 1);
        }

    }

    lata_tu_move_unlink_stubs_to_cold_tail(tb_list, tb_num_in_tu);
    lata_tu_finalize_edges(tb_list, tb_num_in_tu);

    uint32_t search_size = 0;
    for (int i = 0; i < tb_num_in_tu; i++) {
        tb = tb_list[i];
        search_buff_offset[i] = search_size;
        search_size += encode_search(tb, (void *)(tcg_ctx->tb_gen_tail) +
                                     search_buff_offset[i]);
        tb->tu_search_addr = (uint8_t *)
            ((void *)(tcg_ctx->tb_gen_tail) + search_buff_offset[i]);
        lata_fast_jmp_cache_add(tb->env, tb->pc, (uint64_t)(tb->tc.ptr));
    }
    tb_list[0]->s_data->tu_size = tcg_ctx->code_gen_ptr - tb_list[0]->tc.ptr;
    lata_debug_note_tu_generated(tb_num_in_tu, tb_list[0]->s_data->tu_size);
#ifndef CONFIG_TCG_INTERPRETER
    flush_idcache_range((uintptr_t)tb_list[0]->tc.ptr,
                        (uintptr_t)tcg_splitwx_to_rw(tb_list[0]->tc.ptr),
                        tb_list[0]->s_data->tu_size);
#endif

}

/* print tu if open in_asm/out_asm debug mode */
static void print_tu(CPUState *cpu, TranslationBlock **tb_list){
    uint32_t tb_num_in_tu = tu_data->tb_num;
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)
        && qemu_log_in_addr_range(tb_list[0]->pc)) {
        FILE *logfile = qemu_log_trylock();
        fprintf(logfile, "TU IN: %s\n", lookup_symbol(tb_list[0]->pc));
        fprintf(logfile, "-----------------------------------------\n");        
        for (int i = 0; i < tb_num_in_tu; i++) {
            target_disas(logfile, cpu, tb_list[i]->pc, tb_list[i]->size);
            fprintf(logfile, "-----------------------------------------\n");            
        }
        qemu_log_unlock(logfile);
    }

    if (qemu_loglevel_mask(CPU_LOG_TB_OUT_ASM) &&
        qemu_log_in_addr_range(tb_list[0]->pc)) {
        FILE *logfile = qemu_log_trylock();
        if (logfile) {
            int code_size = tb_list[0]->s_data->tu_size;
            // size_t chunk_start;
            // int insn = 0;

            /* Dump header and the first instruction */
            fprintf(logfile, "\n");
            fprintf(logfile, "TU OUT: [size=%d]\n", code_size);
            for (int i = 0; i < tb_num_in_tu; i++) {
                fprintf(logfile, "  -- tb%d: guest addr 0x%016" PRIx64 " \n",
                    i, (uint64_t)tb_list[i]->pc); 
                int gen_code_size = tb_list[i]->codesize;
                disas(logfile, tb_list[i]->tc.ptr, gen_code_size);                    

            }

            fprintf(logfile, "\n");
            qemu_log_unlock(logfile);
        }
    }
}

static void register_tu(TranslationBlock **tb_list,
		CPUState *cpu, int cflags)
{
    uint32_t tb_num_in_tu = tu_data->tb_num;
    for (int i = 0; i < tb_num_in_tu; i++) {
        TranslationBlock *tb = tb_list[i];
        if (tb->s_data->tu_tb_mode != TU_TB_MODE_BROKEN) {
            CPUArchState *env = cpu->env_ptr;
            tb_page_addr_t phys_pc;
            // tb_page_addr_t phys_page2;
            // target_ulong virt_page2;
            phys_pc = get_page_addr_code(env, tb->pc);
            if (phys_pc == -1) {
                /* Generate a one-shot TB with 1 insn in it */
                cflags = (cflags & ~CF_COUNT_MASK) | CF_LAST_IO | 1;
            }
            tb_set_page_addr0(tb, phys_pc);
            tb_set_page_addr1(tb, -1);
            if (phys_pc != -1) {
                tb_lock_page0(phys_pc);
            }
            // phys_page2 = -1;
            /* should inset TB to Qht */
            tb_link_page(tb);
            tcg_tb_insert(tb);
        }
    }

}

/* Called with mmap_lock held for user mode emulation.  */
TranslationBlock *tu_gen_code(CPUState *cpu,
                              target_ulong pc, uint64_t cs_base,
                              uint32_t flags, int cflags)
{
    TranslationBlock* entry;
    TranslationBlock** tb_list = tu_data->tb_list;

    assert_memory_lock();
    qemu_thread_jit_write();

    /* 1.Search all TBs in the function */
    entry = tb_explore(cpu, pc, cs_base, flags, cflags);
    /* 2.Translate TU*/
    translate_tu(tb_list);
    /* 3.Insert TBs in TU to QHT */
    register_tu(tb_list, cpu, cflags);
    print_tu(cpu, tb_list);
    lata_debug_dump_tu(cpu, tb_list, tu_data->tb_num);
    tu_trees_reset();
    return entry;
}
#endif
