#include "qemu/osdep.h"

#include "disas/disas.h"
#include "exec/log.h"
#include "hw/core/cpu.h"
#include "qemu/qemu-print.h"
#include "target/arm/tcg/translate.h"
#include "target/arm/lata/include/lata.h"
#include "target/arm/lata/include/lata-debug.h"
#include "target/arm/lata/include/dataflow.h"
#include "target/arm/lata/include/ir2-peephole.h"

#if defined(CONFIG_LATA_DEBUG) || defined(CONFIG_LATA_PROFILE)
static const char *lata_fam_kind_name(LataFAMKind kind)
{
    switch (kind) {
    case LATA_FAM_KIND_BR:
        return "br";
    case LATA_FAM_KIND_BLR:
        return "blr";
    case LATA_FAM_KIND_RET_X30:
        return "ret-x30";
    case LATA_FAM_KIND_RET_XN:
        return "ret-xn";
    default:
        return "unknown";
    }
}

static void lata_profile_print_fam_stats(CPUArchState *env)
{
    uint64_t cnt = env->jr_cnt;
    uint64_t hit = env->jr_hit;
    double ratio = cnt ? (double)hit / cnt : 0.0;

    qemu_log("[LATA] indirect-jmp cnt=%" PRIu64 " hit=%" PRIu64
             " hit_ratio=%f\n", cnt, hit, ratio);
    for (int i = 0; i < LATA_FAM_KIND_COUNT; i++) {
        uint64_t lookups = env->fam_lookup_count[i];
        uint64_t hits = env->fam_hit_count[i];
        double fam_ratio = lookups ? (double)hits / lookups : 0.0;

        if (option_lata_fam_stats || lookups || env->fam_miss_count[i] ||
            env->fam_range_miss_count[i]) {
            qemu_log("[LATA] FAM %s lookup=%" PRIu64
                     " hit=%" PRIu64 " miss=%" PRIu64
                     " range_miss=%" PRIu64 " hit_ratio=%f\n",
                     lata_fam_kind_name(i), lookups, hits,
                     env->fam_miss_count[i],
                     env->fam_range_miss_count[i], fam_ratio);
        }
    }
}
#endif

#if !defined(CONFIG_LATA_DEBUG) && defined(CONFIG_LATA_PROFILE)
void lata_debug_print_stats(CPUState *cpu)
{
    CPUArchState *env = cpu ? cpu->env_ptr : NULL;

    if (indirect_jmp_opt_profile && env) {
        lata_profile_print_fam_stats(env);
    }
}
#endif

#ifdef CONFIG_LATA_DEBUG
typedef struct LataDebugStats {
    uint64_t fam_add;
    uint64_t ibtc_add;
    uint64_t tb_exec_count;
    uint64_t tu_boundary[LATA_TU_BOUNDARY_COUNT];
#ifdef CONFIG_LATA_TU
    uint64_t tu_count;
    uint64_t tu_tb_count;
    uint64_t tu_code_size;
    uint64_t tu_edge_linked;
    uint64_t tu_edge_unlinked;
    uint64_t tu_edge_relinked;
    uint64_t tu_fallback[LATA_TU_FALLBACK_COUNT];
#endif
} LataDebugStats;

static LataDebugStats lata_debug_stats;
typedef struct LataRuntimeTraceState {
    bool valid;
    uint64_t xregs[32];
    ARMVectorReg vregs[32];
    uint64_t pc;
    uint32_t pstate;
} LataRuntimeTraceState;

static __thread LataRuntimeTraceState lata_last_runtime_state;

static bool lata_debug_tb_matches(TranslationBlock *tb)
{
    return lata_debug_tb_pc != 0 && tb->pc == lata_debug_tb_pc;
}

static uint32_t lata_debug_nzcv_from_pstate(uint32_t pstate)
{
    return (pstate >> 28) & 0xf;
}

static void lata_debug_print_nzcv(FILE *file, uint32_t pstate)
{
    uint32_t nzcv = lata_debug_nzcv_from_pstate(pstate);

    fprintf(file, "NZCV=%u%u%u%u",
            (nzcv >> 3) & 1, (nzcv >> 2) & 1,
            (nzcv >> 1) & 1, nzcv & 1);
}

static void lata_debug_trace_disas(CPUARMState *env, uint64_t pc)
{
    CPUState *cpu = env_cpu(env);
    g_autofree char *text = NULL;

    text = plugin_disas(cpu, pc, sizeof(LataRuntimeTraceInsn));
    if (text && text[0]) {
        fprintf(stderr, "  disas: %s\n", text);
    }
}

static void lata_debug_trace_vector_regs(CPUARMState *env, bool *any)
{
    if (!option_lata_trace_vec) {
        return;
    }

    for (int i = 0; i < 32; i++) {
        ARMVectorReg *reg = &env->vfp.zregs[i];

        if (!(lata_trace_vec_mask & (1u << i))) {
            continue;
        }
        if (!lata_last_runtime_state.valid ||
            memcmp(reg, &lata_last_runtime_state.vregs[i], sizeof(*reg))) {
            fprintf(stderr, "  v%-2d = 0x%016" PRIx64 "%016" PRIx64 "\n",
                    i, reg->d[1], reg->d[0]);
            *any = true;
        }
        lata_last_runtime_state.vregs[i] = *reg;
    }
}

static void lata_debug_trace_ir1_list(TranslationBlock *tb)
{
    DisasContext *ir1 = tb->ir1;

    if (!ir1) {
        fprintf(stderr, "[LATA trace] IR1 list is empty\n");
        return;
    }

    fprintf(stderr, "[LATA trace] ir1_nr=%u\n", tb->icount);
    for (int i = 0; i < tb->icount; i++) {
        fprintf(stderr,
                "[LATA trace] IR1[%03d] pc=0x%016" PRIx64
                " insn=0x%08x type=%d\n",
                i, (uint64_t)ir1[i].pc_curr, ir1[i].insn,
                ir1[i].insn_type);
    }
}

void lata_debug_trace_before_exec(CPUState *cpu, TranslationBlock *tb)
{
    if (!option_lata_trace_tb && !option_lata_trace_ir1) {
        return;
    }

    lata_debug_stats.tb_exec_count++;

    if (option_lata_trace_tb) {
        fprintf(stderr,
                "[LATA trace] before TB exec count=%" PRIu64
                " tb=%p pc=0x%016" PRIx64 " host=%p size=%u host_size=%zu\n",
                lata_debug_stats.tb_exec_count, tb, (uint64_t)tb->pc,
                tb->tc.ptr, tb->size, tb->tc.size);
    }

    if (option_lata_trace_ir1) {
        lata_debug_trace_ir1_list(tb);
    }
}

void lata_debug_trace_after_exec(CPUState *cpu, TranslationBlock *tb,
                                 TranslationBlock *last_tb, int tb_exit)
{
    if (!option_lata_trace_tb) {
        return;
    }

    fprintf(stderr,
            "[LATA trace] after  TB exec tb=%p pc=0x%016" PRIx64
            " last_tb=%p last_pc=0x%016" PRIx64 " exit=%d\n",
            tb, (uint64_t)tb->pc, last_tb,
            last_tb ? (uint64_t)last_tb->pc : 0, tb_exit);
}

void lata_debug_check_break_insn(uint64_t pc, uint32_t insn, int insn_type)
{
    if (lata_break_insn == 0 || pc != lata_break_insn) {
        return;
    }

    fprintf(stderr,
            "[LATA break] pc=0x%016" PRIx64 " insn=0x%08x type=%d\n",
            pc, insn, insn_type);
    raise(SIGTRAP);
}

bool lata_debug_should_trace_runtime(uint64_t pc)
{
    if (!option_lata_trace_runtime) {
        return false;
    }

    if (lata_trace_begin_pc || lata_trace_end_pc) {
        if (lata_trace_begin_pc && pc < lata_trace_begin_pc) {
            return false;
        }
        if (lata_trace_end_pc && pc >= lata_trace_end_pc) {
            return false;
        }
    }

    return true;
}

void lata_debug_runtime_trace(void *opaque_env, uint64_t pc, uint32_t insn,
                              int insn_type)
{
    CPUARMState *env = opaque_env;
    bool any = false;

    fprintf(stderr,
            "[LATA runtime] pc=0x%016" PRIx64 " insn=0x%08x type=%d\n",
            pc, insn, insn_type);
    lata_debug_trace_disas(env, pc);

    if (!lata_last_runtime_state.valid) {
        fprintf(stderr, "[LATA runtime] initial state\n");
    }

    for (int i = 0; i < 31; i++) {
        uint64_t value = env->xregs[i];

        if (!lata_last_runtime_state.valid ||
            value != lata_last_runtime_state.xregs[i]) {
            fprintf(stderr, "  x%-2d = 0x%016" PRIx64 "\n", i, value);
            any = true;
        }
        lata_last_runtime_state.xregs[i] = value;
    }

    lata_last_runtime_state.xregs[31] = 0;
    if (!lata_last_runtime_state.valid ||
        env->pc != lata_last_runtime_state.pc) {
        fprintf(stderr, "  pc  = 0x%016" PRIx64 "\n", (uint64_t)env->pc);
        any = true;
    }
    if (!lata_last_runtime_state.valid ||
        env->pstate != lata_last_runtime_state.pstate) {
        fprintf(stderr, "  pstate = 0x%08x ", env->pstate);
        lata_debug_print_nzcv(stderr, env->pstate);
        fprintf(stderr, "\n");
        any = true;
    }
    lata_debug_trace_vector_regs(env, &any);
    if (lata_last_runtime_state.valid && !any) {
        fprintf(stderr, "  no architectural GPR/PSTATE changes\n");
    }

    lata_last_runtime_state.pc = env->pc;
    lata_last_runtime_state.pstate = env->pstate;
    lata_last_runtime_state.valid = true;
}

void lata_debug_trace_mem_store(uint64_t pc, uint64_t addr, uint32_t size,
                                uint32_t is_vector)
{
    if (!lata_trace_mem || addr != lata_trace_mem) {
        return;
    }

    fprintf(stderr,
            "[LATA trace-mem] store pc=0x%016" PRIx64
            " addr=0x%016" PRIx64 " size=%u%s\n",
            pc, addr, size, is_vector ? " vector" : "");
}

void lata_debug_begin_tb(TranslationBlock *tb, LataDebugDumpState *state)
{
    state->active = false;
    state->dump = option_lata_dump;
    state->ir1 = option_lata_dump_ir1;
    state->ir2 = option_lata_dump_ir2;
    state->host = option_lata_dump_host;
    state->tu = option_lata_dump_tu;

    if (!lata_debug_tb_matches(tb)) {
        return;
    }

    state->active = true;
    option_lata_dump = 1;
    option_lata_dump_ir1 = 1;
    option_lata_dump_ir2 = 1;
    option_lata_dump_host = 1;
}

void lata_debug_end_tb(const LataDebugDumpState *state)
{
    if (!state->active) {
        return;
    }

    option_lata_dump = state->dump;
    option_lata_dump_ir1 = state->ir1;
    option_lata_dump_ir2 = state->ir2;
    option_lata_dump_host = state->host;
    option_lata_dump_tu = state->tu;
}

void lata_debug_dump_ir1(TranslationBlock *tb)
{
    CPUState *cpu = tcg_ctx->cpu;
    DisasContext *ir1 = tb->ir1;

    qemu_log("\n[LATA] TB IR1 pc=0x%016" PRIx64 " size=%u icount=%u\n",
             (uint64_t)tb->pc, tb->size, tb->icount);

    FILE *logfile = qemu_log_trylock();
    if (logfile) {
        if (cpu && tb->icount) {
            fprintf(logfile, "[LATA] Guest disassembly\n");
            fprintf(logfile, "-----------------------------------------\n");
            target_disas(logfile, cpu, tb->pc, tb->size);
            fprintf(logfile, "-----------------------------------------\n");
        }
        qemu_log_unlock(logfile);
    }

    if (!ir1) {
        qemu_log("[LATA] IR1 list is empty\n");
        return;
    }

    for (int i = 0; i < tb->icount; i++) {
        qemu_log("IR1[%03d] pc=0x%016" PRIx64 " insn=0x%08x type=%d\n",
                 i, (uint64_t)ir1[i].pc_curr, ir1[i].insn, ir1[i].insn_type);
    }
    lata_df_dump_tb(tb);
    lata_df_dump_ir1_facts(tb);
}

void lata_debug_dump_ir2(void)
{
    IR2_INST *ir2 = lsenv->tr_data->first_ir2;

    qemu_log("\n[LATA] TB IR2\n");
    while (ir2) {
        ir2_dump(ir2);
        ir2 = ir2_next(ir2);
    }
}

void lata_debug_dump_host(TranslationBlock *tb, const void *code, size_t code_size)
{
    FILE *logfile;

    qemu_log("\n[LATA] TB host pc=0x%016" PRIx64 " code=%p size=%zu\n",
             (uint64_t)tb->pc, code, code_size);

    logfile = qemu_log_trylock();
    if (!logfile) {
        return;
    }

    disas(logfile, code, code_size);
    qemu_log_unlock(logfile);
}

void lata_debug_dump_assembled_ir2(int ir2_id, const void *addr, uint32_t raw,
                                   IR2_INST *ir2)
{
    qemu_log("IR2[%03d] at %p 0x%08x\n", ir2_id, addr, raw);
    ir2_dump(ir2);
}

#ifdef CONFIG_LATA_TU
static const char *lata_tu_boundary_kind_name(LataTUBoundaryKind kind)
{
    switch (kind) {
    case LATA_TU_BOUNDARY_BR:
        return "br";
    case LATA_TU_BOUNDARY_BLR:
        return "blr";
    case LATA_TU_BOUNDARY_RET:
        return "ret";
    case LATA_TU_BOUNDARY_SVC:
        return "svc";
    case LATA_TU_BOUNDARY_OTHER:
        return "other";
    default:
        return "unknown";
    }
}


static const char *lata_tu_edge_state_name(LataTUEdgeState state)
{
    switch (state) {
    case LATA_TU_EDGE_EMPTY:
        return "empty";
    case LATA_TU_EDGE_EMITTED:
        return "emitted";
    case LATA_TU_EDGE_LINKED:
        return "linked";
    case LATA_TU_EDGE_UNLINKED:
        return "unlinked";
    case LATA_TU_EDGE_RELINK_PENDING:
        return "relink-pending";
    default:
        return "unknown";
    }
}

static const char *lata_tu_branch_kind_name(LataTUBranchKind kind)
{
    switch (kind) {
    case LATA_TU_BRANCH_NONE:
        return "none";
    case LATA_TU_BRANCH_B:
        return "b";
    case LATA_TU_BRANCH_BCC16:
        return "bcc16";
    case LATA_TU_BRANCH_BCC20:
        return "bcc20";
    default:
        return "unknown";
    }
}

static const char *lata_tu_fallback_reason_name(LataTUFallbackReason reason)
{
    switch (reason) {
    case LATA_TU_FALLBACK_NONE:
        return "none";
    case LATA_TU_FALLBACK_CROSS_PAGE:
        return "cross-page";
    case LATA_TU_FALLBACK_MODE_SWITCH:
        return "mode-switch";
    case LATA_TU_FALLBACK_TARGET_NOT_TRANSLATABLE:
        return "target-not-translatable";
    case LATA_TU_FALLBACK_EDGE_PC_MISMATCH:
        return "edge-pc-mismatch";
    case LATA_TU_FALLBACK_UNSUPPORTED_TERMINATOR:
        return "unsupported-terminator";
    case LATA_TU_FALLBACK_OVERLAP_SPLIT_FAILED:
        return "overlap-split-failed";
    case LATA_TU_FALLBACK_OVERLAP_PREFIX:
        return "overlap-prefix";
    case LATA_TU_FALLBACK_MAX_TB_LIMIT:
        return "max-tb-limit";
    case LATA_TU_FALLBACK_BRANCH_RANGE:
        return "branch-range";
    case LATA_TU_FALLBACK_ISLAND_RANGE:
        return "island-range";
    case LATA_TU_FALLBACK_INVALID_TARGET:
        return "invalid-target";
    default:
        return "unknown";
    }
}

static void lata_debug_dump_tu_edge(TranslationBlock *tb, int n)
{
    LataTUEdge *edge = &tb->tu_edges[n];
    const char *name = n == TU_TB_INDEX_NEXT ? "next" : "target";
    TranslationBlock *target = tb->next_tb[n];

    qemu_log("    %s edge: guest=0x%016" PRIx64 " target_tb=%p "
             "target_pc=0x%016" PRIx64 " state=%s branch=%s "
             "branch_off=0x%x unlink_off=0x%x "
             "island_off=0x%x fallback=0x%016" PRIx64 " reason=%s\n",
             name, edge->guest_pc, edge->target_tb,
             target ? (uint64_t)target->pc : 0,
             lata_tu_edge_state_name(edge->state),
             lata_tu_branch_kind_name(edge->branch_kind),
             edge->branch_offset, edge->unlink_stub_offset,
             edge->branch_island_offset, edge->fallback_guest_pc,
             lata_tu_fallback_reason_name(edge->fallback_reason));
}

static gint lata_debug_cmp_tb_pc(gconstpointer a, gconstpointer b)
{
    const TranslationBlock *ta = *(TranslationBlock * const *)a;
    const TranslationBlock *tb = *(TranslationBlock * const *)b;

    return ta->pc > tb->pc ? 1 : ta->pc < tb->pc ? -1 : 0;
}

void lata_debug_dump_tu(CPUState *cpu, TranslationBlock **tb_list,
                        uint32_t tb_count)
{
    if (!option_lata_dump_tu || tb_count == 0) {
        return;
    }

    qemu_log("\n[LATA] TU pc=0x%016" PRIx64 " tb_count=%u code_size=%u\n",
             (uint64_t)tb_list[0]->pc, tb_count, tb_list[0]->s_data->tu_size);

    g_autofree TranslationBlock **pc_order =
        g_new(TranslationBlock *, tb_count);
    memcpy(pc_order, tb_list, sizeof(*pc_order) * tb_count);
    g_qsort_with_data(pc_order, tb_count, sizeof(*pc_order),
                      (GCompareDataFunc)lata_debug_cmp_tb_pc, NULL);

    qemu_log("  TU pc-order:");
    for (uint32_t i = 0; i < tb_count; i++) {
        qemu_log(" [%u]=0x%016" PRIx64, i, (uint64_t)pc_order[i]->pc);
    }
    qemu_log("\n");

    for (uint32_t i = 0; i < tb_count; i++) {
        TranslationBlock *tb = tb_list[i];

        qemu_log("  tb[%02u] pc=0x%016" PRIx64 " size=%u icount=%u "
                 "host=%p code_size=%u tu_off=0x%zx flags=0x%x cflags=0x%x "
                 "cs_base=0x%016" PRIx64 " last_ir1_type=%d "
                 "next_pc=0x%016" PRIx64 " target_pc=0x%016" PRIx64
                 " mode=%d fallback=%s\n",
                 i, (uint64_t)tb->pc, tb->size, tb->icount, tb->tc.ptr,
                 tb->codesize, tb->tc.offset_in_tu, tb->flags, tb->cflags,
                 (uint64_t)tb->cs_base, tb->last_ir1_type, tb->next_pc,
                 tb->target_pc, tb->s_data->tu_tb_mode,
                 lata_tu_fallback_reason_name(tb->tu_fallback_reason));
        lata_df_dump_tb(tb);
        lata_debug_dump_tu_edge(tb, TU_TB_INDEX_NEXT);
        lata_debug_dump_tu_edge(tb, TU_TB_INDEX_TARGET);
    }

    if (option_lata_dump_host) {
        FILE *logfile = qemu_log_trylock();
        if (logfile) {
            fprintf(logfile, "[LATA] TU host disassembly\n");
            for (uint32_t i = 0; i < tb_count; i++) {
                TranslationBlock *tb = tb_list[i];

                fprintf(logfile, "  -- tb[%02u] guest=0x%016" PRIx64
                        " host=%p size=%u\n",
                        i, (uint64_t)tb->pc, tb->tc.ptr, tb->codesize);
                disas(logfile, tb->tc.ptr, tb->codesize);
            }
            qemu_log_unlock(logfile);
        }
    }

    if (option_lata_dump_ir1 && cpu) {
        FILE *logfile = qemu_log_trylock();
        if (logfile) {
            fprintf(logfile, "[LATA] TU guest disassembly\n");
            for (uint32_t i = 0; i < tb_count; i++) {
                TranslationBlock *tb = tb_list[i];

                fprintf(logfile, "  -- tb[%02u] guest=0x%016" PRIx64
                        " size=%u\n",
                        i, (uint64_t)tb->pc, tb->size);
                target_disas(logfile, cpu, tb->pc, tb->size);
            }
            qemu_log_unlock(logfile);
        }
    }
}

void lata_debug_note_tu_generated(uint32_t tb_count, uint32_t code_size)
{
    lata_debug_stats.tu_count++;
    lata_debug_stats.tu_tb_count += tb_count;
    lata_debug_stats.tu_code_size += code_size;
}

void lata_debug_note_tu_edge_linked(void)
{
    lata_debug_stats.tu_edge_linked++;
}

void lata_debug_note_tu_edge_unlinked(void)
{
    lata_debug_stats.tu_edge_unlinked++;
}

void lata_debug_note_tu_edge_relinked(void)
{
    lata_debug_stats.tu_edge_relinked++;
}

void lata_debug_note_tu_fallback(LataTUFallbackReason reason)
{
    if (reason > LATA_TU_FALLBACK_NONE &&
        reason < LATA_TU_FALLBACK_COUNT) {
        lata_debug_stats.tu_fallback[reason]++;
    }
}

void lata_debug_trace_tu_edge_state(TranslationBlock *tb, int n,
                                    LataTUEdgeState old_state,
                                    LataTUEdgeState new_state,
                                    const char *reason)
{
    const char *edge_name = n == TU_TB_INDEX_NEXT ? "next" : "target";

    if (!option_lata_dump_tu || old_state == new_state) {
        return;
    }

    qemu_log("[LATA] TU edge-state pc=0x%016" PRIx64 " %s %s->%s %s\n",
             tb ? (uint64_t)tb->pc : 0, edge_name,
             lata_tu_edge_state_name(old_state),
             lata_tu_edge_state_name(new_state), reason ? reason : "");
}
#endif

void lata_debug_note_tu_boundary(LataTUBoundaryKind kind)
{
    if (kind < LATA_TU_BOUNDARY_COUNT) {
        lata_debug_stats.tu_boundary[kind]++;
    }
}

void lata_debug_note_fam_add(bool full_assoc)
{
    if (full_assoc) {
        lata_debug_stats.fam_add++;
    } else {
        lata_debug_stats.ibtc_add++;
    }
}

void lata_debug_print_stats(CPUState *cpu)
{
    CPUArchState *env = cpu ? cpu->env_ptr : NULL;
    bool profile_stats = false;

#ifdef CONFIG_LATA_PROFILE
    profile_stats = indirect_jmp_opt_profile;
#endif
    if (profile_stats && env) {
        lata_profile_print_fam_stats(env);
        qemu_log("[LATA] jump-cache fam_add=%" PRIu64 " ibtc_add=%" PRIu64 "\n",
                 lata_debug_stats.fam_add, lata_debug_stats.ibtc_add);
    } else if (option_lata_dump || option_lata_dump_tu ||
               option_lata_fam_stats) {
        if (option_lata_fam_stats && env) {
            lata_profile_print_fam_stats(env);
        }
        qemu_log("[LATA] jump-cache fam_add=%" PRIu64 " ibtc_add=%" PRIu64 "\n",
                 lata_debug_stats.fam_add, lata_debug_stats.ibtc_add);
    }

#ifdef CONFIG_LATA_TU
    if (option_lata_dump || option_lata_dump_tu ||
        option_lata_tu_stats || profile_stats) {
        qemu_log("[LATA] TU stats count=%" PRIu64 " tb_count=%" PRIu64
                 " code_size=%" PRIu64 " edge_linked=%" PRIu64
                 " edge_unlinked=%" PRIu64 " edge_relinked=%" PRIu64 "\n",
                 lata_debug_stats.tu_count, lata_debug_stats.tu_tb_count,
                 lata_debug_stats.tu_code_size,
                 lata_debug_stats.tu_edge_linked,
                 lata_debug_stats.tu_edge_unlinked,
                 lata_debug_stats.tu_edge_relinked);
        for (int i = LATA_TU_FALLBACK_NONE + 1;
             i < LATA_TU_FALLBACK_COUNT; i++) {
            if (lata_debug_stats.tu_fallback[i]) {
                qemu_log("[LATA] TU fallback %s=%" PRIu64 "\n",
                         lata_tu_fallback_reason_name(i),
                         lata_debug_stats.tu_fallback[i]);
            }
        }
        for (int i = 0; i < LATA_TU_BOUNDARY_COUNT; i++) {
            if (lata_debug_stats.tu_boundary[i]) {
                qemu_log("[LATA] TU boundary %s=%" PRIu64 "\n",
                         lata_tu_boundary_kind_name(i),
                         lata_debug_stats.tu_boundary[i]);
            }
        }
    }
#endif

    lata_ir2_peephole_dump_stats();
}
#endif
