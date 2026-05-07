#ifndef LATA_DEBUG_H
#define LATA_DEBUG_H

#include <stdbool.h>
#include <stddef.h>

#include "exec/translation-block.h"
#include "ir2.h"

typedef struct LataDebugDumpState {
    bool active;
    int dump;
    int ir1;
    int ir2;
    int host;
    int tu;
} LataDebugDumpState;

typedef struct LataRuntimeTraceInsn {
    uint32_t insn;
} LataRuntimeTraceInsn;

typedef enum LataTUBoundaryKind {
    LATA_TU_BOUNDARY_BR = 0,
    LATA_TU_BOUNDARY_BLR,
    LATA_TU_BOUNDARY_RET,
    LATA_TU_BOUNDARY_SVC,
    LATA_TU_BOUNDARY_OTHER,
    LATA_TU_BOUNDARY_COUNT,
} LataTUBoundaryKind;

typedef enum LataFAMKind {
    LATA_FAM_KIND_BR = 0,
    LATA_FAM_KIND_BLR,
    LATA_FAM_KIND_RET_X30,
    LATA_FAM_KIND_RET_XN,
    LATA_FAM_KIND_COUNT,
} LataFAMKind;

typedef enum LataFAMMissReason {
    LATA_FAM_MISS_EMPTY = 0,
    LATA_FAM_MISS_KEY,
    LATA_FAM_MISS_INVALID,
    LATA_FAM_MISS_UNSUPPORTED,
} LataFAMMissReason;

#ifdef CONFIG_LATA_DEBUG
void lata_debug_begin_tb(TranslationBlock *tb, LataDebugDumpState *state);
void lata_debug_end_tb(const LataDebugDumpState *state);
void lata_debug_dump_ir1(TranslationBlock *tb);
void lata_debug_dump_ir2(void);
void lata_debug_dump_host(TranslationBlock *tb, const void *code, size_t code_size);
void lata_debug_dump_assembled_ir2(int ir2_id, const void *addr, uint32_t raw,
                                   IR2_INST *ir2);
void lata_debug_trace_before_exec(CPUState *cpu, TranslationBlock *tb);
void lata_debug_trace_after_exec(CPUState *cpu, TranslationBlock *tb,
                                 TranslationBlock *last_tb, int tb_exit);
void lata_debug_check_break_insn(uint64_t pc, uint32_t insn, int insn_type);
bool lata_debug_should_trace_runtime(uint64_t pc);
void lata_debug_runtime_trace(void *env, uint64_t pc, uint32_t insn,
                              int insn_type);
void lata_debug_trace_mem_store(uint64_t pc, uint64_t addr, uint32_t size,
                                uint32_t is_vector);
void lata_debug_note_tu_boundary(LataTUBoundaryKind kind);

#ifdef CONFIG_LATA_TU
void lata_debug_dump_tu(CPUState *cpu, TranslationBlock **tb_list,
                        uint32_t tb_count);
void lata_debug_note_tu_generated(uint32_t tb_count, uint32_t code_size);
void lata_debug_note_tu_edge_linked(void);
void lata_debug_note_tu_edge_unlinked(void);
void lata_debug_note_tu_edge_relinked(void);
void lata_debug_note_tu_fallback(LataTUFallbackReason reason);
void lata_debug_trace_tu_edge_state(TranslationBlock *tb, int n,
                                    LataTUEdgeState old_state,
                                    LataTUEdgeState new_state,
                                    const char *reason);
#endif

void lata_debug_note_fam_add(bool full_assoc);
void lata_debug_note_fam_invalidate(void);
void lata_debug_note_fam_clear_all(void);
void lata_debug_note_fam_overwrite(void);
void lata_debug_print_stats(CPUState *cpu);
#else
static inline void lata_debug_begin_tb(TranslationBlock *tb,
                                       LataDebugDumpState *state)
{
    state->active = false;
}

static inline void lata_debug_end_tb(const LataDebugDumpState *state) {}
static inline void lata_debug_dump_ir1(TranslationBlock *tb) {}
static inline void lata_debug_dump_ir2(void) {}
static inline void lata_debug_dump_host(TranslationBlock *tb, const void *code,
                                        size_t code_size) {}
static inline void lata_debug_dump_assembled_ir2(int ir2_id, const void *addr,
                                                 uint32_t raw, IR2_INST *ir2) {}
static inline void lata_debug_trace_before_exec(CPUState *cpu,
                                                TranslationBlock *tb) {}
static inline void lata_debug_trace_after_exec(CPUState *cpu,
                                               TranslationBlock *tb,
                                               TranslationBlock *last_tb,
                                               int tb_exit) {}
static inline void lata_debug_check_break_insn(uint64_t pc, uint32_t insn,
                                               int insn_type) {}
static inline bool lata_debug_should_trace_runtime(uint64_t pc)
{
    return false;
}
static inline void lata_debug_runtime_trace(void *env, uint64_t pc,
                                            uint32_t insn, int insn_type) {}
static inline void lata_debug_trace_mem_store(uint64_t pc, uint64_t addr,
                                              uint32_t size,
                                              uint32_t is_vector) {}
static inline void lata_debug_note_tu_boundary(LataTUBoundaryKind kind) {}

#ifdef CONFIG_LATA_TU
static inline void lata_debug_dump_tu(CPUState *cpu,
                                      TranslationBlock **tb_list,
                                      uint32_t tb_count) {}
static inline void lata_debug_note_tu_generated(uint32_t tb_count,
                                                uint32_t code_size) {}
static inline void lata_debug_note_tu_edge_linked(void) {}
static inline void lata_debug_note_tu_edge_unlinked(void) {}
static inline void lata_debug_note_tu_edge_relinked(void) {}
static inline void lata_debug_note_tu_fallback(LataTUFallbackReason reason) {}
static inline void lata_debug_trace_tu_edge_state(TranslationBlock *tb, int n,
                                                  LataTUEdgeState old_state,
                                                  LataTUEdgeState new_state,
                                                  const char *reason) {}
#endif

static inline void lata_debug_note_fam_add(bool full_assoc) {}
static inline void lata_debug_note_fam_invalidate(void) {}
static inline void lata_debug_note_fam_clear_all(void) {}
static inline void lata_debug_note_fam_overwrite(void) {}
#ifndef CONFIG_LATA_PROFILE
static inline void lata_debug_print_stats(CPUState *cpu) {}
#endif
#endif

#if !defined(CONFIG_LATA_DEBUG) && defined(CONFIG_LATA_PROFILE)
void lata_debug_print_stats(CPUState *cpu);
#endif

#endif
