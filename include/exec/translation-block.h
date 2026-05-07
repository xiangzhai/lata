/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Definition of TranslationBlock.
 *  Copyright (c) 2003 Fabrice Bellard
 */

#ifndef EXEC_TRANSLATION_BLOCK_H
#define EXEC_TRANSLATION_BLOCK_H

#include "qemu/atomic.h"
#include "qemu/thread.h"
#include "qemu/interval-tree.h"
#include "exec/cpu-common.h"
#include "exec/target_page.h"

/*
 * Page tracking code uses ram addresses in system mode, and virtual
 * addresses in userspace mode.  Define tb_page_addr_t to be an
 * appropriate type.
 */
#if defined(CONFIG_USER_ONLY)
typedef vaddr tb_page_addr_t;
#define TB_PAGE_ADDR_FMT "%" VADDR_PRIx
#else
typedef ram_addr_t tb_page_addr_t;
#define TB_PAGE_ADDR_FMT RAM_ADDR_FMT
#endif

/*
 * Translation Cache-related fields of a TB.
 * This struct exists just for convenience; we keep track of TB's in a binary
 * search tree, and the only fields needed to compare TB's in the tree are
 * @ptr and @size.
 * Note: the address of search data can be obtained by adding @size to @ptr.
 */
struct tb_tc {
    const void *ptr;    /* pointer to the translated code */
    size_t size;
#ifdef CONFIG_LATA_TU
    size_t offset_in_tu;
#endif
};

#ifdef CONFIG_LATA_TU
#define TU_TB_INDEX_NEXT 0
#define TU_TB_INDEX_TARGET 1
#define TU_UNLINK_STUB_INVALID 0xffffffff /* TU no unlink stub. */
#define LATA_TU_EDGE_OFFSET_INVALID 0xffffffff

typedef struct TranslationBlock TranslationBlock;

typedef enum tu_tb_mode_type {
    TU_TB_MODE_NONE = 0,
    TU_TB_MODE_SWITCH_TO_TB,
    TU_TB_MODE_BROKEN,
    TU_TB_MODE_STATIC,
    TB_GEN_CODE,
} tu_tb_mode_type;

struct separated_data{
    tu_tb_mode_type tu_tb_mode;
    union {
        int is_first_tb;
        int tu_size;
    };
    uint64_t tu_id;
};

typedef enum AARCH64_TYPE {
    IR1_TYPE_NORMAL = 0,
    IR1_TYPE_BRANCH,
    IR1_TYPE_CALL,
    IR1_TYPE_CALLIN,
    IR1_TYPE_JMP,
    IR1_TYPE_JMPIN,
    IR1_TYPE_RET,
    IR1_TYPE_SYSCALL,
} AARCH64_TYPE;

typedef enum LataTUEdgeKind {
    LATA_TU_EDGE_NONE = 0,
    LATA_TU_EDGE_NEXT,
    LATA_TU_EDGE_TARGET,
} LataTUEdgeKind;

typedef enum LataTUBranchKind {
    LATA_TU_BRANCH_NONE = 0,
    LATA_TU_BRANCH_B,
    LATA_TU_BRANCH_BCC16,
    LATA_TU_BRANCH_BCC20,
} LataTUBranchKind;

typedef enum LataTUEdgeState {
    LATA_TU_EDGE_EMPTY = 0,
    LATA_TU_EDGE_EMITTED,
    LATA_TU_EDGE_LINKED,
    LATA_TU_EDGE_UNLINKED,
    LATA_TU_EDGE_RELINK_PENDING,
} LataTUEdgeState;

typedef enum LataTUFallbackReason {
    LATA_TU_FALLBACK_NONE = 0,
    LATA_TU_FALLBACK_CROSS_PAGE,
    LATA_TU_FALLBACK_MODE_SWITCH,
    LATA_TU_FALLBACK_TARGET_NOT_TRANSLATABLE,
    LATA_TU_FALLBACK_EDGE_PC_MISMATCH,
    LATA_TU_FALLBACK_UNSUPPORTED_TERMINATOR,
    LATA_TU_FALLBACK_OVERLAP_SPLIT_FAILED,
    LATA_TU_FALLBACK_OVERLAP_PREFIX,
    LATA_TU_FALLBACK_MAX_TB_LIMIT,
    LATA_TU_FALLBACK_BRANCH_RANGE,
    LATA_TU_FALLBACK_ISLAND_RANGE,
    LATA_TU_FALLBACK_INVALID_TARGET,
    LATA_TU_FALLBACK_COUNT,
} LataTUFallbackReason;

typedef struct LataTUEdge {
    LataTUEdgeKind kind;
    LataTUBranchKind branch_kind;
    LataTUEdgeState state;
    LataTUFallbackReason fallback_reason;
    uint64_t guest_pc;
    TranslationBlock *target_tb;
    uint32_t branch_offset;
    uint32_t unlink_stub_offset;
    uint32_t branch_island_offset;
    uint32_t saved_insn;
    uint64_t fallback_guest_pc;
    uint32_t local_unlink_stub_offset;
} LataTUEdge;
#endif

struct TranslationBlock {
    /*
     * Guest PC corresponding to this block.  This must be the true
     * virtual address.  Therefore e.g. x86 stores EIP + CS_BASE, and
     * targets like Arm, MIPS, HP-PA, which reuse low bits for ISA or
     * privilege, must store those bits elsewhere.
     *
     * If CF_PCREL, the opcodes for the TranslationBlock are written
     * such that the TB is associated only with the physical page and
     * may be run in any virtual address context.  In this case, PC
     * must always be taken from ENV in a target-specific manner.
     * Unwind information is taken as offsets from the page, to be
     * deposited into the "current" PC.
     */
    vaddr pc;

    /*
     * Target-specific data associated with the TranslationBlock, e.g.:
     * x86: the original user, the Code Segment virtual base,
     * arm: an extension of tb->flags,
     * s390x: instruction data for EXECUTE,
     * sparc: the next pc of the instruction queue (for delay slots).
     */
    uint64_t cs_base;

    uint32_t flags; /* flags defining in which context the code was generated */
    uint32_t cflags;    /* compile flags */

/* Note that TCG_MAX_INSNS is 512; we validate this match elsewhere. */
#define CF_COUNT_MASK    0x000001ff
#define CF_NO_GOTO_TB    0x00000200 /* Do not chain with goto_tb */
#define CF_NO_GOTO_PTR   0x00000400 /* Do not chain with goto_ptr */
#define CF_SINGLE_STEP   0x00000800 /* gdbstub single-step in effect */
#define CF_LAST_IO       0x00008000 /* Last insn may be an IO access.  */
#define CF_MEMI_ONLY     0x00010000 /* Only instrument memory ops */
#define CF_USE_ICOUNT    0x00020000
#define CF_INVALID       0x00040000 /* TB is stale. Set with @jmp_lock held */
#define CF_PARALLEL      0x00080000 /* Generate code for a parallel context */
#define CF_NOIRQ         0x00100000 /* Generate an uninterruptible TB */
#define CF_PCREL         0x00200000 /* Opcodes in TB are PC-relative */
#define CF_CLUSTER_MASK  0xff000000 /* Top 8 bits are cluster ID */
#define CF_CLUSTER_SHIFT 24

    /*
     * Above fields used for comparing
     */

    /* size of target code for this block (1 <= size <= TARGET_PAGE_SIZE) */
    uint16_t size;
    uint16_t icount;

    struct tb_tc tc;

    /*
     * Track tb_page_addr_t intervals that intersect this TB.
     * For user-only, the virtual addresses are always contiguous,
     * and we use a unified interval tree.  For system, we use a
     * linked list headed in each PageDesc.  Within the list, the lsb
     * of the previous pointer tells the index of page_next[], and the
     * list is protected by the PageDesc lock(s).
     */
#ifdef CONFIG_USER_ONLY
    IntervalTreeNode itree;
#else
    uintptr_t page_next[2];
    tb_page_addr_t page_addr[2];
#endif

    /* jmp_lock placed here to fill a 4-byte hole. Its documentation is below */
    QemuSpin jmp_lock;

    /* The following data are used to directly call another TB from
     * the code of this one. This can be done either by emitting direct or
     * indirect native jump instructions. These jumps are reset so that the TB
     * just continues its execution. The TB can be linked to another one by
     * setting one of the jump targets (or patching the jump instruction). Only
     * two of such jumps are supported.
     */
#define TB_JMP_OFFSET_INVALID 0xffff /* indicates no jump generated */
    uint16_t jmp_reset_offset[2]; /* offset of original jump target */
    uint16_t jmp_insn_offset[2];  /* offset of direct jump insn */
    uintptr_t jmp_target_addr[2]; /* target address */
#ifdef CONFIG_LATA_INSTS_PATTERN
    uint16_t nzcv_save[2];
    bool nzcv_use;
#endif
    /*
     * Each TB has a NULL-terminated list (jmp_list_head) of incoming jumps.
     * Each TB can have two outgoing jumps, and therefore can participate
     * in two lists. The list entries are kept in jmp_list_next[2]. The least
     * significant bit (LSB) of the pointers in these lists is used to encode
     * which of the two list entries is to be used in the pointed TB.
     *
     * List traversals are protected by jmp_lock. The destination TB of each
     * outgoing jump is kept in jmp_dest[] so that the appropriate jmp_lock
     * can be acquired from any origin TB.
     *
     * jmp_dest[] are tagged pointers as well. The LSB is set when the TB is
     * being invalidated, so that no further outgoing jumps from it can be set.
     *
     * jmp_lock also protects the CF_INVALID cflag; a jump must not be chained
     * to a destination TB that has CF_INVALID set.
     */
    uintptr_t jmp_list_head;
    uintptr_t jmp_list_next[2];
    uintptr_t jmp_dest[2];
#ifdef CONFIG_LATA
    void *ir1;
    int codesize;
    TranslationBlock *lata_prelink_tb[2];
#endif
#ifdef CONFIG_LATA_TU
    uint64_t target_pc;
    uint64_t next_pc;
    bool tu_has_edges;
    LataTUFallbackReason tu_fallback_reason;
    LataTUEdge tu_edges[2];
    uint8_t *tu_search_addr;
    struct separated_data *s_data;
    TranslationBlock *next_tb[2];
    AARCH64_TYPE last_ir1_type;
    int isplit;
    CPUArchState *env;
#endif
#ifdef CONFIG_LATA
    void *lata_df_ir1;
    uint16_t lata_df_ir1_count;
    uint32_t lata_df_gpr_use;
    uint32_t lata_df_gpr_x_use;
    uint32_t lata_df_gpr_def;
    uint32_t lata_df_gpr_wdef;
    uint32_t lata_df_gpr_all_use;
    uint32_t lata_df_gpr_all_x_use;
    uint32_t lata_df_gpr_live_in;
    uint32_t lata_df_gpr_live_out;
    uint32_t lata_df_gpr_x_live_in;
    uint32_t lata_df_gpr_x_live_out;
    uint32_t lata_df_vec_use;
    uint32_t lata_df_vec_def;
    uint32_t lata_df_vec_live_in;
    uint32_t lata_df_vec_live_out;
    uint8_t lata_df_nzcv_use_mask;
    uint8_t lata_df_nzcv_def_mask;
    uint8_t lata_df_nzcv_live_in_mask;
    uint8_t lata_df_nzcv_live_out_mask;
    bool lata_df_nzcv_use;
    bool lata_df_nzcv_def;
    bool lata_df_nzcv_live_in;
    bool lata_df_nzcv_live_out;
    bool lata_df_helper_boundary;
    bool lata_df_state_boundary;
#endif
};

/* The alignment given to TranslationBlock during allocation. */
#define CODE_GEN_ALIGN  16

#endif /* EXEC_TRANSLATION_BLOCK_H */
