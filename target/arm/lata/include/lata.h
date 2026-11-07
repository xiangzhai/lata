#ifndef _LATA_H_
#define _LATA_H_

#include <stdint.h>

#include "qemu/osdep.h"
#include "qemu/rcu.h"
#include "mem.h"
#include "ir2.h"
#include "la-append.h"
#include "lata-options.h"
#include "reg-alloc.h"
#include "macro-inst.h"

#include "tcg/tcg.h"
//#include "env.h"

#define B_STUB_SIZE 12
#define LATA_GPR_CACHE_MAX 3

typedef enum LataFAMMode {
    LATA_FAM_OFF = -1,
    LATA_FAM_SAFE = 0,
    LATA_FAM_FAST = 1,
} LataFAMMode;

struct LataFAMEntry {
    uint64_t pc;
    uint64_t cs_base;
    union {
        struct {
            uint32_t flags;
            uint32_t cflags;
        };
        uint64_t flags_cflags;
    };
    union {
        TranslationBlock *tb;
        void *host_ptr;
    };
};
typedef struct LataFAMEntry LataFAMEntry;

struct LataFAMCache {
    uint32_t size;
    uint32_t mask;
    TranslationBlock **fast_tbs;
    struct rcu_head rcu;
    LataFAMEntry entries[];
};
typedef struct LataFAMCache LataFAMCache;

typedef struct TRANSLATION_DATA {

    void *curr_tb; /* from QEMU */

    /* ir1 */
    // IR1_INST *curr_ir1_inst;
    // int curr_ir1_count;
    /* uint8       ir1_dump_threshold[MAX_IR1_NUM_PER_TB]; */

    /*  w_write_flag indicates whether a 32-bit register was written 
        before the current instruction, it should initialize to zero
        Each bit represents one general registers(w0-w31)
    */
    uint32_t w_write_flag;

    /* ir2 */
    IR2_INST *ir2_inst_array;
    int ir2_inst_num_max;
    int ir2_inst_num_current;
    int real_ir2_inst_num;

    /* the list of ir2 */
    IR2_INST *first_ir2;
    IR2_INST *last_ir2;

    /* label number */
    int label_num;

    /* temp reg */
    union {
        uint32 all_temp_status;
        struct {
            uint16 itemp_status;
            uint16 ftemp_status;
        };
    };

    struct {
        uint8_t guest_reg;
        uint8_t host_reg;
        bool valid;
        bool pinned;
    } gpr_cache[LATA_GPR_CACHE_MAX];

    /* TODO : support static translation */
    uint8 curr_ir1_skipped_eflags; /* these eflag calculation can be skipped */
                                   /* (because of flag pattern, etc) */
} TRANSLATION_DATA;


typedef struct ENV {
    void *cpu_state;            /* from QEMU,CPUArchState */
    TRANSLATION_DATA *tr_data;  /* from LATR */
} ENV;


void lata_tr_data_init(CPUArchState *env);
void tr_init(void*);
void tr_fini(void);

extern const int arm_la_map[];
extern const int arm_la_fmap[];
extern __thread TRANSLATION_DATA *tr_data;
extern __thread ENV *lsenv;
extern bool lata_dump;

extern uint64_t context_switch_bt_to_native;
extern uint64_t context_switch_native_to_bt_ret_0;
extern uint64_t context_switch_native_to_bt;

int lata_gen_prologue(TCGContext *tcg_ctx);
int lata_gen_epilogue(TCGContext *tcg_ctx);
bool lata_fam_init(CPUArchState *env);
void lata_fam_destroy(CPUArchState *env);
void lata_fam_clear_all(CPUArchState *env);
void lata_fam_clear_all_cpus(void);
void lata_fam_clear_page(CPUArchState *env, uint64_t page_addr);
void lata_fam_add_tb(CPUArchState *env, TranslationBlock *tb);
void lata_fam_invalidate_tb(CPUArchState *env, TranslationBlock *tb);
TranslationBlock *lata_fam_lookup_tb(CPUArchState *env, uint64_t pc,
                                     uint64_t cs_base, uint32_t flags,
                                     uint32_t cflags);
void lata_fam_prelink_tb(TranslationBlock *tb);

int tr_ir2_assemble(const void *code_start_addr, int max_bytes);
void label_dispose(void);

void lata_gen_call_helper_prologue(TCGContext *tcg_ctx);
void lata_gen_call_helper_epilogue(TCGContext *tcg_ctx);
void lata_gen_call_helper_prologue_no_flags(TCGContext *tcg_ctx);
void lata_gen_call_helper_epilogue_no_flags(TCGContext *tcg_ctx);

IR2_OPND alloc_gpr_src(int i);
IR2_OPND alloc_gpr_src_sp(int i);
/* Read-only source allocators may return a shared clean cache entry. */
IR2_OPND alloc_gpr_src_ro(int i);
IR2_OPND alloc_gpr_src_sp_ro(int i);
IR2_OPND alloc_gpr_dst(int i);
IR2_OPND alloc_gpr_dst_sp(int i);
void store_gpr_dst(int i, IR2_OPND opnd);
void store_gpr_zero(int i);
void free_alloc_gpr(IR2_OPND opnd);
void lata_gpr_cache_reset(void);
void lata_gpr_cache_flush_all(void);
void lata_gpr_cache_end_insn(void);
bool lata_gpr_cache_owns_opnd(IR2_OPND opnd);
bool lata_gpr_cache_adopt_clean(int i, IR2_OPND opnd);
bool lata_gpr_cache_reclaim(void);

IR2_OPND alloc_fpr_src(int i);
IR2_OPND alloc_fpr_dst(int i);
void store_fpr_dst(int i, IR2_OPND opnd);
void free_alloc_fpr(IR2_OPND opnd);
void lata_vec_dirty_reset(void);
void lata_vec_mark_dirty(unsigned reg, unsigned size);
void lata_vec_mark_clean(unsigned reg);
void lata_vec_materialize_dirty(unsigned reg);
void lata_vec_materialize_all_dirty(void);

#endif
