#ifndef LATA_DATAFLOW_H
#define LATA_DATAFLOW_H

#include <stdint.h>
#include <stdbool.h>

#include "exec/translation-block.h"
#include "target/arm/tcg/translate.h"
#include "target/arm/lata/include/dataflow-lifecycle.h"

typedef struct LataIR1Facts {
    uint32_t gpr_use;
    uint32_t gpr_x_use;
    uint32_t gpr_def;
    uint32_t gpr_wdef;
    uint32_t vec_use;
    uint32_t vec_def;
    uint32_t vec_high_use[4];
    uint32_t vec_high_def[4];
    uint8_t nzcv_use;
    uint8_t nzcv_def;
    bool helper_boundary;
    bool state_boundary;
} LataIR1Facts;

typedef struct LataIR1DF {
    LataIR1Facts fact;
    uint32_t gpr_live_after;
    uint32_t gpr_x_live_after;
    uint32_t vec_live_after;
    uint32_t vec_high_live_after[4];
    uint32_t vec_high_local_live_after[4];
    uint8_t nzcv_live_after;
} LataIR1DF;

void lata_df_analyze_tb(TranslationBlock *tb);

#ifdef CONFIG_LATA_TU
void lata_df_analyze_tu(TranslationBlock **tb_list, uint32_t tb_count);
#endif

void lata_df_begin_translate(TranslationBlock *tb);
void lata_df_end_translate(void);
void lata_df_advance_insn(void);
void lata_df_mark_helper_boundary(void);
bool lata_df_reg_live_after(unsigned reg);
bool lata_df_reg_high_live_after_write(unsigned reg);
bool lata_df_vec_high_live_after_write(unsigned reg, unsigned size);
bool lata_df_vec_high_local_live_after_write(unsigned reg, unsigned size);
bool lata_df_should_save_nzcv_for_edge(TranslationBlock *tb, unsigned edge);

#ifdef CONFIG_LATA_DEBUG
void lata_df_dump_tb(TranslationBlock *tb);
void lata_df_dump_ir1_facts(TranslationBlock *tb);
#else
static inline void lata_df_dump_tb(TranslationBlock *tb) {}
static inline void lata_df_dump_ir1_facts(TranslationBlock *tb) {}
#endif

#endif
