#ifndef LATA_OPTIONS_H
#define LATA_OPTIONS_H

#include "qemu/osdep.h"

#ifdef CONFIG_LATA_PROFILE
extern int indirect_jmp_opt_profile;
#endif
extern int option_fam_jmp_cache;
extern int option_fp_precise;

extern int option_lata_dump;
extern int option_lata_dump_ir1;
extern int option_lata_dump_ir2;
extern int option_lata_dump_host;
extern int option_lata_dump_tu;
extern int option_lata_trace_tb;
extern int option_lata_trace_ir1;
extern int option_lata_trace_runtime;
extern int option_lata_trace_vec;
extern int option_lata_dataflow_opt;
extern int option_lata_tu_stats;
extern int option_lata_fam_stats;
extern int option_lata_peephole_stats;

extern uint64_t lata_debug_tb_pc;
extern uint64_t lata_trace_mem;
extern uint64_t lata_break_insn;
extern uint64_t lata_unlink_count;
extern uint32_t lata_unlink_cpu;
extern uint64_t lata_trace_begin_pc;
extern uint64_t lata_trace_end_pc;
extern uint32_t lata_trace_vec_mask;

void lata_options_init(void);
void lata_options_parse_dump(const char *arg);
void lata_options_parse_trace(const char *arg);
void lata_options_parse_show_tb(const char *arg);
void lata_options_parse_trace_mem(const char *arg);
void lata_options_parse_break_insn(const char *arg);
void lata_options_parse_unlink(const char *arg);
void lata_options_parse_trace_begin(const char *arg);
void lata_options_parse_trace_end(const char *arg);
void lata_options_parse_trace_pc(const char *arg);
void lata_options_parse_trace_vec(const char *arg);
void lata_options_parse_fp_precise(const char *arg);
void lata_options_parse_dataflow_opt(const char *arg);
void lata_options_enable_tu_stats(const char *arg);
void lata_options_enable_fam_stats(const char *arg);
void lata_options_enable_peephole_stats(const char *arg);

#endif
