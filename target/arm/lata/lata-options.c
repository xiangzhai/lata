#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "target/arm/lata/include/lata-options.h"

#ifdef CONFIG_LATA_PROFILE
int indirect_jmp_opt_profile;
#endif
#ifdef CONFIG_LATA_INDIRECT_JMP
int option_fam_jmp_cache = 1;
#else
int option_fam_jmp_cache;
#endif
int option_fp_precise = 1;

int option_lata_dump;
int option_lata_dump_ir1;
int option_lata_dump_ir2;
int option_lata_dump_host;
int option_lata_dump_tu;
int option_lata_trace_tb;
int option_lata_trace_ir1;
int option_lata_trace_runtime;
int option_lata_trace_vec;
int option_lata_dataflow_opt = 1;
int option_lata_tu_stats;
int option_lata_fam_stats;
int option_lata_peephole_stats;

uint64_t lata_debug_tb_pc;
uint64_t lata_trace_mem;
uint64_t lata_break_insn;
uint64_t lata_unlink_count;
uint32_t lata_unlink_cpu;
uint64_t lata_trace_begin_pc;
uint64_t lata_trace_end_pc;
uint32_t lata_trace_vec_mask;

static bool lata_option_is_digit_bitmap(const char *arg)
{
    if (!arg || !*arg) {
        return false;
    }
    for (const char *p = arg; *p; p++) {
        if (*p != '0' && *p != '1') {
            return false;
        }
    }
    return true;
}

static bool lata_option_token_enabled(const char *arg, const char *name)
{
    g_autofree char *copy = g_strdup(arg);
    char *saveptr = NULL;

    for (char *tok = strtok_r(copy, ",", &saveptr);
         tok;
         tok = strtok_r(NULL, ",", &saveptr)) {
        if (!g_ascii_strcasecmp(tok, name)) {
            return true;
        }
    }
    return false;
}

void lata_options_init(void)
{
#ifdef CONFIG_LATA_PROFILE
    indirect_jmp_opt_profile = 0;
#endif
#ifdef CONFIG_LATA_INDIRECT_JMP
    option_fam_jmp_cache = 1;
#else
    option_fam_jmp_cache = 0;
#endif
    option_fp_precise = 1;

    option_lata_dump = 0;
    option_lata_dump_ir1 = 0;
    option_lata_dump_ir2 = 0;
    option_lata_dump_host = 0;
    option_lata_dump_tu = 0;
    option_lata_trace_tb = 0;
    option_lata_trace_ir1 = 0;
    option_lata_trace_runtime = 0;
    option_lata_trace_vec = 0;
    option_lata_dataflow_opt = 1;
    option_lata_tu_stats = 0;
    option_lata_fam_stats = 0;
    option_lata_peephole_stats = 0;

    lata_debug_tb_pc = 0;
    lata_trace_mem = 0;
    lata_break_insn = 0;
    lata_unlink_count = 0;
    lata_unlink_cpu = 0;
    lata_trace_begin_pc = 0;
    lata_trace_end_pc = 0;
    lata_trace_vec_mask = 0;
}

void lata_options_parse_dump(const char *arg)
{
    if (!arg) {
        return;
    }

    option_lata_dump = 0;
    option_lata_dump_ir1 = 0;
    option_lata_dump_ir2 = 0;
    option_lata_dump_host = 0;
    option_lata_dump_tu = 0;

    if (lata_option_is_digit_bitmap(arg)) {
        option_lata_dump = arg[0] == '1';
        option_lata_dump_ir1 = arg[1] == '1';
        option_lata_dump_ir2 = arg[2] == '1';
        option_lata_dump_host = arg[3] == '1';
        option_lata_dump_tu = arg[4] == '1';
        return;
    }

    option_lata_dump = lata_option_token_enabled(arg, "func") ||
                       lata_option_token_enabled(arg, "all");
    option_lata_dump_ir1 = lata_option_token_enabled(arg, "ir1") ||
                           lata_option_token_enabled(arg, "all");
    option_lata_dump_ir2 = lata_option_token_enabled(arg, "ir2") ||
                           lata_option_token_enabled(arg, "all");
    option_lata_dump_host = lata_option_token_enabled(arg, "host") ||
                            lata_option_token_enabled(arg, "all");
    option_lata_dump_tu = lata_option_token_enabled(arg, "tu") ||
                          lata_option_token_enabled(arg, "cfg") ||
                          lata_option_token_enabled(arg, "all");
}

void lata_options_parse_trace(const char *arg)
{
    if (!arg) {
        return;
    }

    option_lata_trace_tb = 0;
    option_lata_trace_ir1 = 0;
    option_lata_trace_runtime = 0;
    option_lata_trace_vec = 0;

    if (lata_option_is_digit_bitmap(arg)) {
        option_lata_trace_tb = arg[0] == '1';
        option_lata_trace_ir1 = arg[1] == '1';
        option_lata_trace_runtime = arg[2] == '1';
        return;
    }

    option_lata_trace_tb = lata_option_token_enabled(arg, "tb") ||
                           lata_option_token_enabled(arg, "all");
    option_lata_trace_ir1 = lata_option_token_enabled(arg, "ir1") ||
                            lata_option_token_enabled(arg, "all");
    option_lata_trace_runtime = lata_option_token_enabled(arg, "runtime") ||
                                lata_option_token_enabled(arg, "all");
    option_lata_trace_vec = lata_option_token_enabled(arg, "vec") ||
                            lata_option_token_enabled(arg, "vector") ||
                            lata_option_token_enabled(arg, "all");
    if (option_lata_trace_vec && !lata_trace_vec_mask) {
        lata_trace_vec_mask = UINT32_MAX;
    }
}

void lata_options_parse_show_tb(const char *arg)
{
    if (arg) {
        qemu_strtou64(arg, NULL, 0, &lata_debug_tb_pc);
    }
}

void lata_options_parse_trace_mem(const char *arg)
{
    if (arg) {
        qemu_strtou64(arg, NULL, 0, &lata_trace_mem);
    }
}

void lata_options_parse_break_insn(const char *arg)
{
    if (arg) {
        qemu_strtou64(arg, NULL, 0, &lata_break_insn);
    }
}

void lata_options_parse_unlink(const char *arg)
{
    if (!arg) {
        return;
    }

    g_auto(GStrv) split = g_strsplit(arg, ",", 2);
    if (split[0]) {
        lata_unlink_count = g_ascii_strtoull(split[0], NULL, 0);
    }
    if (split[1]) {
        lata_unlink_cpu = g_ascii_strtoull(split[1], NULL, 0);
    }
}

void lata_options_parse_trace_begin(const char *arg)
{
    if (arg) {
        qemu_strtou64(arg, NULL, 0, &lata_trace_begin_pc);
    }
}

void lata_options_parse_trace_end(const char *arg)
{
    if (arg) {
        qemu_strtou64(arg, NULL, 0, &lata_trace_end_pc);
    }
}

void lata_options_parse_trace_pc(const char *arg)
{
    if (!arg) {
        return;
    }

    g_auto(GStrv) split = g_strsplit(arg, ":", 2);
    if (split[0] && split[0][0]) {
        qemu_strtou64(split[0], NULL, 0, &lata_trace_begin_pc);
    }
    if (split[1] && split[1][0]) {
        qemu_strtou64(split[1], NULL, 0, &lata_trace_end_pc);
    }
    option_lata_trace_runtime = 1;
}

void lata_options_parse_trace_vec(const char *arg)
{
    if (!arg) {
        option_lata_trace_vec = 1;
        lata_trace_vec_mask = UINT32_MAX;
        return;
    }

    if (!g_ascii_strcasecmp(arg, "0") ||
        !g_ascii_strcasecmp(arg, "off") ||
        !g_ascii_strcasecmp(arg, "none")) {
        option_lata_trace_vec = 0;
        lata_trace_vec_mask = 0;
        return;
    }
    if (!g_ascii_strcasecmp(arg, "1") ||
        !g_ascii_strcasecmp(arg, "on") ||
        !g_ascii_strcasecmp(arg, "all")) {
        option_lata_trace_vec = 1;
        lata_trace_vec_mask = UINT32_MAX;
        return;
    }

    option_lata_trace_vec = 1;
    lata_trace_vec_mask = 0;
    g_auto(GStrv) split = g_strsplit(arg, ",", 0);
    for (char **p = split; p && *p; p++) {
        uint64_t reg;

        if (qemu_strtou64(*p, NULL, 0, &reg) == 0 && reg < 32) {
            lata_trace_vec_mask |= 1u << reg;
        }
    }
    if (!lata_trace_vec_mask) {
        lata_trace_vec_mask = UINT32_MAX;
    }
}

void lata_options_parse_fp_precise(const char *arg)
{
    if (arg) {
        option_fp_precise = atoi(arg);
    }
}

void lata_options_parse_dataflow_opt(const char *arg)
{
    if (arg) {
        option_lata_dataflow_opt = atoi(arg);
    }
}

void lata_options_parse_fam_cache(const char *arg)
{
    if (arg) {
        option_fam_jmp_cache = atoi(arg);
        if (option_fam_jmp_cache > 1) {
            option_fam_jmp_cache = 1;
        }
        if (option_fam_jmp_cache < -1) {
            option_fam_jmp_cache = -1;
        }
    }
}

void lata_options_enable_tu_stats(const char *arg)
{
    option_lata_tu_stats = !arg || atoi(arg) != 0;
}

void lata_options_enable_fam_stats(const char *arg)
{
    option_lata_fam_stats = !arg || atoi(arg) != 0;
}

void lata_options_enable_peephole_stats(const char *arg)
{
    option_lata_peephole_stats = !arg || atoi(arg) != 0;
}
