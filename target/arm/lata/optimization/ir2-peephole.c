#include "qemu/osdep.h"

#include "exec/log.h"
#include "target/arm/lata/include/ir2-peephole.h"
#include "target/arm/lata/include/lata.h"
#include "target/arm/lata/include/lata-options.h"

typedef enum LataPeepholeChange {
    LATA_PEEPHOLE_KEEP,
    LATA_PEEPHOLE_REMOVE_HIGH_CLEAR,
    LATA_PEEPHOLE_REMOVE_ADDR_WRAP,
} LataPeepholeChange;

static LataIR2PeepholeStats peephole_stats;

static bool is_self_bstrpick(IR2_INST *ir2, int msb, int lsb)
{
    if (ir2_opcode(ir2) != LISA_BSTRPICK_D &&
        ir2_opcode(ir2) != LISA_BSTRPICK_W) {
        return false;
    }
    if (!ir2_opnd_is_ireg(&ir2->_opnd[0]) ||
        !ir2_opnd_is_ireg(&ir2->_opnd[1])) {
        return false;
    }
    if (!ir2_opnd_cmp(&ir2->_opnd[0], &ir2->_opnd[1])) {
        return false;
    }
    return ir2_opnd_imm(&ir2->_opnd[2]) == msb &&
           ir2_opnd_imm(&ir2->_opnd[3]) == lsb;
}

static bool is_self_high_clear(IR2_INST *ir2)
{
    return is_self_bstrpick(ir2, 31, 0);
}

static bool is_self_addr_wrap(IR2_INST *ir2)
{
    return ir2_opcode(ir2) == LISA_BSTRPICK_D &&
           is_self_bstrpick(ir2, 47, 0);
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

static LataPeepholeChange duplicate_self_bstrpick(IR2_INST *ir2)
{
    IR2_INST *next = ir2_next(ir2);

    if (!next) {
        return LATA_PEEPHOLE_KEEP;
    }
    if (same_high_clear(ir2, next)) {
        return LATA_PEEPHOLE_REMOVE_HIGH_CLEAR;
    }
    if (same_addr_wrap(ir2, next)) {
        return LATA_PEEPHOLE_REMOVE_ADDR_WRAP;
    }
    return LATA_PEEPHOLE_KEEP;
}

static uint64_t run_pass(LataPeepholeChange (*pass)(IR2_INST *))
{
    uint64_t removed = 0;
    IR2_INST *ir2 = lsenv->tr_data->first_ir2;

    while (ir2) {
        IR2_INST *next = ir2_next(ir2);
        LataPeepholeChange change = pass(ir2);

        if (change != LATA_PEEPHOLE_KEEP) {
            ir2_remove(next);
            peephole_stats.removed_total++;
            removed++;
            if (change == LATA_PEEPHOLE_REMOVE_HIGH_CLEAR) {
                peephole_stats.removed_high_clear++;
            } else if (change == LATA_PEEPHOLE_REMOVE_ADDR_WRAP) {
                peephole_stats.removed_addr_wrap++;
            }
            continue;
        }
        ir2 = next;
    }

    return removed;
}

void lata_ir2_peephole_run(void)
{
    peephole_stats.runs++;

    run_pass(duplicate_self_bstrpick);
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
             " removed=%" PRIu64
             " high_clear=%" PRIu64
             " addr_wrap=%" PRIu64 "\n",
             peephole_stats.runs,
             peephole_stats.removed_total,
             peephole_stats.removed_high_clear,
             peephole_stats.removed_addr_wrap);
}
