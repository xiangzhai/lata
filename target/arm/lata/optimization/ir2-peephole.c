#include "qemu/osdep.h"

#include "target/arm/lata/include/ir2-peephole.h"
#include "target/arm/lata/include/lata.h"

static bool is_self_high_clear(IR2_INST *ir2)
{
    IR2_OPCODE opcode = ir2_opcode(ir2);

    if (opcode != LISA_BSTRPICK_D && opcode != LISA_BSTRPICK_W) {
        return false;
    }
    if (!ir2_opnd_is_ireg(&ir2->_opnd[0]) ||
        !ir2_opnd_is_ireg(&ir2->_opnd[1])) {
        return false;
    }
    if (!ir2_opnd_cmp(&ir2->_opnd[0], &ir2->_opnd[1])) {
        return false;
    }
    return ir2_opnd_imm(&ir2->_opnd[2]) == 31 &&
           ir2_opnd_imm(&ir2->_opnd[3]) == 0;
}

static bool same_high_clear(IR2_INST *a, IR2_INST *b)
{
    return is_self_high_clear(a) && is_self_high_clear(b) &&
           ir2_opcode(a) == ir2_opcode(b) &&
           ir2_opnd_cmp(&a->_opnd[0], &b->_opnd[0]);
}

void lata_ir2_peephole_run(void)
{
    IR2_INST *ir2 = lsenv->tr_data->first_ir2;

    while (ir2) {
        IR2_INST *next = ir2_next(ir2);

        if (next && same_high_clear(ir2, next)) {
            ir2_remove(next);
            continue;
        }
        ir2 = next;
    }
}
