#include "clear-high.h"
#include "lata.h"
#include "dataflow.h"

bool clearGprHigh = 1;

void set_w_write_flag(int i, int sf){
    uint32_t old = lsenv->tr_data->w_write_flag;

    if(sf){ /* write_X */
        lsenv->tr_data->w_write_flag = (old & (1 << i)) ? (old - (1 << i)) : old;  
    }else{ /* write_W */
        lsenv->tr_data->w_write_flag = old | (1 << i);
    }
    // printf("gpr_%d, old : %x, now : %x\n ", i, old, lsenv->tr_data->w_write_flag);
}

void clear_gpr_high(int i)
{
    uint32_t old = lsenv->tr_data->w_write_flag;
    if (old & (1 << i))
    {
        IR2_OPND opnd = ir2_opnd_new(IR2_OPND_GPR, arm_la_map[i]);
        la_bstrpick_d(opnd, opnd, 31, 0);
        lsenv->tr_data->w_write_flag = old - (1 << i);       
    }

}

void clear_gpr_high_for_boundary(int i)
{
    if (!lata_df_reg_high_live_after_write(i)) {
        lsenv->tr_data->w_write_flag &= ~(1u << i);
        return;
    }
    clear_gpr_high(i);
}
