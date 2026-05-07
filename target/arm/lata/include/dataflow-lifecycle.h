#ifndef LATA_DATAFLOW_LIFECYCLE_H
#define LATA_DATAFLOW_LIFECYCLE_H

#include "exec/translation-block.h"

void lata_df_reset_tb(TranslationBlock *tb);
void lata_df_free_tb(TranslationBlock *tb);

#endif
