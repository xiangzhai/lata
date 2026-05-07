#ifndef LATA_IR2_PEEPHOLE_H
#define LATA_IR2_PEEPHOLE_H

typedef struct LataIR2PeepholeStats {
    uint64_t runs;
    uint64_t removed_total;
    uint64_t removed_high_clear;
    uint64_t removed_addr_wrap;
} LataIR2PeepholeStats;

void lata_ir2_peephole_run(void);
void lata_ir2_peephole_dump_stats(void);
const LataIR2PeepholeStats *lata_ir2_peephole_get_stats(void);

#endif
