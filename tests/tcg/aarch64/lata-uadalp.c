/*
 * Regression test: UADALP/SADALP must release their floating-point temporary.
 *
 * The accumulating pairwise-add handlers used to free their vector temporary
 * through free_alloc_gpr(), so every translated instruction leaked one of the
 * six ftemp registers.  Leaking more than six of them in a single translation
 * block exhausted the pool and aborted translation, so this test keeps all the
 * accumulating pairwise adds in one straight-line block.
 *
 * Copyright (c) 2026, Loongson Technology. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 */

#include <stdint.h>
#include <stdio.h>

int main(void)
{
    uint32_t out[4] = { 0, 0, 0, 0 };

    __asm__ volatile(
        "movi v0.16b, #0\n\t"
        "movi v11.16b, #0\n\t"
        "movi v12.16b, #0\n\t"
        "movi v15.16b, #0\n\t"
        "movi v25.16b, #0\n\t"
        "movi v26.16b, #0\n\t"
        "uadalp v15.8h, v11.16b\n\t"
        "uadalp v0.8h, v12.16b\n\t"
        "uadalp v25.4s, v15.8h\n\t"
        "uadalp v25.4s, v0.8h\n\t"
        "uadalp v25.4s, v15.8h\n\t"
        "uadalp v25.4s, v0.8h\n\t"
        "uadalp v25.4s, v15.8h\n\t"
        "uadalp v25.4s, v0.8h\n\t"
        "uadalp v25.4s, v15.8h\n\t"
        "uadalp v25.4s, v0.8h\n\t"
        "uaddw v15.8h, v11.8h, v12.8b\n\t"
        "str q25, [%0]\n\t"
        :
        : "r"(out)
        : "v0", "v11", "v12", "v15", "v25", "v26", "memory");

    if (out[0] != 0 || out[1] != 0 || out[2] != 0 || out[3] != 0) {
        printf("FAIL: uadalp result %u %u %u %u\n",
               out[0], out[1], out[2], out[3]);
        return 1;
    }
    printf("PASS: uadalp/sadalp temporary released\n");
    return 0;
}
