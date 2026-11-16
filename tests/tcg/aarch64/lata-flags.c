/*
 * LATA ADCS/SBCS carry-chain regression test.
 *
 * AArch64 allows writing the carry flag into either an unmapped guest
 * register (which LATA may cache in a host register) or a statically mapped
 * register.  The flag helper must still observe the original source values
 * after the result has been written, and the carry must survive arbitrary
 * non-flag-setting instructions between two adcs/sbcs operations.
 *
 * Keep this test self-checking so it can run under any aarch64-linux-user
 * emulator.
 */

#include <stdint.h>
#include <stdio.h>

static uint64_t nzcv_add(uint64_t a, uint64_t b, uint64_t cin, uint64_t *res)
{
    unsigned __int128 s = (unsigned __int128)a + b + cin;
    uint64_t r = (uint64_t)s;
    uint64_t c = (uint64_t)(s >> 64) & 1;
    uint64_t n = r >> 63;
    uint64_t z = r == 0;
    uint64_t v = ((a ^ r) & (b ^ r)) >> 63 & 1;

    *res = r;
    return (n << 31) | (z << 30) | (c << 29) | (v << 28);
}

static uint64_t nzcv_sub(uint64_t a, uint64_t b, uint64_t cin, uint64_t *res)
{
    uint64_t borrow = 1 - cin;
    uint64_t r = a - b - borrow;
    uint64_t c = a >= b + borrow;
    uint64_t n = r >> 63;
    uint64_t z = r == 0;
    uint64_t v = ((a ^ b) & (a ^ r)) >> 63 & 1;

    *res = r;
    return (n << 31) | (z << 30) | (c << 29) | (v << 28);
}

#define TEST_VALUES                                                    \
    { 0x0000000000000000ULL, 0x0000000000000000ULL },                \
    { 0x0000000000000000ULL, 0xffffffffffffffffULL },                \
    { 0x7fffffffffffffffULL, 0x0000000000000001ULL },                \
    { 0xffffffffffffffffULL, 0x0000000000000001ULL },                \
    { 0x63309429d6d1c7c0ULL, 0x4b81e344a0a2d863ULL },                \
    { 0x8000000000000000ULL, 0x8000000000000000ULL },                \
    { 0xffffffff00000000ULL, 0x00000000ffffffffULL }

#define CHECK(cond, name)                                              \
    do {                                                               \
        if (!(cond)) {                                                 \
            printf("FAIL: %s\n", name);                                \
            failures++;                                                \
        }                                                              \
    } while (0)

/*
 * adcs x19, x19, x19; <filler>; adcs x20, x20, x20
 * x19/x20 are statically mapped guest registers, so rd == rn == rm makes
 * the destination alias both sources.
 */
#define GEN_ADCS_MAPPED(NAME, FILLER)                                  \
    static int test_adcs_mapped_##NAME(void)                           \
    {                                                                  \
        static const uint64_t vals[][2] = { TEST_VALUES };             \
        int failures = 0;                                              \
        size_t i;                                                      \
        for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {         \
            uint64_t a = vals[i][0], b = vals[i][1];                   \
            uint64_t r19, r20, flags, e19, e20, f1, f2, cin = 1;       \
            uint64_t scratch = 0;                                      \
            asm volatile(                                              \
                "mov x24, %6\n\t"                                      \
                "mov x19, %3\n\t"                                      \
                "mov x20, %4\n\t"                                      \
                "mov x23, %5\n\t"                                      \
                "mov x1, xzr\n\t"                                      \
                "subs x2, x1, xzr\n\t"                                 \
                "adcs x19, x19, x19\n\t"                               \
                FILLER "\n\t"                                          \
                "adcs x20, x20, x20\n\t"                               \
                "mrs x22, nzcv\n\t"                                    \
                "mov %0, x19\n\t"                                      \
                "mov %1, x20\n\t"                                      \
                "mov %2, x22"                                          \
                : "=&r"(r19), "=&r"(r20), "=&r"(flags)                 \
                : "r"(a), "r"(b), "r"(b), "r"(&scratch)                \
                : "x1", "x2", "x10", "x19", "x20", "x22", "x23",       \
                  "x24", "memory", "cc");                              \
            f1 = nzcv_add(a, a, cin, &e19);                            \
            f2 = nzcv_add(b, b, (f1 >> 29) & 1, &e20);                 \
            CHECK(r19 == e19, #NAME " result 1");                      \
            CHECK(r20 == e20, #NAME " result 2");                      \
            CHECK(flags == f2, #NAME " flags");                        \
        }                                                              \
        return failures;                                               \
    }

/*
 * adcs x15, x15, x15; <filler>; adcs x16, x16, x16
 * x15/x16 are not statically mapped and may live in LATA's GPR cache.
 */
#define GEN_ADCS_CACHED(NAME, FILLER)                                  \
    static int test_adcs_cached_##NAME(void)                           \
    {                                                                  \
        static const uint64_t vals[][2] = { TEST_VALUES };             \
        int failures = 0;                                              \
        size_t i;                                                      \
        for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {         \
            uint64_t a = vals[i][0], b = vals[i][1];                   \
            uint64_t r15, r16, flags, e15, e16, f1, f2, cin = 1;       \
            uint64_t scratch = 0;                                      \
            asm volatile(                                              \
                "mov x24, %6\n\t"                                      \
                "mov x15, %3\n\t"                                      \
                "mov x16, %4\n\t"                                      \
                "mov x6, %5\n\t"                                       \
                "mov x1, xzr\n\t"                                      \
                "subs x2, x1, xzr\n\t"                                 \
                "adcs x15, x15, x15\n\t"                               \
                FILLER "\n\t"                                          \
                "adcs x16, x16, x16\n\t"                               \
                "mrs x17, nzcv\n\t"                                    \
                "mov %0, x15\n\t"                                      \
                "mov %1, x16\n\t"                                      \
                "mov %2, x17"                                          \
                : "=&r"(r15), "=&r"(r16), "=&r"(flags)                 \
                : "r"(a), "r"(b), "r"(a), "r"(&scratch)                \
                : "x1", "x2", "x6", "x10", "x15", "x16", "x17",        \
                  "x24", "memory", "cc");                              \
            f1 = nzcv_add(a, a, cin, &e15);                            \
            f2 = nzcv_add(b, b, (f1 >> 29) & 1, &e16);                 \
            CHECK(r15 == e15, #NAME " result 1");                      \
            CHECK(r16 == e16, #NAME " result 2");                      \
            CHECK(flags == f2, #NAME " flags");                        \
        }                                                              \
        return failures;                                               \
    }

/*
 * sbcs x19, x19, x14; <filler>; sbcs x20, x20, x15
 * This is the multi-limb borrow chain emitted by OpenSSL's P-256 code.
 */
#define GEN_SBCS(NAME, FILLER)                                         \
    static int test_sbcs_##NAME(void)                                  \
    {                                                                  \
        static const uint64_t vals[][2] = { TEST_VALUES };             \
        int failures = 0;                                              \
        size_t i;                                                      \
        for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {         \
            uint64_t a = vals[i][0], b = vals[i][1];                   \
            uint64_t c = vals[i][1], d = vals[i][0];                   \
            uint64_t r19, r20, flags, e19, e20, f1, f2, cin = 1;       \
            uint64_t scratch = 0;                                      \
            asm volatile(                                              \
                "mov x24, %7\n\t"                                      \
                "mov x19, %3\n\t"                                      \
                "mov x20, %4\n\t"                                      \
                "mov x14, %5\n\t"                                      \
                "mov x15, %6\n\t"                                      \
                "mov x1, xzr\n\t"                                      \
                "subs x2, x1, xzr\n\t"                                 \
                "sbcs x19, x19, x14\n\t"                               \
                FILLER "\n\t"                                          \
                "sbcs x20, x20, x15\n\t"                               \
                "mrs x22, nzcv\n\t"                                    \
                "mov %0, x19\n\t"                                      \
                "mov %1, x20\n\t"                                      \
                "mov %2, x22"                                          \
                : "=&r"(r19), "=&r"(r20), "=&r"(flags)                 \
                : "r"(a), "r"(c), "r"(b), "r"(d), "r"(&scratch)        \
                : "x1", "x2", "x10", "x14", "x15", "x19", "x20",       \
                  "x22", "x24", "memory", "cc");                       \
            f1 = nzcv_sub(a, b, cin, &e19);                            \
            f2 = nzcv_sub(c, d, (f1 >> 29) & 1, &e20);                 \
            CHECK(r19 == e19, #NAME " result 1");                      \
            CHECK(r20 == e20, #NAME " result 2");                      \
            CHECK(flags == f2, #NAME " flags");                        \
        }                                                              \
        return failures;                                               \
    }

GEN_ADCS_MAPPED(nop, "nop")
GEN_ADCS_MAPPED(mov, "mov x10, x23")
GEN_ADCS_MAPPED(add, "add x10, x23, x23")
GEN_ADCS_MAPPED(and, "and x10, x23, x23")
GEN_ADCS_MAPPED(mul, "mul x10, x23, x23")
GEN_ADCS_MAPPED(umulh, "umulh x10, x23, x23")
GEN_ADCS_MAPPED(ldr, "ldr x10, [x24]")
GEN_ADCS_MAPPED(str, "str x23, [x24]")

GEN_ADCS_CACHED(nop, "nop")
GEN_ADCS_CACHED(mov, "mov x10, x6")
GEN_ADCS_CACHED(add, "add x10, x6, x6")
GEN_ADCS_CACHED(and, "and x10, x6, x6")
GEN_ADCS_CACHED(mul, "mul x10, x6, x6")
GEN_ADCS_CACHED(umulh, "umulh x10, x6, x6")
GEN_ADCS_CACHED(ldr, "ldr x10, [x24]")
GEN_ADCS_CACHED(str, "str x6, [x24]")

GEN_SBCS(nop, "nop")
GEN_SBCS(add, "add x10, x6, x6")
GEN_SBCS(and, "and x10, x6, x6")
GEN_SBCS(mul, "mul x10, x6, x6")
GEN_SBCS(umulh, "umulh x10, x6, x6")
GEN_SBCS(stp, "stp xzr, xzr, [x24]")
GEN_SBCS(ldr, "ldr x10, [x24]")
GEN_SBCS(str, "str x6, [x24]")

#define RUN(fn) failures += fn()

int main(void)
{
    int failures = 0;

    RUN(test_adcs_mapped_nop);
    RUN(test_adcs_mapped_mov);
    RUN(test_adcs_mapped_add);
    RUN(test_adcs_mapped_and);
    RUN(test_adcs_mapped_mul);
    RUN(test_adcs_mapped_umulh);
    RUN(test_adcs_mapped_ldr);
    RUN(test_adcs_mapped_str);

    RUN(test_adcs_cached_nop);
    RUN(test_adcs_cached_mov);
    RUN(test_adcs_cached_add);
    RUN(test_adcs_cached_and);
    RUN(test_adcs_cached_mul);
    RUN(test_adcs_cached_umulh);
    RUN(test_adcs_cached_ldr);
    RUN(test_adcs_cached_str);

    RUN(test_sbcs_nop);
    RUN(test_sbcs_add);
    RUN(test_sbcs_and);
    RUN(test_sbcs_mul);
    RUN(test_sbcs_umulh);
    RUN(test_sbcs_stp);
    RUN(test_sbcs_ldr);
    RUN(test_sbcs_str);

    if (failures) {
        printf("lata-flags: %d failure(s)\n", failures);
        return 1;
    }
    printf("lata-flags: all tests passed\n");
    return 0;
}
