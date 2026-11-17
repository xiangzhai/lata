/*
 * LATA LSE atomic destination/base aliasing regression test.
 *
 * AArch64 allows the LSE atomic destination register to be the same register
 * as the base address, for example "ldset x1, x2, [x1]".  The LoongArch AMO
 * instructions used by the translator require the result register to differ
 * from the address register, so LATA must allocate a temporary in that case.
 * Exercise every wide AMO operation with rt == rn, for both 64-bit and
 * 32-bit forms.
 */

#include <stdint.h>
#include <stdio.h>

#define CHECK(cond, name)                                              \
    do {                                                               \
        if (!(cond)) {                                                 \
            printf("FAIL: %s\n", name);                                \
            failures++;                                                \
        }                                                              \
    } while (0)

#define DEFINE_LSE64(NAME, INSN, INIT, OPERAND, EXPECTED)               \
    static int test_##NAME(void)                                       \
    {                                                                  \
        static uint64_t mem;                                           \
        uint64_t old;                                                  \
        int failures = 0;                                              \
                                                                       \
        mem = (INIT);                                                  \
        asm volatile(                                                  \
            ".arch_extension lse\n\t"                                  \
            "mov x1, %1\n\t"                                           \
            "mov x2, %2\n\t"                                           \
            #INSN " x2, x1, [x1]\n\t"                                  \
            ".arch_extension nolse\n\t"                                \
            "mov %0, x1"                                               \
            : "=&r"(old)                                               \
            : "r"(&mem), "r"((uint64_t)(OPERAND))                      \
            : "x1", "x2", "memory");                                   \
        CHECK(old == (uint64_t)(INIT), #NAME " returns old value");     \
        CHECK(mem == (uint64_t)(EXPECTED), #NAME " updates memory");    \
        return failures;                                               \
    }

#define DEFINE_LSE32(NAME, INSN, INIT, OPERAND, EXPECTED_LOW)           \
    static int test_##NAME##_w(void)                                   \
    {                                                                  \
        static uint64_t mem;                                           \
        uint64_t old;                                                  \
        int failures = 0;                                              \
                                                                       \
        mem = (INIT);                                                  \
        asm volatile(                                                  \
            ".arch_extension lse\n\t"                                  \
            "mov x1, %1\n\t"                                           \
            "mov w2, %w2\n\t"                                          \
            #INSN " w2, w1, [x1]\n\t"                                  \
            ".arch_extension nolse\n\t"                                \
            "mov %0, x1"                                               \
            : "=&r"(old)                                               \
            : "r"(&mem), "r"((uint32_t)(OPERAND))                      \
            : "x1", "x2", "memory");                                   \
        CHECK((old == ((uint64_t)(INIT) & 0xffffffffULL)),              \
              #NAME "w returns old value");                            \
        CHECK(mem == (((uint64_t)(INIT) & ~0xffffffffULL) |            \
                      (uint64_t)(EXPECTED_LOW)),                       \
              #NAME "w updates memory");                               \
        return failures;                                               \
    }

#define INIT64  0x0000000000000123ULL
#define OP64    0x00000000000000f0ULL

DEFINE_LSE64(ldadd, ldadd, INIT64, OP64, INIT64 + OP64)
DEFINE_LSE64(ldclr, ldclr, INIT64, OP64, INIT64 & ~OP64)
DEFINE_LSE64(ldeor, ldeor, INIT64, OP64, INIT64 ^ OP64)
DEFINE_LSE64(ldset, ldset, INIT64, OP64, INIT64 | OP64)
DEFINE_LSE64(ldsmax, ldsmax, INIT64, OP64, INIT64)
DEFINE_LSE64(ldsmin, ldsmin, INIT64, OP64, OP64)
DEFINE_LSE64(ldumax, ldumax, INIT64, OP64, INIT64)
DEFINE_LSE64(ldumin, ldumin, INIT64, OP64, OP64)
DEFINE_LSE64(swp, swp, INIT64, OP64, OP64)

#define INIT32  0xdeadbeef11223344ULL
#define OP32    0x00ff00ffU

DEFINE_LSE32(ldadd, ldadd, INIT32, OP32, 0x12213443U)
DEFINE_LSE32(ldclr, ldclr, INIT32, OP32, 0x11003300U)
DEFINE_LSE32(ldeor, ldeor, INIT32, OP32, 0x11dd33bbU)
DEFINE_LSE32(ldset, ldset, INIT32, OP32, 0x11ff33ffU)
DEFINE_LSE32(ldsmax, ldsmax, INIT32, OP32, 0x11223344U)
DEFINE_LSE32(ldsmin, ldsmin, INIT32, OP32, 0x00ff00ffU)
DEFINE_LSE32(ldumax, ldumax, INIT32, OP32, 0x11223344U)
DEFINE_LSE32(ldumin, ldumin, INIT32, OP32, 0x00ff00ffU)
DEFINE_LSE32(swp, swp, INIT32, OP32, 0x00ff00ffU)

#define RUN(fn) failures += fn()

int main(void)
{
    int failures = 0;

    RUN(test_ldadd);
    RUN(test_ldclr);
    RUN(test_ldeor);
    RUN(test_ldset);
    RUN(test_ldsmax);
    RUN(test_ldsmin);
    RUN(test_ldumax);
    RUN(test_ldumin);
    RUN(test_swp);

    RUN(test_ldadd_w);
    RUN(test_ldclr_w);
    RUN(test_ldeor_w);
    RUN(test_ldset_w);
    RUN(test_ldsmax_w);
    RUN(test_ldsmin_w);
    RUN(test_ldumax_w);
    RUN(test_ldumin_w);
    RUN(test_swp_w);

    if (failures) {
        printf("lata-lse-alias: %d failure(s)\n", failures);
        return 1;
    }
    printf("lata-lse-alias: all tests passed\n");
    return 0;
}
