/*
 * LATA MOVZ/MOVN + MOVK immediate-sequence regression test.
 *
 * Adjacent wide moves that build one constant are fused by the translator.
 * Verify the fused value, 32-bit zero extension, MOVN fill, and that a
 * later unrelated move does not inherit a stale fused result.
 */

#include <stdint.h>
#include <stdio.h>

static uint64_t build_movz_movk(uint64_t seed)
{
    uint64_t r;

    asm volatile(
        "movz x9, #0xbeef\n"
        "movk x9, #0xdead, lsl #16\n"
        "movk x9, #0x1234, lsl #32\n"
        "movk x9, #0xabcd, lsl #48\n"
        "add  %0, x9, %1\n"
        : "=&r"(r)
        : "r"(seed)
        : "x9");
    return r;
}

static uint64_t build_movz_movk_w(uint64_t seed)
{
    uint64_t r;

    asm volatile(
        "movz w10, #0xcdef\n"
        "movk w10, #0x89ab, lsl #16\n"
        "add  %0, x10, %1\n"
        : "=&r"(r)
        : "r"(seed)
        : "x10");
    return r;
}

static uint64_t build_movn_movk(void)
{
    uint64_t r;

    asm volatile(
        "movn x11, #0x00ff\n"
        "movk x11, #0x1234, lsl #16\n"
        "movk x11, #0x5678, lsl #48\n"
        "mov  %0, x11\n"
        : "=&r"(r)
        :
        : "x11");
    return r;
}

static uint64_t build_split(uint64_t seed)
{
    uint64_t r;

    asm volatile(
        "movz x12, #0x1111\n"
        "movk x12, #0x2222, lsl #16\n"
        "movz x12, #0x3333\n"
        "movk x12, #0x4444, lsl #16\n"
        "add  %0, x12, %1\n"
        : "=&r"(r)
        : "r"(seed)
        : "x12");
    return r;
}

/* The narrow LSE atomic path calls an integer-only helper.  Ensure live
 * guest vector registers survive that call. */
static int helper_preserves_fpr(void)
{
    uint64_t out5 = 0, out20 = 0;
    uint8_t mem = 0;

    asm volatile(
        "movi v5.2d, #0\n"
        "movi v20.2d, #0\n"
        "movz x1, #0x1111\n"
        "mov  v5.d[0], x1\n"
        "movz x2, #0x2222\n"
        "mov  v20.d[0], x2\n"
        ".arch_extension lse\n"
        "ldaddb w3, w4, [%2]\n"
        ".arch_extension nolse\n"
        "umov %0, v5.d[0]\n"
        "umov %1, v20.d[0]\n"
        : "=&r"(out5), "=&r"(out20)
        : "r"(&mem)
        : "x1", "x2", "x3", "x4", "v5", "v20", "memory");

    return out5 == 0x1111 && out20 == 0x2222;
}

#define CHECK(cond, name)                                              \
    do {                                                               \
        if (!(cond)) {                                                 \
            printf("FAIL: %s\n", name);                                \
            failures++;                                                \
        }                                                              \
    } while (0)

int main(void)
{
    int failures = 0;
    const uint64_t seed = 0x0102030405060708ULL;
    uint64_t movn = ~(uint64_t)0x00ff;

    movn = (movn & ~(0xffffULL << 16)) | (0x1234ULL << 16);
    movn = (movn & ~(0xffffULL << 48)) | (0x5678ULL << 48);

    CHECK(build_movz_movk(seed) == seed + 0xabcd1234deadbeefULL,
          "movz/movk 64-bit");
    CHECK(build_movz_movk_w(seed) == seed + 0x89abcdefULL,
          "movz/movk 32-bit zero extend");
    CHECK(build_movn_movk() == movn, "movn/movk");
    CHECK(build_split(seed) == seed + 0x44443333ULL, "split sequence");
    CHECK(helper_preserves_fpr(), "integer helper preserves live FPRs");

    if (failures) {
        printf("lata-movwide: %d failures\n", failures);
        return 1;
    }
    printf("lata-movwide: all tests passed\n");
    return 0;
}
