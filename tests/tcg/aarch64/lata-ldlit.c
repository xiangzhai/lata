/*
 * LATA LDR (literal) high-address regression test.
 *
 * LDR literal is PC-relative, but its target can still be anywhere in the
 * 64-bit guest address space when the code itself is mapped above 4GB.
 * The translator used to materialize the literal address with a 32-bit
 * lu12i.w, truncating the address and faulting.  Map a small code page above
 * 4GB and load 64-bit, unsigned 32-bit, and signed 32-bit literals from it.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* LDR Xt, #8 ; RET ; <64-bit literal> */
#define INSN_LDR_X0_8   0x58000040U
#define INSN_LDR_W0_8   0x18000040U
#define INSN_LDRSW_X0_8 0x98000040U
#define INSN_RET        0xd65f03c0U

static uint32_t *emit_literal_load(uint32_t *code, uint32_t insn,
                                   uint64_t literal)
{
    code[0] = insn;
    code[1] = INSN_RET;
    memcpy(&code[2], &literal, sizeof(literal));
    return code + 4;
}

static int check(uint64_t got, uint64_t expected, const char *name)
{
    if (got != expected) {
        printf("FAIL: %s: got 0x%016llx, expected 0x%016llx\n",
               name, (unsigned long long)got,
               (unsigned long long)expected);
        return 1;
    }
    return 0;
}

int main(void)
{
    const uintptr_t high = 0x100000000ULL;
    const size_t page_size = sysconf(_SC_PAGESIZE);
    uint64_t (*fn64)(void);
    uint64_t (*fn32)(void);
    uint64_t (*fn32s)(void);
    uint32_t *base;
    int failures = 0;

    void *map = mmap((void *)high, page_size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (map == MAP_FAILED) {
        perror("mmap high code page");
        return 1;
    }
    if ((uintptr_t)map <= UINT32_MAX) {
        printf("FAIL: high mapping returned low address %p\n", map);
        return 1;
    }

    base = map;
    emit_literal_load(base, INSN_LDR_X0_8, 0x1122334455667788ULL);
    emit_literal_load(base + 16, INSN_LDR_W0_8, 0x89abcdefULL);
    emit_literal_load(base + 32, INSN_LDRSW_X0_8, 0x80000001ULL);

    fn64 = (uint64_t (*)(void))base;
    fn32 = (uint64_t (*)(void))(base + 16);
    fn32s = (uint64_t (*)(void))(base + 32);

    __builtin___clear_cache((char *)map, (char *)map + page_size);

    failures += check(fn64(), 0x1122334455667788ULL,
                      "64-bit literal load");
    failures += check(fn32(), 0x0000000089abcdefULL,
                      "32-bit literal zero extend");
    failures += check(fn32s(), 0xffffffff80000001ULL,
                      "32-bit literal sign extend");

    if (failures) {
        printf("lata-ldlit: %d failure(s)\n", failures);
        return 1;
    }
    printf("lata-ldlit: all tests passed\n");
    return 0;
}
