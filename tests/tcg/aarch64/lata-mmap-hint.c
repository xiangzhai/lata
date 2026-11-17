/*
 * LATA low mmap() hint regression test.
 *
 * Linux treats an mmap() address below vm.mmap_min_addr as a hint and ignores
 * it.  LATA used to pass the low hint straight to the host mmap, where it was
 * rejected, and returned ENOMEM instead of allocating at a usable address.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
    static const uintptr_t hints[] = {
        0x1000, 0x2000, 0x4000, 0x8000, 0xc000, 0xf000,
    };
    const size_t page_size = sysconf(_SC_PAGESIZE);
    int failures = 0;

    for (size_t i = 0; i < sizeof(hints) / sizeof(hints[0]); i++) {
        volatile unsigned char *p;

        errno = 0;
        p = mmap((void *)hints[i], page_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            printf("FAIL: low mmap hint %#llx returned MAP_FAILED: "
                   "errno=%d\n", (unsigned long long)hints[i], errno);
            failures++;
            continue;
        }

        p[0] = 0x5a;
        if (p[0] != 0x5a) {
            printf("FAIL: low mmap hint %#llx page is not writable\n",
                   (unsigned long long)hints[i]);
            failures++;
        }

        if (munmap((void *)p, page_size) != 0) {
            perror("munmap");
            failures++;
        }
    }

    if (failures) {
        printf("lata-mmap-hint: %d failure(s)\n", failures);
        return 1;
    }
    printf("lata-mmap-hint: all tests passed\n");
    return 0;
}
