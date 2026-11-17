/*
 * Stress TU construction with overlapping basic blocks and a forked child.
 *
 * TU exploration can discover TBs that start in the middle of an earlier TB.
 * Splitting/retranslating those blocks used to corrupt the translated tail
 * and crash multi-threaded guests such as codex.  The child below runs a
 * branch-heavy hash-table workload after fork, which exercises the same kind
 * of overlapping control flow without depending on an external program.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define TABLE_SIZE 8192
#define KEY_COUNT  6000

static _Atomic int stop;
static volatile unsigned long spin_iters;

static void *spinner(void *arg)
{
    unsigned long n = 0;

    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        n++;
        __asm__ __volatile__("" ::: "memory");
    }
    spin_iters = n;
    return NULL;
}

static uint32_t hash_key(uint32_t key)
{
    key ^= key >> 16;
    key *= 0x7feb352dU;
    key ^= key >> 15;
    key *= 0x846ca68bU;
    key ^= key >> 16;
    return key;
}

static int table_insert(uint64_t *keys, uint32_t *used, uint32_t key)
{
    uint32_t slot = hash_key(key) & (TABLE_SIZE - 1);

    for (uint32_t probe = 0; probe < TABLE_SIZE; probe++) {
        if (used[slot] == 0) {
            used[slot] = 1;
            keys[slot] = key;
            return 0;
        }
        if (keys[slot] == key) {
            return 0;
        }
        slot = (slot + 1) & (TABLE_SIZE - 1);
    }
    return -1;
}

static int table_find(const uint64_t *keys, const uint32_t *used, uint32_t key)
{
    uint32_t slot = hash_key(key) & (TABLE_SIZE - 1);

    for (uint32_t probe = 0; probe < TABLE_SIZE; probe++) {
        if (used[slot] == 0) {
            return 0;
        }
        if (keys[slot] == key) {
            return 1;
        }
        slot = (slot + 1) & (TABLE_SIZE - 1);
    }
    return 0;
}

static int child_workload(void)
{
    uint64_t *keys = calloc(TABLE_SIZE, sizeof(*keys));
    uint32_t *used = calloc(TABLE_SIZE, sizeof(*used));
    uint32_t inserted = 0;

    if (!keys || !used) {
        free(keys);
        free(used);
        return 1;
    }

    for (uint32_t i = 0; i < KEY_COUNT; i++) {
        uint32_t key = i * 2654435761U + 12345U;

        if (table_insert(keys, used, key) == 0) {
            inserted++;
        }
    }

    for (uint32_t i = 0; i < KEY_COUNT; i++) {
        uint32_t key = i * 2654435761U + 12345U;

        if (!table_find(keys, used, key)) {
            free(keys);
            free(used);
            return 2;
        }
    }

    for (uint32_t i = 0; i < KEY_COUNT; i++) {
        uint32_t key = i * 2654435761U + 12345U + 0x80000000U;

        if (table_find(keys, used, key)) {
            free(keys);
            free(used);
            return 3;
        }
    }

    free(keys);
    free(used);
    return inserted ? 0 : 4;
}

int main(void)
{
    pthread_t thread;

    if (pthread_create(&thread, NULL, spinner, NULL) != 0) {
        perror("pthread_create");
        return 2;
    }

    usleep(100000);

    for (int i = 0; i < 20; i++) {
        pid_t pid = fork();
        int status;

        if (pid < 0) {
            perror("fork");
            return 3;
        }
        if (pid == 0) {
            _exit(child_workload());
        }
        if (waitpid(pid, &status, 0) != pid) {
            perror("waitpid");
            return 4;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "child failed: status=%d\n", status);
            return 5;
        }
    }

    atomic_store_explicit(&stop, 1, memory_order_relaxed);
    if (pthread_join(thread, NULL) != 0) {
        perror("pthread_join");
        return 6;
    }

    printf("tu-overlap ok (%lu spins)\n", spin_iters);
    return 0;
}
