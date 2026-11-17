/*
 * fork() from a multi-threaded process must interrupt other vCPUs that are
 * spinning in translated code.  QEMU's start_exclusive() only sets the exit
 * request; it does not send a signal.  If a JIT/TU loop never returns to the
 * C execution loop the request is never observed and fork() deadlocks.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

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

int main(void)
{
    pthread_t thread;

    if (pthread_create(&thread, NULL, spinner, NULL) != 0) {
        perror("pthread_create");
        return 2;
    }

    /* Let the spinner reach its steady-state translated loop. */
    usleep(200000);

    for (int i = 0; i < 50; i++) {
        pid_t pid = fork();
        int status;

        if (pid < 0) {
            perror("fork");
            return 3;
        }
        if (pid == 0) {
            _exit(0);
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

    printf("forkexit ok (%lu spins)\n", spin_iters);
    return 0;
}
