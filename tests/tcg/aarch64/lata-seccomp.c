/*
 * Regression test for emulated guest seccomp filters.
 *
 * linux-user used to return ENOSYS for the seccomp() syscall.  Sandboxed
 * applications such as codex's codex-linux-sandbox install a seccomp-BPF
 * filter before exec'ing a command; the ENOSYS turned into a Rust panic and
 * every sandboxed shell command failed.
 *
 * The test installs two filters and checks that the second one chains on top
 * of the first, that SECCOMP_RET_ERRNO is reported to the guest, that
 * unrelated syscalls still run, and that PR_GET_SECCOMP reports filter mode.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef SYS_seccomp
#define SYS_seccomp 277
#endif

static int failures;

static void fail(const char *what)
{
    fprintf(stderr, "FAIL: %s (errno=%d %s)\n", what, errno, strerror(errno));
    failures++;
}

static int install_filter(int deny_nr, int deny_errno)
{
    struct sock_filter insns[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, deny_nr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | deny_errno),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = sizeof(insns) / sizeof(insns[0]),
        .filter = insns,
    };

    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) {
        fail("seccomp(SECCOMP_SET_MODE_FILTER)");
        return -1;
    }
    return 0;
}

int main(void)
{
    uint32_t action = SECCOMP_RET_ERRNO;
    long ret;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fail("prctl(PR_SET_NO_NEW_PRIVS)");
        return 1;
    }

    if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action) != 0) {
        fail("seccomp(SECCOMP_GET_ACTION_AVAIL)");
        return 1;
    }

    ret = syscall(SYS_getpid);
    if (ret <= 0) {
        fail("getpid before filters");
        return 1;
    }

    if (install_filter(SYS_getpid, EPERM) != 0) {
        return 1;
    }

    errno = 0;
    ret = syscall(SYS_getpid);
    if (ret != -1 || errno != EPERM) {
        fprintf(stderr, "FAIL: getpid was not denied with EPERM: %ld/%d\n",
                ret, errno);
        failures++;
    }

    if (syscall(SYS_getppid) <= 0) {
        fail("getppid with first filter");
    }

    if (prctl(PR_GET_SECCOMP) != SECCOMP_MODE_FILTER) {
        fail("prctl(PR_GET_SECCOMP) after install");
    }

    if (install_filter(SYS_getppid, ENOSYS) != 0) {
        return 1;
    }

    errno = 0;
    ret = syscall(SYS_getppid);
    if (ret != -1 || errno != ENOSYS) {
        fprintf(stderr,
                "FAIL: chained filter did not deny getppid: %ld/%d\n",
                ret, errno);
        failures++;
    }

    errno = 0;
    ret = syscall(SYS_getpid);
    if (ret != -1 || errno != EPERM) {
        fprintf(stderr, "FAIL: previous filter lost after chain: %ld/%d\n",
                ret, errno);
        failures++;
    }

    if (syscall(SYS_getuid) < 0) {
        fail("getuid with chained filters");
    }

    if (failures) {
        fprintf(stderr, "lata-seccomp: %d failure(s)\n", failures);
        return 1;
    }
    puts("lata-seccomp ok");
    return 0;
}
