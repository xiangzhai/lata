/*
 * Regression test for guest execve() of an AArch64 ELF image.
 *
 * QEMU user-mode used to hand every guest execve() to the host kernel.
 * Without binfmt_misc support for AArch64 that fails with ENOEXEC, which
 * breaks programs that re-execute themselves or launch their own helper
 * through a symlink (codex's codex-linux-sandbox does exactly that).
 *
 * The test re-executes itself through a symlink and verifies that argv[0]
 * is preserved (the helper sets it to "lata-exec-helper") and that the
 * guest environment survives the exec.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int check_child(int argc, char **argv)
{
    const char *mark = getenv("LATA_EXEC_MARK");

    if (argc != 3 || strcmp(argv[1], "child") != 0 ||
        strcmp(argv[2], "payload") != 0) {
        fprintf(stderr, "bad argv after execve: argc=%d\n", argc);
        return 1;
    }
    if (strcmp(argv[0], "lata-exec-helper") != 0) {
        fprintf(stderr, "bad argv[0] after execve: %s\n", argv[0]);
        return 1;
    }
    if (!mark || strcmp(mark, "yes") != 0) {
        fprintf(stderr, "environment lost across execve\n");
        return 1;
    }

    puts("lata-exec ok");
    return 0;
}

int main(int argc, char **argv)
{
    char exe[PATH_MAX];
    char dir[] = "/tmp/lata-exec-XXXXXX";
    char link[PATH_MAX];
    char *args[] = { "lata-exec-helper", "child", "payload", NULL };
    int n;

    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        return check_child(argc, argv);
    }

    if (!realpath(argv[0], exe)) {
        perror("realpath");
        return 1;
    }
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        return 1;
    }
    n = snprintf(link, sizeof(link), "%s/helper", dir);
    if (n < 0 || (size_t)n >= sizeof(link)) {
        fprintf(stderr, "link path too long\n");
        return 1;
    }
    if (symlink(exe, link) != 0) {
        perror("symlink");
        return 1;
    }
    if (setenv("LATA_EXEC_MARK", "yes", 1) != 0) {
        perror("setenv");
        return 1;
    }

    execv(link, args);
    fprintf(stderr, "execv(%s): %s\n", link, strerror(errno));
    return 1;
}
