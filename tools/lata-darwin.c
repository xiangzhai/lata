/*
 * Standalone launcher for Darwin AArch64 Mach-O executables.
 *
 * Copyright (c) 2026, Loongson Technology. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is part of LATA but is deliberately not linked into
 * qemu-aarch64.  A Mach-O is not an ELF, so the normal linux-user loader
 * cannot start it.  Darling's mldr is a Linux AArch64 ELF that maps the
 * Mach-O image and hands control to dyld/libSystem; this wrapper starts
 * mldr under LATA and lets the existing AArch64 translator execute the
 * whole Darwin runtime.
 */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define DSERVER_WAIT_TICKS 300
#define DEFAULT_SYSROOT "/usr/gnemul/lata-aarch64"

static const char *env_or(const char *name, const char *fallback)
{
    const char *value = getenv(name);
    return value && value[0] ? value : fallback;
}

static bool read_self(char *out, size_t out_size)
{
    ssize_t n = readlink("/proc/self/exe", out, out_size - 1);
    if (n <= 0) {
        return false;
    }
    out[n] = '\0';
    return true;
}

static bool is_darwin_macho(const char *path)
{
    unsigned char magic[4];
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    ssize_t n = read(fd, magic, sizeof(magic));
    close(fd);
    if (n != (ssize_t)sizeof(magic)) {
        return false;
    }
    return (magic[0] == 0xcf && magic[1] == 0xfa &&
            magic[2] == 0xed && magic[3] == 0xfe) ||
           (magic[0] == 0xce && magic[1] == 0xfa &&
            magic[2] == 0xed && magic[3] == 0xfe) ||
           (magic[0] == 0xca && magic[1] == 0xfe &&
            magic[2] == 0xba && magic[3] == 0xbe);
}

static int find_target_arg(int argc, char **argv)
{
    /*
     * binfmt_misc with the P flag replaces the interpreter's argv[0] with
     * the original executable path, so the Mach-O target can also be
     * argv[0].  argv[0] is the wrapper itself for a direct
     * `lata-darwin <target>` invocation and is not a Mach-O then.
     */
    for (int i = 0; i < argc; i++) {
        if (argv[i][0] != '-' && is_darwin_macho(argv[i])) {
            return i;
        }
    }
    return -1;
}

static bool is_darling_root(const char *root)
{
    char path[PATH_MAX];

    if (!root || !root[0] || strlen(root) + 16 >= sizeof(path)) {
        return false;
    }
    snprintf(path, sizeof(path), "%s/usr/lib/dyld", root);
    return access(path, R_OK) == 0;
}

static bool find_darling_root(char *out, size_t out_size)
{
    const char *root = getenv("NBL_DARWIN_ROOT");
    if (root && root[0]) {
        snprintf(out, out_size, "%s", root);
        return is_darling_root(out);
    }

    const char *stage = getenv("DARLING_STAGE");
    if (stage && stage[0]) {
        snprintf(out, out_size, "%s/libexec/darling", stage);
        if (is_darling_root(out)) {
            return true;
        }
    }

    char self[PATH_MAX];
    if (read_self(self, sizeof(self))) {
        char *slash = strrchr(self, '/');
        if (slash) {
            *slash = '\0';
        }

        static const char *const candidates[] = {
            "darling-stage-aarch64-full/usr/local/libexec/darling",
            "darling-stage-aarch64/usr/local/libexec/darling",
            "darling-stage-aarch64-m0/usr/local/libexec/darling",
            "usr/local/libexec/darling",
        };
        char dir[PATH_MAX];
        snprintf(dir, sizeof(dir), "%s", self);
        for (int depth = 0; depth < 8; depth++) {
            for (size_t i = 0; i < ARRAY_SIZE(candidates); i++) {
                snprintf(out, out_size, "%s/%s", dir, candidates[i]);
                if (is_darling_root(out)) {
                    return true;
                }
            }
            slash = strrchr(dir, '/');
            if (!slash || slash == dir) {
                break;
            }
            *slash = '\0';
        }
    }

    snprintf(out, out_size, "%s", "/usr/local/libexec/darling");
    return is_darling_root(out);
}

static bool find_mldr(char *out, size_t out_size, const char *root)
{
    const char *mldr = getenv("NBL_DARWIN_MLDR");
    if (mldr && mldr[0]) {
        snprintf(out, out_size, "%s", mldr);
        return access(out, R_OK) == 0;
    }

    static const char *const names[] = {
        "usr/libexec/darling/mldr.real",
        "usr/libexec/darling/mldr",
        "bin/mldr",
    };
    for (size_t i = 0; i < ARRAY_SIZE(names); i++) {
        snprintf(out, out_size, "%s/%s", root, names[i]);
        if (access(out, R_OK) == 0) {
            return true;
        }
    }
    return false;
}

static bool find_lata(char *out, size_t out_size)
{
    const char *env = getenv("LATA_AARCH64");
    if (env && env[0]) {
        snprintf(out, out_size, "%s", env);
        if (access(out, X_OK) == 0) {
            return true;
        }
    }

    char self[PATH_MAX];
    if (read_self(self, sizeof(self))) {
        char *slash = strrchr(self, '/');
        if (slash) {
            *slash = '\0';
            snprintf(out, out_size, "%s/lata-aarch64", self);
            if (access(out, X_OK) == 0) {
                return true;
            }
        }
    }

    snprintf(out, out_size, "%s", "/usr/bin/lata-aarch64");
    return access(out, X_OK) == 0;
}

static bool dserver_alive(const char *socket_path)
{
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
    bool alive = connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0;
    close(fd);
    return alive;
}

static void server_pid_path(char *out, size_t out_size, const char *prefix)
{
    snprintf(out, out_size, "%s/.lata-darwin-server.pid", prefix);
}

static int remove_tree_entry(const char *path, const struct stat *st,
                             int type, struct FTW *ftw)
{
    (void)st;
    (void)type;
    (void)ftw;
    return remove(path);
}

static void remove_tree(const char *path)
{
    nftw(path, remove_tree_entry, 16, FTW_DEPTH | FTW_PHYS);
}

/*
 * /proc/<pid>/cmdline is a NUL-separated argv list, so a plain strstr() only
 * ever sees argv[0].  Check each argument instead, otherwise a recycled pid
 * that still belongs to us is never recognised and the stale darlingserver
 * survives every run.
 */
static bool cmdline_has_arg(const char *cmdline, size_t len, const char *want)
{
    size_t i = 0;

    while (i < len) {
        size_t n = strnlen(cmdline + i, len - i);
        if (n > 0 && strstr(cmdline + i, want) != NULL) {
            return true;
        }
        i += n + 1;
    }
    return false;
}

/*
 * A previous run may have left darlingserver (and its socket) behind.  It
 * belongs to a dead guest session, so reusing it makes the new guest hang or
 * fail in set_executable_path().  Stop it and start a clean server.
 */
static void stop_previous_server(const char *prefix, const char *socket_path)
{
    char path[PATH_MAX];
    server_pid_path(path, sizeof(path), prefix);

    FILE *file = fopen(path, "r");
    if (file) {
        long pid = 0;
        if (fscanf(file, "%ld", &pid) == 1 && pid > 0) {
            char proc_path[64];
            char cmdline[512] = { 0 };
            ssize_t n = 0;
            snprintf(proc_path, sizeof(proc_path), "/proc/%ld/cmdline", pid);
            int fd = open(proc_path, O_RDONLY);
            if (fd >= 0) {
                n = read(fd, cmdline, sizeof(cmdline) - 1);
                close(fd);
                if (n <= 0) {
                    n = 0;
                }
                cmdline[n] = '\0';
            }
            if (cmdline_has_arg(cmdline, (size_t)n, "darlingserver")) {
                kill((pid_t)pid, SIGTERM);
                for (int i = 0; i < 20 && kill((pid_t)pid, 0) == 0; i++) {
                    struct timespec delay = { .tv_sec = 0,
                                              .tv_nsec = 100000000 };
                    nanosleep(&delay, NULL);
                }
                if (kill((pid_t)pid, 0) == 0) {
                    kill((pid_t)pid, SIGKILL);
                }
            }
        }
        fclose(file);
        unlink(path);
    }
    unlink(socket_path);
}

static bool start_dserver(const char *root, const char *prefix,
                          const char *socket_path, const char *lata,
                          const char *sysroot)
{
    const char *server = getenv("NBL_DARWIN_SERVER");
    char bind_dir[PATH_MAX];
    char server_path[PATH_MAX];
    char server_real[PATH_MAX];
    char command[PATH_MAX * 4];

    snprintf(bind_dir, sizeof(bind_dir), "%s", root);
    char *slash = strrchr(bind_dir, '/');
    if (!slash || strcmp(slash, "/darling") != 0) {
        fprintf(stderr, "lata-darwin: invalid Darling root: %s\n", root);
        return false;
    }
    *slash = '\0';
    slash = strrchr(bind_dir, '/');
    if (!slash || strcmp(slash, "/libexec") != 0) {
        fprintf(stderr, "lata-darwin: invalid Darling root: %s\n", root);
        return false;
    }
    *slash = '\0'; /* <stage>/usr/local */

    snprintf(server_path, sizeof(server_path), "%s/bin/darlingserver",
             bind_dir);
    snprintf(server_real, sizeof(server_real), "%s/bin/darlingserver.real",
             bind_dir);

    if (!server || !server[0]) {
        server = server_path;
    }
    if (access(server_real, X_OK) != 0) {
        snprintf(server_real, sizeof(server_real), "%s", server);
    }

    snprintf(command, sizeof(command),
             "mount --bind '%s' /usr/local || exit 1; "
             "export DARLING_NOOVERLAYFS=1 DSERVER_KEEP_STDIO=1 "
             "DSERVER_INIT=/nonexistent; "
             "exec 9>/dev/null; exec '%s' -L '%s' -0 darlingserver "
             "'%s' '%s' 0 0 9 0",
             bind_dir, lata, sysroot, server_real, prefix);

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "lata-darwin: fork for darlingserver failed: %s\n",
                strerror(errno));
        return false;
    }
    if (pid == 0) {
        if (getenv("NBL_DARWIN_DEBUG") == NULL) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                if (devnull > STDERR_FILENO) {
                    close(devnull);
                }
            }
        }
        if (geteuid() == 0) {
            execlp("unshare", "unshare", "-m", "sh", "-c", command,
                   (char *)NULL);
        } else {
            execlp("unshare", "unshare", "-Ur", "-m", "sh", "-c", command,
                   (char *)NULL);
        }
        _exit(127);
    }

    char pid_path[PATH_MAX];
    server_pid_path(pid_path, sizeof(pid_path), prefix);
    int pid_fd = open(pid_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (pid_fd >= 0) {
        char pidbuf[32];
        int len = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)pid);
        (void)write(pid_fd, pidbuf, len);
        close(pid_fd);
    }

    for (int i = 0; i < DSERVER_WAIT_TICKS; i++) {
        if (access(socket_path, F_OK) == 0) {
            return true;
        }
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000 };
        nanosleep(&delay, NULL);
    }
    fprintf(stderr, "lata-darwin: timed out waiting for darlingserver socket %s\n",
            socket_path);
    return false;
}

/*
 * Re-exec in a private user+mount namespace when started as an ordinary user.
 * darlingserver must share a user namespace with the translated guest for
 * process_vm_readv() to pass Yama's ptrace_scope=2 check.
 */
static void reexec_in_userns(int argc, char **argv, int target)
{
    char self[PATH_MAX];
    if (!read_self(self, sizeof(self))) {
        return;
    }

    char **args = calloc((size_t)argc + 6, sizeof(*args));
    if (!args) {
        return;
    }
    int ai = 0;
    args[ai++] = (char *)"unshare";
    args[ai++] = (char *)"-Ur";
    args[ai++] = (char *)"-m";
    args[ai++] = (char *)"--";
    args[ai++] = self;
    /*
     * In the usual `lata-darwin <target>` form argv[0] is the wrapper and
     * argv[1..] already carries the target.  Under binfmt_misc P the target
     * is argv[0], so it must be forwarded explicitly.
     */
    for (int i = target == 0 ? 0 : 1; i < argc; i++) {
        args[ai++] = argv[i];
    }
    args[ai] = NULL;

    setenv("NBL_DARWIN_IN_NS", "1", 1);
    execvp("unshare", args);
    unsetenv("NBL_DARWIN_IN_NS");
    free(args);
}

static void redirect_guest_stderr(void)
{
    const char *log = getenv("LATA_DARWIN_STDERR");
    if (!log || !log[0] || !isatty(STDERR_FILENO) ||
        getenv("NBL_DARWIN_DEBUG") != NULL) {
        return;
    }
    int fd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd >= 0) {
        dup2(fd, STDERR_FILENO);
        close(fd);
    }
}

int main(int argc, char **argv)
{
    int target = find_target_arg(argc, argv);
    if (target < 0) {
        fprintf(stderr, "lata-darwin: no Mach-O executable in arguments\n");
        return 1;
    }

    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "-L") == 0) {
            setenv("NBL_LATA_SYSROOT", argv[i + 1], 1);
        } else if (strncmp(argv[i], "-L", 2) == 0 && argv[i][2] != '\0') {
            setenv("NBL_LATA_SYSROOT", argv[i] + 2, 1);
        }
    }

    if (geteuid() != 0 && getenv("NBL_DARWIN_IN_NS") == NULL) {
        reexec_in_userns(argc, argv, target);
    }

    char root[PATH_MAX];
    char mldr[PATH_MAX];
    char prefix[PATH_MAX];
    char socket_path[PATH_MAX];
    char lata[PATH_MAX];

    if (!find_lata(lata, sizeof(lata))) {
        fprintf(stderr, "lata-darwin: cannot find lata-aarch64; "
                "set LATA_AARCH64\n");
        return 1;
    }
    if (!find_darling_root(root, sizeof(root))) {
        fprintf(stderr, "lata-darwin: cannot find a Darling root; "
                "set NBL_DARWIN_ROOT or DARLING_STAGE\n");
        return 1;
    }
    if (!find_mldr(mldr, sizeof(mldr), root)) {
        fprintf(stderr, "lata-darwin: mldr not found under %s\n", root);
        return 1;
    }

    /*
     * Darling executes Mach-O helpers (for example vchroot) through
     * binfmt_misc, which starts a fresh launcher.  Publish the resolved
     * runtime so those nested launches do not have to rediscover it from
     * an installed path that may differ from this build tree.
     */
    setenv("NBL_DARWIN_ROOT", root, 1);
    setenv("NBL_DARWIN_MLDR", mldr, 1);
    setenv("LATA_AARCH64", lata, 1);

    const char *configured_prefix = getenv("NBL_DARWIN_PREFIX");
    if (!configured_prefix || !configured_prefix[0]) {
        configured_prefix = getenv("DPREFIX");
    }
    bool default_prefix = !configured_prefix || !configured_prefix[0];
    if (!default_prefix) {
        snprintf(prefix, sizeof(prefix), "%s", configured_prefix);
    } else {
        snprintf(prefix, sizeof(prefix), "%s/.lata-darling-prefix",
                 env_or("HOME", "/tmp"));
    }
    mkdir(prefix, 0755);

    const char *configured_socket = getenv("NBL_DARWIN_SOCKET");
    if (configured_socket && configured_socket[0]) {
        snprintf(socket_path, sizeof(socket_path), "%s", configured_socket);
    } else {
        snprintf(socket_path, sizeof(socket_path), "%s/.darlingserver.sock",
                 prefix);
    }

    const char *sysroot = env_or("NBL_LATA_SYSROOT", DEFAULT_SYSROOT);
    setenv("NBL_LATA_SYSROOT", sysroot, 1);

    if (configured_socket && configured_socket[0]) {
        if (!dserver_alive(socket_path) &&
            !start_dserver(root, prefix, socket_path, lata, sysroot)) {
            return 1;
        }
    } else {
        stop_previous_server(prefix, socket_path);
        if (default_prefix) {
            /* A killed TUI leaves launchd state behind; start clean. */
            remove_tree(prefix);
            mkdir(prefix, 0755);
        }
        if (!start_dserver(root, prefix, socket_path, lata, sysroot)) {
            return 1;
        }
    }

    setenv("__mldr_sockpath", socket_path, 1);
    setenv("__mldr_DYLD_ROOT_PATH", root, 1);
    if (getenv("DYLD_LIBRARY_PATH") == NULL) {
        setenv("DYLD_LIBRARY_PATH", "", 1);
    }

#ifdef PR_SET_PTRACER
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif

    char argv0[PATH_MAX + 16];
    snprintf(argv0, sizeof(argv0), "mldr!%s", argv[target]);

    int new_argc = 6 + (argc - target);
    char **new_argv = calloc((size_t)new_argc + 1, sizeof(*new_argv));
    if (!new_argv) {
        fprintf(stderr, "lata-darwin: out of memory\n");
        return 1;
    }
    int ai = 0;
    new_argv[ai++] = lata;
    new_argv[ai++] = (char *)"-L";
    new_argv[ai++] = (char *)sysroot;
    new_argv[ai++] = (char *)"-0";
    new_argv[ai++] = argv0;
    new_argv[ai++] = mldr;
    new_argv[ai++] = argv[target];
    for (int i = target + 1; i < argc; i++) {
        new_argv[ai++] = argv[i];
    }
    new_argv[ai] = NULL;

    char stderr_log[PATH_MAX];
    snprintf(stderr_log, sizeof(stderr_log), "%s/.lata-darling.log",
             env_or("HOME", "/tmp"));
    setenv("LATA_DARWIN_STDERR", stderr_log, 1);
    redirect_guest_stderr();
    execv(lata, new_argv);
    fprintf(stderr, "lata-darwin: cannot exec %s: %s\n", lata,
            strerror(errno));
    return 1;
}
