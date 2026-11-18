#!/usr/bin/env python3
"""Smoke gate for real AArch64 Linux applications under LATA.

This is intentionally separate from ``make check-tcg``: it needs the external
codex/claude binaries and an AArch64 sysroot.  The script skips cleanly when
they are unavailable; set LATA_APP_GATE_REQUIRE=1 in CI to turn a skip into a
failure.

The codex check drives the TUI through a pty (including the terminal queries
the TUI waits for), submits a short prompt and verifies that the event loop
processes it.  That catches both the fork/start_exclusive deadlock and the TU
overlap child crash, without depending on a particular model response.
"""

import argparse
import fcntl
import os
import pty
import re
import resource
import select
import signal
import struct
import subprocess
import sys
import termios
import time


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
DEFAULT_SYSROOT = "/usr/gnemul/lata-aarch64"


def expand(path):
    return os.path.abspath(os.path.expanduser(path))


def skip(msg):
    print("SKIP: " + msg)
    return 0 if os.environ.get("LATA_APP_GATE_REQUIRE") != "1" else 1


def check_binfmt_packaging():
    """Guard the packaged handler's argv[0] preservation.

    codex re-executes itself through the codex-linux-sandbox symlink and
    dispatches on argv[0].  binfmt_misc without the P flag drops the original
    argv[0], so the helper starts as the normal codex CLI and every sandboxed
    shell command fails.  Keep the packaged entry on POCF.
    """
    path = os.path.join(REPO_ROOT, "latabuild", "lata-opt.sh")
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as exc:
        print("FAIL: cannot read %s: %s" % (path, exc))
        return 1

    entry = None
    for line in lines:
        line = line.strip()
        if line.startswith(":lata-aarch64:M::"):
            entry = line
            break
    if entry is None:
        print("FAIL: latabuild/lata-opt.sh has no aarch64 binfmt entry")
        return 1

    fields = entry.split(":")
    flags = fields[-1] if len(fields) >= 8 else ""
    if "P" not in flags:
        print("FAIL: packaged binfmt entry does not preserve argv[0]: %s" %
              entry)
        return 1
    print("ok: binfmt packaging preserves argv[0]")
    return 0


def check_default_ld_prefix(args):
    """Guard the built-in -L default used by binfmt_misc execution.

    Directly executing an AArch64 binary through binfmt_misc cannot pass
    -L, so the sysroot must already be the built-in interpreter prefix.
    """
    if not os.path.isfile(args.qemu):
        return skip("LATA qemu binary not found: %s" % args.qemu)
    try:
        proc = subprocess.run([args.qemu, "--help"], text=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("FAIL: cannot query %s: %s" % (args.qemu, exc))
        return 1
    m = re.search(r"QEMU_LD_PREFIX\s*=\s*(\S+)", proc.stdout)
    if not m or m.group(1) != DEFAULT_SYSROOT:
        print("FAIL: default QEMU_LD_PREFIX is %s, expected %s" %
              (m.group(1) if m else "<missing>", DEFAULT_SYSROOT))
        return 1
    print("ok: default -L prefix is %s" % DEFAULT_SYSROOT)
    return 0


def check_prereqs(args):
    if not os.path.isfile(args.qemu) or not os.access(args.qemu, os.X_OK):
        return skip("LATA qemu binary not found: %s" % args.qemu)
    if not os.path.isdir(args.sysroot):
        return skip("AArch64 sysroot not found: %s" % args.sysroot)
    if not os.path.isfile(args.codex) and \
       not os.path.isfile(args.claude):
        return skip("codex/claude binaries not found")
    return None


def run_version(args, binary, label):
    if not os.path.isfile(binary):
        return skip("%s binary not found: %s" % (label, binary))

    cmd = [args.qemu, "-L", args.sysroot, binary, "--version"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        print("FAIL: %s --version timed out" % label)
        return 1
    if proc.returncode != 0:
        print("FAIL: %s --version rc=%d: %s" %
              (label, proc.returncode,
               proc.stdout.decode("utf-8", "replace")[-500:]))
        return 1
    print("ok: %s --version" % label)
    return 0


class PtyApp:
    def __init__(self, argv, cwd=None):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            try:
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except (ValueError, OSError):
                pass
            if cwd:
                os.chdir(cwd)
            os.environ["TERM"] = "xterm-256color"
            os.execvp(argv[0], argv)
            os._exit(127)

        fcntl.ioctl(self.fd, termios.TIOCSWINSZ,
                    struct.pack("HHHH", 40, 120, 0, 0))
        self.buf = b""
        self.eof = False

    def poll(self, timeout):
        end = time.time() + timeout

        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], min(0.1, end - time.time()))
            if not r:
                continue
            try:
                data = os.read(self.fd, 65536)
            except OSError:
                self.eof = True
                return False
            if not data:
                self.eof = True
                return False
            self.buf += data
            self._answer_queries(data)
        return True

    def _answer_queries(self, data):
        replies = []
        if b"\x1b[>c" in data:
            replies.append(b"\x1b[>0;95;0c")
        elif b"\x1b[c" in data:
            replies.append(b"\x1b[?62;c")
        if b"\x1b[6n" in data:
            replies.append(b"\x1b[1;1R")
        if b"\x1b[?u" in data:
            replies.append(b"\x1b[?0u")
        if b"\x1b]10;?" in data:
            replies.append(b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\")
        if b"\x1b]11;?" in data:
            replies.append(b"\x1b]11;rgb:0000/0000/0000\x1b\\")
        for reply in replies:
            try:
                os.write(self.fd, reply)
            except OSError:
                pass

    def wait_for(self, patterns, timeout):
        rx = re.compile(b"|".join(patterns))
        end = time.time() + timeout
        while time.time() < end:
            if rx.search(self.buf):
                return True
            if not self.poll(min(0.5, end - time.time())):
                return False
        return bool(rx.search(self.buf))

    def send(self, data):
        try:
            os.write(self.fd, data)
        except OSError:
            pass

    def alive(self):
        pid, _ = os.waitpid(self.pid, os.WNOHANG)
        return pid == 0

    def close(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass


def plain(text):
    text = re.sub(rb"\x1b\[[0-9;?<>]*[a-zA-Z]", b"", text)
    text = re.sub(rb"\x1b\][^\x07\x1b]*(\x07|\x1b\\)", b"", text)
    return text.decode("utf-8", "replace")


def run_codex_tui(args):
    if not os.path.isfile(args.codex):
        return skip("codex binary not found: %s" % args.codex)

    argv = [args.qemu, "-L", args.sysroot, args.codex, "--no-daemon"]
    app = PtyApp(argv, cwd=REPO_ROOT)
    try:
        ready = app.wait_for([rb"state=idle:app=codex"], args.startup_timeout)
        if not ready or not app.alive():
            print("FAIL: codex TUI did not reach idle: %s" %
                  plain(app.buf)[-500:])
            return 1

        # Let the final screen settle before submitting.
        app.poll(2.0)
        app.buf = b""
        app.send(b"hi\r")
        processed = app.wait_for(
            [rb"Working", rb"Worked for", rb"Hi!", rb"hi",
             rb"error", rb"Error"], args.input_timeout)
        if not processed:
            print("FAIL: codex TUI did not process input: %s" %
                  plain(app.buf)[-500:])
            return 1
        if not app.alive():
            print("FAIL: codex TUI exited while processing input")
            return 1
        print("ok: codex interactive input")
        return 0
    finally:
        app.close()


def run_claude_tui(args):
    if not os.path.isfile(args.claude):
        return skip("claude binary not found: %s" % args.claude)

    argv = [args.qemu, "-L", args.sysroot, args.claude]
    app = PtyApp(argv, cwd=REPO_ROOT)
    try:
        # Claude's TUI varies with auth/config.  A configured terminal must
        # at least start and keep running; immediate crashes are caught.
        app.poll(args.startup_timeout)
        if app.eof or not app.alive():
            print("FAIL: claude TUI exited during startup: %s" %
                  plain(app.buf)[-500:])
            return 1
        if not app.buf:
            print("FAIL: claude TUI produced no output")
            return 1
        print("ok: claude interactive startup")
        return 0
    finally:
        app.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", default="lata-aarch64")
    parser.add_argument("--sysroot", default=DEFAULT_SYSROOT)
    parser.add_argument("--codex",
                        default="~/codex-aarch64-unknown-linux-musl")
    parser.add_argument("--claude", default="/usr/gnemul/lata-aarch64/bin/claude")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--startup-timeout", type=float, default=45.0)
    parser.add_argument("--input-timeout", type=float, default=30.0)
    parser.add_argument("--no-codex", action="store_true")
    parser.add_argument("--no-claude", action="store_true")
    args = parser.parse_args()

    args.qemu = expand(args.qemu)
    args.sysroot = expand(args.sysroot)
    args.codex = expand(args.codex)
    args.claude = expand(args.claude)

    rc = check_binfmt_packaging()
    if rc != 0:
        return rc

    rc = check_default_ld_prefix(args)
    if rc != 0:
        return rc

    rc = check_prereqs(args)
    if rc is not None:
        return rc

    rc = 0
    if not args.no_codex:
        rc |= run_version(args, args.codex, "codex")
        if rc == 0:
            rc |= run_codex_tui(args)
    if not args.no_claude and rc == 0:
        rc |= run_version(args, args.claude, "claude")
        rc |= run_claude_tui(args)
    return 0 if rc == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
