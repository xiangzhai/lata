#!/usr/bin/env python3
"""Run a small AArch64 rootfs smoke set through LATA and print FAM stats."""

import argparse
import os
import subprocess
import sys
from pathlib import Path


DEFAULT_PREFIXES = [
    Path("/usr/gnemul/qemu-aarch64"),
    Path("/usr/aarch64-linux-gnu"),
    Path("/opt/aarch64-rootfs"),
]


def find_prefix(explicit):
    if explicit:
        prefix = Path(explicit)
        if prefix.exists():
            return prefix
        raise SystemExit(f"rootfs prefix not found: {prefix}")

    for prefix in DEFAULT_PREFIXES:
        if (prefix / "usr/bin").is_dir() or (prefix / "bin").is_dir():
            return prefix
    raise SystemExit("no AArch64 rootfs prefix found; pass --prefix")


def find_program(prefix, names):
    for name in names:
        for subdir in ("usr/bin", "bin", "usr/lib/p7zip"):
            path = prefix / subdir / name
            if path.exists() and os.access(path, os.X_OK):
                return path
    return None


def run_case(qemu, prefix, name, program, args, timeout):
    cmd = [qemu, "-L", str(prefix)]
    if qemu_supports_arg(qemu, "-lata-fam-stats"):
        cmd.append("-lata-fam-stats")
    cmd += [str(program)] + args
    try:
        result = subprocess.run(cmd, text=True, capture_output=True,
                                timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        print(f"TIMEOUT {name}")
        if exc.stderr:
            print(exc.stderr[-1200:])
        return False

    text = result.stdout + result.stderr
    ok = result.returncode == 0
    print(f"{'PASS' if ok else 'FAIL'} {name} rc={result.returncode}")
    for line in text.splitlines():
        if line.startswith("[LATA] indirect-jmp") or line.startswith("[LATA] FAM"):
            print(f"  {line}")
    if not ok:
        print(text[-2000:])
    return ok


def qemu_supports_arg(qemu, arg):
    try:
        result = subprocess.run([qemu, "--help"], text=True,
                                capture_output=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return arg in (result.stdout + result.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix")
    parser.add_argument("--qemu-lata", default="build_aarch64/lata-aarch64")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    prefix = find_prefix(args.prefix)
    qemu = str(Path(args.qemu_lata))
    cases = []

    grep = find_program(prefix, ["grep"])
    if grep:
        cases.append(("grep", grep, ["-n", "root", str(prefix / "etc/passwd")]))

    sha256sum = find_program(prefix, ["sha256sum"])
    if sha256sum:
        cases.append(("sha256sum", sha256sum, [str(prefix / "etc/passwd")]))

    sevenz = find_program(prefix, ["7z", "7za"])
    if sevenz:
        cases.append(("7z-b-mmt1", sevenz, ["b", "-mmt1"]))

    if not cases:
        raise SystemExit(f"no smoke programs found under {prefix}")

    failures = 0
    print(f"rootfs prefix: {prefix}")
    for name, program, program_args in cases:
        if not run_case(qemu, prefix, name, program, program_args, args.timeout):
            failures += 1

    print(f"rootfs smoke: {len(cases) - failures}/{len(cases)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
