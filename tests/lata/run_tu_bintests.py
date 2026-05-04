#!/usr/bin/env python3
"""Focused AArch64 TU bintests for LATA.

The tests are generated as tiny Linux-user ELF binaries so they can be run
through both TCG and LATA.  They intentionally exercise TU-friendly direct CFG
edges and TU boundary cases that should fall back to the dispatcher/FAM path.
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path


TESTS = {
    "direct_branch": r"""
        .text
        .global _start
_start:
        mov     x19, #0
        b       1f
        mov     x19, #99
1:
        add     x19, x19, #3
        b       2f
        mov     x19, #88
2:
        cmp     x19, #3
        b.ne    fail
        b       pass
""",
    "cond_branch": r"""
        .text
        .global _start
_start:
        mov     x19, #0
        mov     x20, #8
1:
        add     x19, x19, x20
        subs    x20, x20, #1
        b.ne    1b
        cmp     x19, #36
        b.eq    2f
        b       fail
2:
        mov     x21, #0
        cmp     x21, #0
        b.eq    3f
        b       fail
3:
        mov     x21, #7
        cmp     x21, #0
        b.ne    pass
        b       fail
""",
    "cbz_tbz": r"""
        .text
        .global _start
_start:
        mov     x19, #0
        cbz     x19, 1f
        b       fail
1:
        mov     x19, #5
        cbnz    x19, 2f
        b       fail
2:
        mov     x20, #0x10
        tbz     x20, #0, 3f
        b       fail
3:
        tbnz    x20, #4, pass
        b       fail
""",
    "call_ret_boundary": r"""
        .text
        .global _start
_start:
        mov     x19, #11
        bl      add_31
        cmp     x0, #42
        b.eq    pass
        b       fail
add_31:
        add     x0, x19, #31
        ret
""",
    "indirect_boundary": r"""
        .text
        .global _start
_start:
        adrp    x16, target
        add     x16, x16, :lo12:target
        br      x16
        b       fail
target:
        mov     x19, #17
        cmp     x19, #17
        b.eq    pass
        b       fail
""",
    "cross_page_direct": r"""
        .text
        .global _start
_start:
        mov     x19, #0
        b       cross_page_target
        b       fail
        .balign 4096
cross_page_target:
        add     x19, x19, #1
        cmp     x19, #1
        b.eq    pass
        b       fail
""",
}


COMMON_TAIL = r"""
pass:
        adrp    x1, pass_msg
        add     x1, x1, :lo12:pass_msg
        mov     x0, #1
        mov     x2, #7
        mov     x8, #64
        svc     #0
        mov     x0, #0
        mov     x8, #94
        svc     #0
fail:
        adrp    x1, fail_msg
        add     x1, x1, :lo12:fail_msg
        mov     x0, #1
        mov     x2, #7
        mov     x8, #64
        svc     #0
        mov     x0, #1
        mov     x8, #94
        svc     #0
        .section .rodata
pass_msg:
        .ascii  "[PASS]\n"
fail_msg:
        .ascii  "[FAIL]\n"
"""


def run(cmd, timeout):
    try:
        return subprocess.run(cmd, text=True, capture_output=True,
                              timeout=timeout)
    except FileNotFoundError as exc:
        raise SystemExit(f"missing tool: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(cmd, -1, exc.stdout or "",
                                           exc.stderr or "TIMEOUT")


def build_test(name, asm, out_dir):
    src = out_dir / f"{name}.S"
    obj = out_dir / f"{name}.o"
    elf = out_dir / f"{name}.elf"
    src.write_text(asm + COMMON_TAIL)

    subprocess.run(["aarch64-none-elf-as", "-march=armv8.5-a", "-o",
                    str(obj), str(src)], check=True)
    subprocess.run(["aarch64-none-elf-ld", "-Ttext=0x400000", "-o",
                    str(elf), str(obj)], check=True)
    return elf


def run_guest(qemu, elf, timeout, debug_tu=False):
    cmd = [qemu]
    if debug_tu:
        cmd += ["-lata-dump", "tu"]
    cmd.append(str(elf))
    result = run(cmd, timeout)
    ok = result.returncode == 0 and "[PASS]" in result.stdout
    return ok, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu-lata", default="build/lata-aarch64")
    parser.add_argument("--qemu-tcg", default="/bin/qemu-aarch64")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--filter")
    parser.add_argument("--debug-tu", action="store_true",
                        help="also pass -lata-dump tu to LATA")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    selected = [(name, asm) for name, asm in TESTS.items()
                if not args.filter or args.filter in name]
    if not selected:
        print("no tests selected", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="lata-tu-bintest-") as tmp:
        out_dir = Path(tmp)
        failures = []

        for name, asm in selected:
            elf = build_test(name, asm, out_dir)
            tcg_ok, tcg = run_guest(args.qemu_tcg, elf, args.timeout)
            lata_ok, lata = run_guest(args.qemu_lata, elf, args.timeout,
                                      args.debug_tu)

            if tcg_ok and lata_ok:
                print(f"PASS {name}")
                continue

            failures.append(name)
            print(f"FAIL {name}")
            print(f"  TCG:  rc={tcg.returncode} stdout={tcg.stdout!r} stderr={tcg.stderr[:200]!r}")
            print(f"  LATA: rc={lata.returncode} stdout={lata.stdout!r} stderr={lata.stderr[:200]!r}")

        if args.keep:
            keep_dir = Path("/tmp/lata-tu-bintests")
            keep_dir.mkdir(exist_ok=True)
            subprocess.run(["cp", "-a", f"{out_dir}/.", str(keep_dir)],
                           check=True)
            print(f"kept generated tests in {keep_dir}")

    print(f"TU bintests: {len(selected) - len(failures)}/{len(selected)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
