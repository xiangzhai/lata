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
    "w_write_high_live_across_tu_edge": r"""
        .text
        .global _start
_start:
        mov     x19, #-1
        mov     w19, #1
        b       check_x19
        b       fail
check_x19:
        lsr     x20, x19, #32
        cbnz    x20, fail
        cmp     x19, #1
        b.eq    pass
        b       fail
""",
    "w_write_high_live_across_cond_edge": r"""
        .text
        .global _start
_start:
        mov     x19, #-1
        mov     w19, #0x1234
        mov     x21, #1
        cbnz    x21, check_x19
        b       fail
check_x19:
        lsr     x20, x19, #32
        cbnz    x20, fail
        movz    x21, #0x1234
        cmp     x19, x21
        b.eq    pass
        b       fail
""",
    "ldrsw_high_live_across_tu_edge": r"""
        .text
        .global _start
_start:
        sub     sp, sp, #16
        mov     w19, #-1
        str     w19, [sp]
        ldrsw   x20, [sp]
        add     sp, sp, #16
        b       check_x20
        b       fail
check_x20:
        lsr     x21, x20, #32
        mov     w22, #-1
        cmp     x21, x22
        b.ne    fail
        cmp     x20, #-1
        b.eq    pass
        b       fail
""",
    "tbz_low_bit_does_not_need_high": r"""
        .text
        .global _start
_start:
        mov     x19, #-1
        mov     w19, #2
        b       check_low_bit
        b       fail
check_low_bit:
        tbz     x19, #0, pass
        b       fail
""",
    "tbz_high_bit_needs_high": r"""
        .text
        .global _start
_start:
        mov     x19, #-1
        mov     w19, #0
        mov     x20, #1
        lsl     x20, x20, #40
        orr     x19, x19, x20
        b       check_high_bit
        b       fail
check_high_bit:
        tbnz    x19, #40, pass
        b       fail
""",
    "nzcv_live_across_direct_edge": r"""
        .text
        .global _start
_start:
        mov     x19, #42
        cmp     x19, #42
        b       check_flags
        b       fail
check_flags:
        b.eq    pass
        b       fail
""",
    "nzcv_live_across_fallthrough_edge": r"""
        .text
        .global _start
_start:
        mov     x19, #9
        mov     x20, #4
        subs    x21, x19, x20
        b       check_flags
        b       fail
check_flags:
        b.gt    pass
        b       fail
""",
    "nzcv_live_same_tb": r"""
        .text
        .global _start
_start:
        mov     x19, #5
        cmp     x19, #5
        b.eq    pass
        b       fail
""",
    "nzcv_dead_after_compare": r"""
        .text
        .global _start
_start:
        mov     x19, #1
        cmp     x19, #2
        mov     x20, #9
        add     x21, x20, #3
        cmp     x21, #12
        b.eq    pass
        b       fail
""",
    "nzcv_adc_sbc_live_across_edge": r"""
        .text
        .global _start
_start:
        mov     x19, #-1
        adds    xzr, x19, #1
        b       check_adc
        b       fail
check_adc:
        mov     x20, #7
        adc     x21, x20, xzr
        cmp     x21, #8
        b.ne    fail
        mov     x22, #0
        cmp     x22, #0
        sbc     x23, x20, xzr
        cmp     x23, #7
        b.eq    pass
        b       fail
""",
    "nzcv_ccmp_live_across_edge": r"""
        .text
        .global _start
_start:
        mov     x19, #5
        cmp     x19, #5
        b       check_ccmp
        b       fail
check_ccmp:
        mov     x20, #9
        ccmp    x20, #9, #0, eq
        b.ne    fail
        ccmp    x20, #8, #4, eq
        b.eq    fail
        b       pass
""",
    "nzcv_csel_family_live_across_edge": r"""
        .text
        .global _start
_start:
        mov     x19, #3
        cmp     x19, #3
        b       check_csel
        b       fail
check_csel:
        mov     x20, #11
        mov     x21, #22
        csel    x22, x20, x21, eq
        cmp     x22, #11
        b.ne    fail
        cmp     x19, #4
        csinc   x23, x20, x21, eq
        cmp     x23, #23
        b.ne    fail
        cmp     x19, #4
        csinv   x24, x20, x21, eq
        mvn     x25, x21
        cmp     x24, x25
        b.ne    fail
        cmp     x19, #4
        csneg   x26, x20, x21, eq
        neg     x27, x21
        cmp     x26, x27
        b.eq    pass
        b       fail
""",
    "nzcv_mrs_msr_live_across_edge": r"""
        .text
        .global _start
_start:
        mov     x19, #0
        cmp     x19, #0
        mrs     x20, nzcv
        mov     x21, #1
        cmp     x21, #0
        b       restore_flags
        b       fail
restore_flags:
        msr     nzcv, x20
        b.eq    pass
        b       fail
""",
    "setf_preserves_c_and_sets_nzv": r"""
        .text
        .global _start
_start:
        mov     x0, #0
        cmp     x0, #0
        mov     w1, #0
        setf8   w1
        mrs     x2, nzcv
        mov     x3, #0x60000000
        cmp     x2, x3
        b.ne    fail

        mov     x0, #0
        cmp     x0, #1
        mov     w1, #0x80
        setf8   w1
        mrs     x2, nzcv
        mov     x3, #0x90000000
        cmp     x2, x3
        b.ne    fail

        mov     x0, #0
        cmp     x0, #1
        mov     w1, #0x8000
        setf16  w1
        mrs     x2, nzcv
        mov     x3, #0x90000000
        cmp     x2, x3
        b.eq    pass
        b       fail
""",
    "rmif_reads_xn_and_updates_masked_nzcv": r"""
        .text
        .global _start
_start:
        mov     x19, #0
        cmp     x19, #0
        mov     x20, #0
        movk    x20, #0xf000, lsl #48
        b       update_flags
        b       fail
update_flags:
        rmif    x20, #60, #0xf
        b.mi    1f
        b       fail
1:
        b.eq    2f
        b       fail
2:
        b.cs    3f
        b       fail
3:
        b.vs    pass
        b       fail
""",
    "fcsel_nzcv_live_across_tu_edge": r"""
        .text
        .global _start
_start:
        mov     x19, #5
        cmp     x19, #5
        b       check_fcsel
        b       fail
check_fcsel:
        fmov    d0, #1.0
        fmov    d1, #2.0
        fcsel   d2, d0, d1, eq
        fmov    x20, d2
        movz    x21, #0
        movk    x21, #0
        movk    x21, #0
        movk    x21, #0x3ff0, lsl #48
        cmp     x20, x21
        b.eq    pass
        b       fail
""",
    "fcadd_vector_live_across_tu_edge": r"""
        .text
        .global _start
_start:
        fmov    s0, #1.0
        movi    v1.4s, #0
        b       do_fcadd
        b       fail
do_fcadd:
        fcadd   v2.4s, v0.4s, v1.4s, #90
        fmov    w20, s2
        movz    w21, #0
        movk    w21, #0x3f80, lsl #16
        cmp     w20, w21
        b.eq    pass
        b       fail
""",
    "vector_ldst_boundary": r"""
        .text
        .global _start
_start:
        movz    x2, #0x7788
        movk    x2, #0x5566, lsl #16
        movk    x2, #0x3344, lsl #32
        movk    x2, #0x1122, lsl #48
        sub     sp, sp, #32
        str     x2, [sp]
        mov     x3, #0
        str     x3, [sp, #8]
        ldr     q0, [sp]
        str     q0, [sp, #16]
        ldr     x1, [sp, #16]
        add     sp, sp, #32
        movz    x2, #0x7788
        movk    x2, #0x5566, lsl #16
        movk    x2, #0x3344, lsl #32
        movk    x2, #0x1122, lsl #48
        cmp     x1, x2
        b.eq    pass
        b       fail
""",
    "blr_boundary": r"""
        .text
        .global _start
_start:
        adrp    x16, target
        add     x16, x16, :lo12:target
        mov     x19, #13
        blr     x16
        cmp     x0, #55
        b.eq    pass
        b       fail
target:
        add     x0, x19, #42
        ret
""",
    "ret_xn_boundary": r"""
        .text
        .global _start
_start:
        bl      target
        cmp     x0, #77
        b.eq    pass
        b       fail
target:
        mov     x17, x30
        mov     x0, #77
        ret     x17
""",
    "fam_ret_x30_state_live": r"""
        .text
        .global _start
_start:
        mov     x19, #0
        mov     x20, #11
        bl      first_call
        cmp     x19, #42
        b.ne    fail
        bl      first_call
        cmp     x19, #84
        b.eq    pass
        b       fail
first_call:
        add     x19, x19, x20
        add     x19, x19, #31
        ret
""",
    "fam_br_state_live": r"""
        .text
        .global _start
_start:
        adrp    x16, target
        add     x16, x16, :lo12:target
        mov     x19, #123
        br      x16
        b       fail
target:
        add     x19, x19, #1
        cmp     x19, #124
        b.eq    pass
        b       fail
""",
    "fam_blr_state_live": r"""
        .text
        .global _start
_start:
        adrp    x16, target
        add     x16, x16, :lo12:target
        mov     x19, #5
        blr     x16
        cmp     x0, #47
        b.eq    pass
        b       fail
target:
        add     x0, x19, #42
        ret
    """,
    "fam_collision_overwrite": r"""
        .text
        .global _start
_start:
        bl      call_a
        cmp     x19, #11
        b.ne    fail
        bl      call_b
        cmp     x19, #33
        b.ne    fail
        bl      call_a
        cmp     x19, #44
        b.eq    pass
        b       fail
call_a:
        adrp    x16, target_a
        add     x16, x16, :lo12:target_a
        br      x16
call_b:
        adrp    x16, target_b
        add     x16, x16, :lo12:target_b
        br      x16
target_a:
        add     x19, x19, #11
        ret
        .org    target_a + 0x40004
target_b:
        add     x19, x19, #22
        ret
    """,
    "fam_tu_interior_hit": r"""
        .text
        .global _start
_start:
        bl      warm_tu
        bl      enter_interior
        cmp     x19, #47
        b.eq    pass
        b       fail
warm_tu:
        mov     x19, #0
        b       interior_target
        b       fail
interior_target:
        add     x19, x19, #5
        ret
enter_interior:
        adrp    x16, interior_target
        add     x16, x16, :lo12:interior_target
        add     x19, x19, #37
        br      x16
    """,
    "fam_invalidate_after_mprotect": r"""
        .text
        .global _start
_start:
        bl      call_target
        cmp     x19, #9
        b.ne    fail
        adrp    x0, target_page
        add     x0, x0, :lo12:target_page
        mov     x1, #4096
        mov     x2, #5
        mov     x8, #226
        svc     #0
        cbnz    x0, fail
        adrp    x0, target_page
        add     x0, x0, :lo12:target_page
        mov     x1, #4096
        mov     x2, #7
        mov     x8, #226
        svc     #0
        cbnz    x0, fail
        adrp    x0, target_page
        add     x0, x0, :lo12:target_page
        mov     x1, #4096
        mov     x2, #5
        mov     x8, #226
        svc     #0
        cbnz    x0, fail
        bl      call_target
        cmp     x19, #18
        b.eq    pass
        b       fail
call_target:
        adrp    x16, target
        add     x16, x16, :lo12:target
        br      x16
        .balign 4096
target_page:
target:
        add     x19, x19, #9
        ret
    """,
    "fam_clone_fresh_cache": r"""
        .text
        .global _start
_start:
        bl      call_target
        cmp     x19, #3
        b.ne    fail
        adrp    x1, child_stack_top
        add     x1, x1, :lo12:child_stack_top
        ldr     x0, =0x50f00
        mov     x2, #0
        mov     x3, #0
        mov     x4, #0
        mov     x8, #220
        svc     #0
        cmp     x0, #0
        b.eq    child
        cmp     x0, #0
        b.lt    fail
        adrp    x20, child_done
        add     x20, x20, :lo12:child_done
1:
        ldr     w21, [x20]
        cbz     w21, 1b
        cmp     w21, #1
        b.ne    fail
        bl      call_target
        cmp     x19, #6
        b.eq    pass
        b       fail
child:
        mov     x19, #0
        bl      call_target
        cmp     x19, #3
        b.ne    child_fail
        adrp    x20, child_done
        add     x20, x20, :lo12:child_done
        mov     w21, #1
        str     w21, [x20]
        mov     x0, #0
        mov     x8, #93
        svc     #0
child_fail:
        adrp    x20, child_done
        add     x20, x20, :lo12:child_done
        mov     w21, #2
        str     w21, [x20]
        mov     x0, #1
        mov     x8, #93
        svc     #0
call_target:
        adrp    x16, target
        add     x16, x16, :lo12:target
        br      x16
target:
        add     x19, x19, #3
        ret
        .data
        .balign 16
child_done:
        .word   0
        .balign 16
child_stack:
        .skip   16384
child_stack_top:
        .text
    """,
    "forced_unlink_direct_edge": r"""
        .text
        .global _start
_start:
        mov     x19, #0
        b       linked_target
        b       fail
linked_target:
        add     x19, x19, #1
        cmp     x19, #1
        b.eq    pass
        b       fail
""",
    "peephole_high_clear_noop_addi": r"""
        .text
        .global _start
_start:
        mov     x19, #-1
        mov     w19, #0x1234
        ubfx    x19, x19, #0, #32
        ubfx    x19, x19, #0, #32
        add     x19, x19, #0
        add     x19, x19, #0
        movz    x20, #0x1234
        cmp     x19, x20
        b.eq    pass
        b       fail
""",
    "peephole_move_chain_dead_write": r"""
        .text
        .global _start
_start:
        mov     x19, #41
        mov     x20, x19
        mov     x21, x20
        mov     x22, #99
        mov     x22, #42
        add     x23, x21, #1
        cmp     x23, x22
        b.eq    pass
        b       fail
""",
    "peephole_small_window": r"""
        .text
        .global _start
_start:
        mov     x19, #-1
        mov     w19, #0x1234
        mov     x22, #0
        ubfx    x19, x19, #0, #32
        add     x22, x22, #1
        ubfx    x19, x19, #0, #32
        mov     x23, #0
        add     x23, x23, #1
        add     x22, x22, #1
        add     x23, x23, #2
        movz    x20, #0x1234
        cmp     x19, x20
        b.ne    fail
        cmp     x22, #2
        b.ne    fail
        cmp     x23, #3
        b.eq    pass
        b       fail
""",
}


TEST_REQUIRED_OUTPUT = {
    "peephole_high_clear_noop_addi": [
        "high_clear=",
        "noop=",
    ],
    "peephole_move_chain_dead_write": [
        "move_chain=",
    ],
    "peephole_small_window": [
        "window=",
    ],
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


def run_guest(qemu, elf, timeout, debug_tu=False, lata_args=None):
    cmd = [qemu]
    if debug_tu:
        cmd += ["-lata-dump", "tu"]
    if lata_args:
        cmd += lata_args
    cmd.append(str(elf))
    result = run(cmd, timeout)
    ok = result.returncode == 0 and "[PASS]" in result.stdout
    return ok, result


def check_required_output(name, result, required):
    text = result.stdout + result.stderr
    missing = [needle for needle in required if needle not in text]
    if missing:
        print(f"FAIL {name} missing debug output: {missing}")
        print(f"  stderr={result.stderr[:1000]!r}")
        return False
    return True


def parse_peephole_stat(text, key):
    marker = f"{key}="
    pos = text.find(marker)
    if pos < 0:
        return None
    pos += len(marker)
    end = pos
    while end < len(text) and text[end].isdigit():
        end += 1
    if end == pos:
        return None
    return int(text[pos:end])


def check_required_peephole_stats(name, result, required):
    text = result.stdout + result.stderr
    missing = []
    zero = []

    for needle in required:
        key = needle[:-1] if needle.endswith("=") else needle
        value = parse_peephole_stat(text, key)
        if value is None:
            missing.append(key)
        elif value <= 0:
            zero.append(key)

    if missing or zero:
        print(f"FAIL {name} peephole stats missing={missing} zero={zero}")
        print(f"  stderr={result.stderr[:1000]!r}")
        return False
    return True


def check_debug_surface_output(name, result):
    text = result.stdout + result.stderr

    if "[LATA] TU" not in text:
        print(f"SKIP {name} debug surface: TU debug output is not enabled")
        return True

    needles = ["[LATA] TU", "fallback", "edge"]
    if name == "forced_unlink_direct_edge":
        needles.append("unlink")
    return check_required_output(name, result, needles)


def qemu_supports_arg(qemu, arg):
    result = run([qemu, "--help"], 10)
    return arg in (result.stdout + result.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu-lata", default="build/lata-aarch64")
    parser.add_argument("--qemu-tcg", default="/bin/qemu-aarch64")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--filter")
    parser.add_argument("--debug-tu", action="store_true",
                        help="also pass -lata-dump tu to LATA")
    parser.add_argument("--check-debug-surface", action="store_true",
                        help="verify TU dump, TU stats and forced unlink output")
    parser.add_argument("--lata-arg", action="append", default=[],
                        help="extra argument passed to QEMU-LATA; repeatable")
    parser.add_argument("--fam-modes",
                        help="comma-separated -lata-fam-cache modes to test, "
                             "for example -1,0,1")
    parser.add_argument("--require-lata-output", action="append", default=[],
                        help="substring required in LATA stdout/stderr; repeatable")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    has_debug_cli = qemu_supports_arg(args.qemu_lata, "-lata-dump")
    has_peephole_stats = qemu_supports_arg(args.qemu_lata,
                                           "-lata-peephole-stats")
    has_tu_debug = has_debug_cli and qemu_supports_arg(args.qemu_lata,
                                                       "-lata-tu-stats")
    if args.check_debug_surface and not has_tu_debug:
        print("SKIP debug surface checks: LATA binary lacks debug/TU CLI")
        args.check_debug_surface = False

    selected = [(name, asm) for name, asm in TESTS.items()
                if not args.filter or args.filter in name]
    if not selected:
        print("no tests selected", file=sys.stderr)
        return 1
    if args.fam_modes:
        lata_runs = []
        for mode in args.fam_modes.split(","):
            mode = mode.strip()
            if not mode:
                continue
            lata_runs.append((f"fam={mode}",
                              args.lata_arg + ["-lata-fam-cache", mode]))
        if not lata_runs:
            print("no FAM modes selected", file=sys.stderr)
            return 1
    else:
        lata_runs = [("default", args.lata_arg)]
    if has_peephole_stats:
        lata_runs = [(label, run_args + ["-lata-peephole-stats"])
                     for label, run_args in lata_runs]

    with tempfile.TemporaryDirectory(prefix="lata-tu-bintest-") as tmp:
        out_dir = Path(tmp)
        failures = []

        for name, asm in selected:
            elf = build_test(name, asm, out_dir)
            tcg_ok, tcg = run_guest(args.qemu_tcg, elf, args.timeout)
            lata_results = []
            lata_ok = True
            for label, lata_args in lata_runs:
                ok, result = run_guest(args.qemu_lata, elf, args.timeout,
                                       args.debug_tu, lata_args)
                if ok and args.require_lata_output:
                    ok = check_required_output(f"{name} {label}", result,
                                               args.require_lata_output)
                if ok and has_peephole_stats and name in TEST_REQUIRED_OUTPUT:
                    ok = check_required_peephole_stats(
                        f"{name} {label}", result,
                        TEST_REQUIRED_OUTPUT[name])
                if ok and args.check_debug_surface:
                    ok = check_debug_surface_output(f"{name} {label}", result)
                lata_results.append((label, ok, result))
                lata_ok = lata_ok and ok

            if tcg_ok and lata_ok:
                print(f"PASS {name}")
                continue

            failures.append(name)
            print(f"FAIL {name}")
            print(f"  TCG:  rc={tcg.returncode} stdout={tcg.stdout!r} stderr={tcg.stderr[:200]!r}")
            for label, ok, result in lata_results:
                print(f"  LATA[{label}]: ok={ok} rc={result.returncode} "
                      f"stdout={result.stdout!r} stderr={result.stderr[:200]!r}")

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
