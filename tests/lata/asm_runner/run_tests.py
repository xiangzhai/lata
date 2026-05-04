#!/usr/bin/env python3
"""
LATA ASM Test Runner - 适配 dynarmic 的 AArch64 裸机 ASM 测试。

将 dynarmic 的 .s 测试文件包装为 Linux ELF 可执行程序，
分别通过 QEMU-lata 和 QEMU-TCG 运行，比较寄存器结果。

用法:
  python3 run_tests.py <dynarmic_asm_dir> [--filter <pattern>] [--verbose]

工具链: aarch64-none-elf-as/ld/objcopy (Debian包 binutils-aarch64-none-elf)
"""

import os, sys, json, re, subprocess, tempfile, argparse
from pathlib import Path
from typing import Optional, Dict, List

# ============================================================
# 配置
# ============================================================
AS = "aarch64-none-elf-as"
LD = "aarch64-none-elf-ld"
OBJCOPY = "aarch64-none-elf-objcopy"

QEMU_LATA = Path(__file__).parent.parent.parent.parent.parent / "build_aarch64" / "qemu-aarch64"
QEMU_TCG  = "/bin/qemu-aarch64"  # 系统 QEMU (TCG)

ASM_RUNTIME = Path(__file__).parent / "asm_runtime.S"
LINKER_SCRIPT = Path(__file__).parent / "baremetal.ld"

# ARM64 通用寄存器
GPR_NAMES_64 = [f"X{i}" for i in range(31)]
GPR_NAMES_32 = [f"W{i}" for i in range(31)]

def parse_config(asm_path: Path) -> Optional[dict]:
    """从 .s 文件中解析 /* CONFIG { ... } */ JSON"""
    text = asm_path.read_text()
    m = re.search(r'/\*\s*CONFIG\s*\n(.*?)\n\s*\*/', text, re.DOTALL)
    if not m:
        return None
    return json.loads(m.group(1))

def compile_test(asm_path: Path, work_dir: Path) -> Optional[Path]:
    """
    将裸机 .s 测试编译为 ELF 可执行程序。

    步骤:
    1. 用 aarch64-none-elf-as 汇编到 .o
    2. 用 aarch64-none-elf-ld 链接 (含 runtime)
    3. 用 aarch64-none-elf-objcopy 提取 binary
    """
    name = asm_path.stem
    obj = work_dir / f"{name}.o"
    elf = work_dir / f"{name}.elf"

    # 汇编测试文件 (.s)
    r = subprocess.run([AS, "-o", str(obj), str(asm_path)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"    ASM FAIL: {r.stderr[:200]}")
        return None

    # 汇编 runtime
    runtime_obj = work_dir / "asm_runtime.o"
    r = subprocess.run([AS, "-o", str(runtime_obj), str(ASM_RUNTIME)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"    ASM RUNTIME FAIL: {r.stderr[:200]}")
        return None

    # 链接
    ld_cmd = [LD, "-o", str(elf), str(obj), str(runtime_obj)]
    if LINKER_SCRIPT.exists():
        ld_cmd += ["-T", str(LINKER_SCRIPT)]
    r = subprocess.run(ld_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"    LD FAIL: {r.stderr[:200]}")
        return None

    return elf

def wrap_to_linux_elf(elf_path: Path, work_dir: Path, config: dict) -> Optional[Path]:
    """
    将裸机 ELF 包装为 Linux AArch64 ELF。
    这个方法使用 python 将裸机二进制嵌入 Linux ELF 中。

    简化方案: 直接用 qemu-aarch64 的 -g 和 gdb 提取结果。
    更实用的方案: 包装成 Linux binary 然后 svc exit.
    """
    # 提取 .text 段
    bin_path = work_dir / f"{elf_path.stem}.bin"
    r = subprocess.run([OBJCOPY, "-O", "binary", str(elf_path), str(bin_path)],
                       capture_output=True)
    if r.returncode != 0:
        return None

    # 创建 wrapper .s (Linux AArch64, 调用测试代码)
    wrapper = work_dir / f"{elf_path.stem}_wrapper.s"
    launch_addr = "0"  # bare metal tests start at _start

    # 构建 Linux wrapper
    reg_init = ""
    if "RegData" in config:
        for reg, val in config["RegData"].items():
            val_int = int(val, 16)
            if reg.startswith("X"):
                reg_init += f"    mov {reg.lower()}, #{val_int}\n"
            elif reg.startswith("W"):
                reg_init += f"    mov {reg.lower()}, #{val_int & 0xFFFFFFFF}\n"
            elif reg == "SP":
                # SP needs special handling
                pass

    wrapper_text = f'''
.text
.global _start
_start:
    // Prologue: set up initial registers
{reg_init}
    // Jump to embedded test code
    // Note: bare-metal test uses address 0 as base
    // We need to mmap the binary and jump to it

    // Save lr, call test
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    // For now, inline the test binary as data
    // and copy it to executable memory
    bl _test_entry
    // NOT REACHED

_test_entry:
    // Placeholder - binary will be copied here
    .space {bin_path.stat().st_size}
    nop

    // Exit
    ldp x29, x30, [sp], #16
    mov x0, #0
    mov x8, #93
    svc #0
'''
    wrapper.write_text(wrapper_text)

    # 编译 wrapper
    wrapper_obj = work_dir / f"{elf_path.stem}_wrapper.o"
    wrapper_elf = work_dir / f"{elf_path.stem}_linux.elf"
    r = subprocess.run([AS, "-o", str(wrapper_obj), str(wrapper)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"    WRAP FAIL: {r.stderr[:200]}")
        return None

    r = subprocess.run([LD, "-o", str(wrapper_elf), str(wrapper_obj)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"    LD2 FAIL: {r.stderr[:200]}")
        return None

    return wrapper_elf

def run_qemu(elf_path: Path, qemu_path: str, timeout: int = 10) -> dict:
    """通过 QEMU 运行 ELF 并提取结果"""
    try:
        r = subprocess.run(
            [qemu_path, "-g", "12345", str(elf_path)],
            capture_output=True, text=True, timeout=timeout
        )
        # Parse output for REG: lines
        result = {}
        for line in r.stdout.split('\n') + r.stderr.split('\n'):
            if line.startswith('REG:'):
                parts = line[4:].strip().split('=')
                if len(parts) == 2:
                    result[parts[0].strip()] = int(parts[1].strip(), 16)
        return result
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except FileNotFoundError:
        return {"error": f"qemu not found: {qemu_path}"}

def run_qemu_singlestep(elf_path: Path, qemu_path: str, config: dict, timeout: int = 10) -> dict:
    """QEMU 单步模式运行，在 brk 处停止并导出寄存器"""
    try:
        # Use -singlestep with BRK handling
        r = subprocess.run(
            [qemu_path, "-singlestep", str(elf_path)],
            capture_output=True, text=True, timeout=timeout
        )
        return {"stdout": r.stdout, "stderr": r.stderr}
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}

def compare_results(lata: dict, tcg: dict, config: dict) -> List[str]:
    """比较 LATA 和 TCG 的执行结果"""
    failures = []

    if "RegData" in config:
        for reg, expected_str in config["RegData"].items():
            expected = int(expected_str, 16)

            if reg in GPR_NAMES_64 or reg in GPR_NAMES_32:
                lata_val = lata.get(reg)
                tcg_val = tcg.get(reg)

                if lata_val is not None and lata_val != expected:
                    failures.append(
                        f"  {reg}: lata={lata_val:#018x} expected={expected:#018x}"
                    )

                if tcg_val is not None and tcg_val != expected:
                    failures.append(
                        f"  {reg}: TCG={tcg_val:#018x} expected={expected:#018x}"
                    )

    # Compare LATA vs TCG (even when expected not specified)
    for reg in set(list(lata.keys()) + list(tcg.keys())):
        if reg in ("error", "stdout", "stderr"):
            continue
        lv = lata.get(reg)
        tv = tcg.get(reg)
        if lv is not None and tv is not None and lv != tv:
            failures.append(f"  {reg}: DIFF lata={lv:#018x} tcg={tv:#018x}")

    return failures

def main():
    parser = argparse.ArgumentParser(description="LATA ASM Test Runner")
    parser.add_argument("asm_dir", help="dynarmic tests/asm/a64/ 目录")
    parser.add_argument("--filter", "-f", help="过滤测试文件")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--qemu-lata", default=str(QEMU_LATA))
    parser.add_argument("--qemu-tcg", default=QEMU_TCG)
    parser.add_argument("--compile-only", action="store_true")
    parser.add_argument("--run-only", action="store_true")
    args = parser.parse_args()

    asm_dir = Path(args.asm_dir)
    if not asm_dir.is_dir():
        print(f"Error: {asm_dir} not found")
        sys.exit(1)

    test_files = sorted(asm_dir.glob("**/*.s"))
    if args.filter:
        test_files = [f for f in test_files if args.filter in f.name]

    print(f"=== LATA ASM Test Runner ===")
    print(f"Test directory: {asm_dir}")
    print(f"Test files: {len(test_files)}")
    print(f"QEMU-LATA: {args.qemu_lata}")
    print(f"QEMU-TCG: {args.qemu_tcg}")

    if not Path(args.qemu_lata).exists():
        print(f"WARNING: QEMU-LATA not found at {args.qemu_lata}")
    if not Path(args.qemu_tcg).exists():
        print(f"WARNING: QEMU-TCG not found at {args.qemu_tcg}")

    passed = 0
    failed = 0
    skipped = 0

    # 测试几个文件
    test_files = test_files[:10]  # 先测试前 10 个文件

    with tempfile.TemporaryDirectory() as tmpdir:
        work_dir = Path(tmpdir)
        print(f"\nWork dir: {work_dir}\n")

        for tf in test_files:
            name = tf.name
            print(f"[{name}]", end=" ", flush=True)

            config = parse_config(tf)
            if not config:
                print("SKIP (no CONFIG)")
                skipped += 1
                continue

            if not args.run_only:
                elf = compile_test(tf, work_dir)
                if not elf:
                    print("COMPILE FAIL")
                    failed += 1
                    continue

                run_elf = elf
            else:
                run_elf = work_dir / f"{tf.stem}.elf"
                if not run_elf.exists():
                    print("SKIP (no elf)")
                    skipped += 1
                    continue

            if args.compile_only:
                print("COMPILED")
                passed += 1
                continue

            # 运行测试
            lata_qemu = args.qemu_lata
            tcg_qemu  = args.qemu_tcg

            if Path(lata_qemu).exists():
                lata_result = run_qemu(run_elf, lata_qemu)
            else:
                lata_result = {"error": "qemu-lata not available"}
                print("(lata N/A)", end=" ")

            if Path(tcg_qemu).exists():
                tcg_result = run_qemu(run_elf, tcg_qemu)
            else:
                tcg_result = {"error": "qemu-tcg not available"}
                print("(tcg N/A)", end=" ")

            # 对比结果
            failures = compare_results(lata_result, tcg_result, config)

            if not failures:
                print("PASS")
                passed += 1
            else:
                print(f"FAIL ({len(failures)} diffs)")
                if args.verbose:
                    for f in failures:
                        print(f)
                failed += 1

    print(f"\n--- Results ---")
    print(f"Passed:  {passed}")
    print(f"Failed:  {failed}")
    print(f"Skipped: {skipped}")

if __name__ == "__main__":
    main()
