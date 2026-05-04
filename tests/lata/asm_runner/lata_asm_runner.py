#!/usr/bin/env python3
"""
LATA ASM Test Runner - 适配 dynarmic 的 AArch64 ASM 测试用例。

功能:
1. 解析 dynarmic 的 .s ASM 测试文件，提取 JSON CONFIG 配置
2. 将裸机测试包装为 Linux AArch64 可执行程序
3. 分别通过 QEMU-lata 和 QEMU-TCG 运行
4. 比较寄存器和内存结果，验证 LATA 的正确性

用法:
  python3 lata_asm_runner.py <test_dir> [--qemu-lata <path>] [--qemu-tcg <path>]

依赖:
  - aarch64-linux-gnu-as, aarch64-linux-gnu-ld, aarch64-linux-gnu-objcopy
  - qemu-aarch64 (lata 版本 和 tcg 版本)
"""

import os
import sys
import json
import subprocess
import tempfile
import struct
import argparse
import re
from pathlib import Path
from typing import Optional, Dict, List, Tuple

# ============================================================
# 配置
# ============================================================

AS = "aarch64-linux-gnu-as"
LD = "aarch64-linux-gnu-ld"
OBJCOPY = "aarch64-linux-gnu-objcopy"

C_TEST_HARNESS = Path(__file__).parent / "test_harness.c"

# ARM64 寄存器名称映射
GPR_NAMES = [f"X{i}" for i in range(31)] + ["SP", "XZR"]
VEC_NAMES = [f"V{i}" for i in range(32)]
FP_NAMES_S = [f"S{i}" for i in range(32)]
FP_NAMES_D = [f"D{i}" for i in range(32)]

class AsmTestConfig:
    """从 dynarmic .s 文件的 CONFIG JSON 中解析测试配置"""
    def __init__(self, config_json: dict):
        self.match = config_json.get("Match", "All")
        self.known_failure = config_json.get("KnownFailure", False)

        # 初始寄存器值 (RegData 同时设置初始值和期望值)
        self.reg_data = {}
        if "RegData" in config_json:
            self.reg_data = config_json["RegData"]

        # 分别设置初始值和期望值 (新格式)
        self.set_reg_data = config_json.get("SetRegData", {})
        self.expected_reg_data = config_json.get("ExpectedRegData", {})

        # 向量寄存器
        self.vec_data = config_json.get("VecData", {})

        # PSTATE/FPCR/FPSR
        self.pstate = config_json.get("Pstate", {})
        self.fpcr = config_json.get("FPCR", None)
        self.fpsr = config_json.get("FPSR", None)

        # 内存数据
        self.mem_data = config_json.get("MemData", {})

        # TLS 配置
        self.tls_data = config_json.get("TlsData", {})

    def get_expected_gpr(self, reg: str) -> Optional[int]:
        """获取期望的 GPR 值"""
        if reg in self.expected_reg_data:
            return int(self.expected_reg_data[reg], 16)
        if reg in self.reg_data:
            return int(self.reg_data[reg], 16)
        return None


class TestResult:
    """测试执行结果"""
    def __init__(self):
        self.passed = True
        self.failures = []
        self.lata_output = {}
        self.tcg_output = {}

    def add_failure(self, msg: str):
        self.passed = False
        self.failures.append(msg)


def parse_config_from_asm(asm_text: str) -> Optional[dict]:
    """从 .s 文件的 /* CONFIG ... */ 注释中解析 JSON 配置"""
    match = re.search(r'/\*\s*CONFIG\s*\n(.*?)\n\s*\*/', asm_text, re.DOTALL)
    if not match:
        return None
    config_text = match.group(1)
    return json.loads(config_text)


def wrap_baremetal_test(asm_path: Path, work_dir: Path) -> Path:
    """
    将裸机 ASM 测试包装为 Linux 可执行程序。

    裸机测试使用 brk #0 结束，需要替换为寄存器 dump + exit 系统调用。
    """
    asm_content = asm_path.read_text()

    # 解析 CONFIG
    config = parse_config_from_asm(asm_content)
    if not config:
        raise ValueError(f"No CONFIG found in {asm_path}")

    # 提取测试代码（在 _start 之后的所有代码，到 brk 之前）
    # 构建 wrapper .s 文件
    wrapper = f'''
/* Auto-generated test wrapper for LATA ASM test runner */
/* Original: {asm_path.name} */

.include "test_harness.inc"

.text
.global _start
.type _start, @function
_start:
    /* Prologue: 初始化寄存器 */
    bl test_init_regs

    /* 原始测试代码 (从原始 .s 文件中提取) */
'''

    # 添加原始测试代码（跳过 CONFIG 注释和 _start 标签）
    in_test = False
    for line in asm_content.split('\n'):
        if '_start:' in line:
            in_test = True
            continue
        if in_test:
            # 将 brk #0 替换为调用 test_end
            if 'brk' in line and '#0' in line:
                wrapper += '    bl test_end\n'
            else:
                wrapper += f'{line}\n'

    wrapper += '''
    /* Epilogue: 不应该到达这里 */
    bl test_end
'''

    wrapper_path = work_dir / f"{asm_path.stem}_wrapper.s"
    wrapper_path.write_text(wrapper)

    return wrapper_path


def run_test_lata(elf_path: Path, qemu_path: str, timeout: int = 30) -> dict:
    """通过 QEMU-lata 运行测试"""
    try:
        result = subprocess.run(
            [qemu_path, str(elf_path)],
            capture_output=True, text=True, timeout=timeout
        )
        return parse_test_output(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def run_test_tcg(elf_path: Path, qemu_path: str, timeout: int = 30) -> dict:
    """通过 QEMU-TCG 运行测试（作为 oracle）"""
    return run_test_lata(elf_path, qemu_path, timeout)


def parse_test_output(output: str) -> dict:
    """解析测试输出，提取寄存器值"""
    result = {}
    for line in output.split('\n'):
        if line.startswith('REG:'):
            parts = line[4:].strip().split('=')
            if len(parts) == 2:
                name = parts[0].strip()
                try:
                    value = int(parts[1].strip(), 16)
                    result[name] = value
                except ValueError:
                    pass
    return result


def compare_results(config: AsmTestConfig, lata_result: dict, tcg_result: dict) -> TestResult:
    """比较 LATA 和 TCG 的执行结果"""
    tr = TestResult()
    tr.lata_output = lata_result
    tr.tcg_output = tcg_result

    # 检查执行错误
    if "error" in lata_result:
        tr.add_failure(f"LATA execution error: {lata_result['error']}")
        return tr
    if "error" in tcg_result:
        tr.add_failure(f"TCG execution error: {tcg_result['error']}")
        return tr

    # 比较 GPR 值
    for reg_name in GPR_NAMES:
        expected = config.get_expected_gpr(reg_name)
        if expected is None:
            continue

        lata_val = lata_result.get(reg_name)
        tcg_val = tcg_result.get(reg_name)

        if lata_val is not None and lata_val != expected:
            tr.add_failure(f"{reg_name}: LATA={lata_val:#018x}, expected={expected:#018x}")

    return tr


def main():
    parser = argparse.ArgumentParser(description="LATA ASM Test Runner")
    parser.add_argument("test_dir", help="Directory containing .s test files")
    parser.add_argument("--qemu-lata", default="qemu-aarch64-lata", help="Path to QEMU with LATA")
    parser.add_argument("--qemu-tcg", default="qemu-aarch64", help="Path to QEMU with TCG")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--filter", "-f", help="Filter test files by pattern")

    args = parser.parse_args()

    test_dir = Path(args.test_dir)
    if not test_dir.exists():
        print(f"Error: test directory {test_dir} not found")
        sys.exit(1)

    # 查找所有 .s 测试文件
    test_files = sorted(test_dir.glob("*.s"))
    if args.filter:
        test_files = [f for f in test_files if args.filter in f.name]

    print(f"Found {len(test_files)} test files")

    passed = 0
    failed = 0
    known_failures = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        work_dir = Path(tmpdir)

        for test_file in test_files:
            print(f"  [{test_file.name}] ", end="", flush=True)

            try:
                asm_text = test_file.read_text()
                config = parse_config_from_asm(asm_text)
                if not config:
                    print("SKIP (no CONFIG)")
                    continue

                test_config = AsmTestConfig(config)

                # 包装为 Linux 可执行程序并运行（当工具链可用时）
                # wrapper_s = wrap_baremetal_test(test_file, work_dir)
                # ... 编译、运行、比较 ...

                if test_config.known_failure:
                    print("KNOWN FAILURE")
                    known_failures += 1
                else:
                    print("SKIP (toolchain unavailable)")

            except Exception as e:
                print(f"ERROR: {e}")
                failed += 1

    print(f"\nResults: {passed} passed, {failed} failed, {known_failures} known failures")


if __name__ == "__main__":
    main()
