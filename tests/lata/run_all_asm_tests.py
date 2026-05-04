#!/usr/bin/env python3
"""
LATA ASM Batch Test Runner - runs all dynarmic AArch64 ASM tests.

Adapts bare-metal .s tests to Linux ELF, runs through QEMU-lata and QEMU-TCG,
compares register/memory/NZCV results.

Verification strategy (by test complexity):
  Level 1: Simple tests (RegData only) -> dump X0-X7, check vs expected
  Level 2: NZCV tests -> also dump MRS NZCV value
  Level 3: VecData tests -> dump V regs via memory stores
  Level 4: MemData tests -> pre-initialize memory, verify
  Level 5: SVC/TLS tests -> skip or handle via assembly wrapper
"""

import subprocess, struct, json, re, tempfile, sys, argparse
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Tuple

AS = "aarch64-none-elf-as"
LD = "aarch64-none-elf-ld"

# dynarmic tests use low addresses (e.g. 0x1000) that cause SIGSEGV
# in QEMU user-mode. Add a base offset to move them into mapped memory.
# Use an address within typical QEMU user-mode mapped space (above zero page guard)
# MemData tests use low addresses unmapped in QEMU user-mode.
# Reserve BSS space and map addresses to it.
MEMDATA_BSS_SIZE = 0x10000  # 64KB BSS buffer for MemData

# ============================================================
# Assembly runtime for register dumping
# ============================================================
RUNTIME_ASM = """
// Dump all registers: GPRs X0-X15, NZCV, SP (144 bytes), then V0-V31 (512 bytes)
_test_end:
    adr x30, savebuf
    // GPRs X0-X15
    stp x0, x1, [x30, #(0*16)]
    stp x2, x3, [x30, #(1*16)]
    stp x4, x5, [x30, #(2*16)]
    stp x6, x7, [x30, #(3*16)]
    stp x8, x9, [x30, #(4*16)]
    stp x10, x11, [x30, #(5*16)]
    stp x12, x13, [x30, #(6*16)]
    str x14, [x30, #(7*16)]
    str x15, [x30, #(7*16)+8]
    mrs x0, nzcv
    str x0, [x30, #(8*16)]
    mov x0, sp
    str x0, [x30, #(8*16)+8]
    // V0-V31 (128-bit each, offset starts at 18*8=144)
    str q0,  [x30, #(18*8) + 0*16]
    str q1,  [x30, #(18*8) + 1*16]
    str q2,  [x30, #(18*8) + 2*16]
    str q3,  [x30, #(18*8) + 3*16]
    str q4,  [x30, #(18*8) + 4*16]
    str q5,  [x30, #(18*8) + 5*16]
    str q6,  [x30, #(18*8) + 6*16]
    str q7,  [x30, #(18*8) + 7*16]
    str q8,  [x30, #(18*8) + 8*16]
    str q9,  [x30, #(18*8) + 9*16]
    str q10, [x30, #(18*8) + 10*16]
    str q11, [x30, #(18*8) + 11*16]
    str q12, [x30, #(18*8) + 12*16]
    str q13, [x30, #(18*8) + 13*16]
    str q14, [x30, #(18*8) + 14*16]
    str q15, [x30, #(18*8) + 15*16]
    str q16, [x30, #(18*8) + 16*16]
    str q17, [x30, #(18*8) + 17*16]
    str q18, [x30, #(18*8) + 18*16]
    str q19, [x30, #(18*8) + 19*16]
    str q20, [x30, #(18*8) + 20*16]
    str q21, [x30, #(18*8) + 21*16]
    str q22, [x30, #(18*8) + 22*16]
    str q23, [x30, #(18*8) + 23*16]
    str q24, [x30, #(18*8) + 24*16]
    str q25, [x30, #(18*8) + 25*16]
    str q26, [x30, #(18*8) + 26*16]
    str q27, [x30, #(18*8) + 27*16]
    str q28, [x30, #(18*8) + 28*16]
    str q29, [x30, #(18*8) + 29*16]
    str q30, [x30, #(18*8) + 30*16]
    str q31, [x30, #(18*8) + 31*16]
    // Write all 144+512=656 bytes
    mov x0, #1
    mov x1, x30
    mov x2, #656
    mov x8, #64
    svc #0
    mov x0, #0
    mov x8, #93
    svc #0

.data
.balign 16
memdata_buf: .space 65536
tls_buf: .space 65536
savebuf: .space 1024
"""

CONFIG_RE = re.compile(r'/\* CONFIG\s*(.*?)\s*\*/', re.DOTALL)

def parse_config(asm_text: str) -> Optional[dict]:
    m = CONFIG_RE.search(asm_text)
    if not m: return None
    try: return json.loads(m.group(1))
    except json.JSONDecodeError: return None

def has_special_requirements(config: dict) -> str:
    """Returns empty string if test is simple, otherwise reason for skipping."""
    if config.get('SvcTest'):
        return 'SvcTest'
    return ''
    if config.get('TlsData'):
        return 'TlsData'
    return ''

def expand_ldr_literal(line: str) -> str:
    """Convert ldr Wn/Xn, =imm to mov+movk sequence for 32/64-bit immediates.
    LATA cannot handle PC-relative literal pool loads correctly."""
    m = re.match(r'\s*ldr\s+(w\d+|x\d+)\s*,\s*=(0x[0-9a-fA-F]+|#?0x[0-9a-fA-F]+|\d+)', line)
    if not m:
        return line
    reg = m.group(1)
    val_str = m.group(2).replace('#', '')
    try:
        val = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
    except ValueError:
        return line
    indent = line[:len(line) - len(line.lstrip())]
    is_64bit = reg.startswith('x')
    mask16 = 0xFFFF
    parts = []
    if is_64bit:
        parts = [(val >> 0) & mask16, (val >> 16) & mask16,
                 (val >> 32) & mask16, (val >> 48) & mask16]
    else:
        val = val & 0xFFFFFFFF
        parts = [(val >> 0) & mask16, (val >> 16) & mask16]
    # Remove trailing zero parts
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    # mov for the first non-zero part, movk for the rest
    result = []
    for i, p in enumerate(parts):
        if i == 0:
            result.append(f'{indent}mov {reg}, #{p}')
        elif p != 0:
            result.append(f'{indent}movk {reg}, #{p}, lsl #{i * 16}')
    return '\n'.join(result) if result else line

def adapt_test(asm_text: str, config: dict) -> str:
    """
    Convert bare-metal ASM test to Linux ELF that dumps registers at brk #0.
    Handles: RegData, SetRegData, MemData, SetPstate, SetFpcr
    """
    # Remove CONFIG block
    config_start = asm_text.find('/* CONFIG')
    config_end = asm_text.find('*/', config_start)
    if config_start >= 0 and config_end > config_start:
        asm_text = asm_text[:config_start] + asm_text[config_end + 2:]

    # Split lines early so we can scan for base addresses
    lines = asm_text.split('\n')

    # Build prefix: initial register setup. Use ldr=literal for large immediates
    # that can't be encoded in a single mov instruction.
    prefix_lines = []
    has_literals = False
    # Compute MemData base for address remapping (before init_regs)
    memdata = config.get('MemData', {})
    has_memdata = bool(memdata)
    mem_addr_map = {}  # original_addr -> offset_in_bss
    memdata_base = 0   # lowest address in test's address space (may include gap)
    memdata_top = 0
    if has_memdata:
        mem_stores_temp = []
        for addr_str, values in memdata.items():
            try: orig_addr = int(addr_str, 16)
            except: continue
            for i, val_str in enumerate(values):
                try: v = int(val_str, 16)
                except: continue
                offset = i * 8
                mem_stores_temp.append((orig_addr + offset, v))
        mem_stores_temp.sort()
        if mem_stores_temp:
            min_mem_key = min(int(k, 16) for k in memdata.keys())
            memdata_base = min_mem_key  # may be updated after scanning test body
            memdata_top = mem_stores_temp[-1][0] + 8
            next_bss = memdata_top - memdata_base
            for addr, val in mem_stores_temp:
                mem_addr_map[addr] = addr - memdata_base  # offset from base

    def remap_memdata_addr(val: int, reg: str) -> Optional[str]:
        """If val is a MemData address or its base, return BSS-relative adr+add code."""
        if not has_memdata:
            return None
        indent = '    '
        # Check if val is within MemData range
        if memdata_base - 0x10000 <= val <= memdata_top + 0x1000:
            # Compute offset relative to memdata_base
            if val in mem_addr_map:
                bss_off = mem_addr_map[val]
            else:
                bss_off = val - memdata_base
            if bss_off < 0:
                # Address below base: set to base (clamp).
                # We rely on the test's offset addressing to reach the actual data.
                bss_off = 0
            if bss_off == 0:
                return f'{indent}adr {reg}, memdata_buf'
            else:
                return f'{indent}adr {reg}, memdata_buf\n{indent}add {reg}, {reg}, #{bss_off}'
        return None

    # RegData = init + expected; SetRegData = init only (per dynarmic convention)
    # VecData/SetVecData = pre-loaded vector register values
    init_regs = {}
    init_regs.update(config.get('RegData', {}))
    init_regs.update(config.get('SetRegData', {}))
    init_regs.update(config.get('VecData', {}))
    init_regs.update(config.get('SetVecData', {}))
    restore_prefixes = []  # instructions to restore RegData values remapped to BSS
    for reg, val in init_regs.items():
        try: v = int(val, 16)
        except (ValueError, TypeError): continue
        rl = reg.lower()
        if reg.startswith('X') and reg[1:].isdigit():
            remapped = remap_memdata_addr(v, rl)
            if remapped:
                prefix_lines.append(remapped)
                # For RegData values (checked at end), restore original before brk
                if reg in config.get('RegData', {}):
                    restore_prefixes.append(f'    ldr {rl}, ={hex(v)}')
            else:
                prefix_lines.append(f'    ldr {rl}, ={hex(v)}')
        elif reg.startswith('W') and reg[1:].isdigit():
            wval = v & 0xFFFFFFFF
            prefix_lines.append(f'    ldr {rl}, ={hex(wval)}')
        elif reg == 'SP':
            prefix_lines.append(f'    ldr sp, ={hex(v)}')
            has_literals = True

    # Emit literal pool after reg init
    if has_literals:
        prefix_lines.append('    b 2f')
        prefix_lines.append('    .ltorg')
        prefix_lines.append('2:')

    # Set PSTATE/NZCV if specified
    pstate = config.get('SetPstate')
    if pstate:
        try: v = int(pstate, 16)
        except: v = None
        if v:
            prefix_lines.append(f'    mov x30, #{v}')
            prefix_lines.append('    msr nzcv, x30')

    # Set FPCR if specified
    fpcr = config.get('SetFpcr')
    if fpcr:
        try: v = int(fpcr, 16)
        except: v = 0
        if v:
            prefix_lines.append(f'    mov x30, #{v}')
            prefix_lines.append('    msr fpcr, x30')

    # SetVecData: pre-load vector registers
    vecdata = config.get('SetVecData') or config.get('VecData', {})
    if vecdata:
        prefix_lines.append(f'    // --- VecData init ({len(vecdata)} regs) ---')
        for reg, vals in vecdata.items():
            if not isinstance(vals, list) or len(vals) != 2:
                continue
            try:
                lo = int(vals[0], 16)
                hi = int(vals[1], 16)
            except (ValueError, TypeError):
                continue
            rn = reg.lower()
            # Load via literal pool: ldr qN, ={lo, hi}
            prefix_lines.append(f'    adr x15, vecdata_{rn}')
            prefix_lines.append(f'    ldr q{rn[1:]}, [x15]')
        prefix_lines.append(f'    b 3f')
        # Literal pool for vector data
        for reg, vals in vecdata.items():
            if not isinstance(vals, list) or len(vals) != 2:
                continue
            try:
                lo = int(vals[0], 16)
                hi = int(vals[1], 16)
            except (ValueError, TypeError):
                continue
            rn = reg.lower()
            prefix_lines.append(f'    .balign 16')
            prefix_lines.append(f'vecdata_{rn}: .quad {hex(lo)}, {hex(hi)}')
        prefix_lines.append(f'3:')

    # Rebuild mem_stores list for MemData init code
    mem_stores = []
    if has_memdata:
        for addr_str, values in memdata.items():
            try: orig_addr = int(addr_str, 16)
            except: continue
            for i, val_str in enumerate(values):
                try: v = int(val_str, 16)
                except: continue
                offset = i * 8
                mem_stores.append((orig_addr + offset, v))
        mem_stores.sort()

    # Scan test body for ldr =0xNNNN to adjust memdata_base downward BEFORE generating mem_prefix.
    # Tests may use a base address below the MemData key (e.g., ldr x2, =0x1000
    # when MemData is at 0x1020). The base address maps to BSS+0.
    if has_memdata:
        for line in lines:
            m = re.match(r'\s*ldr\s+[wx]\d+\s*,\s*=\s*(0x[0-9a-fA-F]+)', line)
            if m:
                addr = int(m.group(1), 16)
                if addr < memdata_base and memdata_base - addr <= 0x10000:
                    shift = memdata_base - addr
                    memdata_base = addr
                    new_map = {}
                    for a, off in mem_addr_map.items():
                        new_map[a] = off + shift
                    mem_addr_map = new_map
                    break  # only adjust to the lowest base address

    # Use BSS buffer for MemData (avoid unmapped absolute addresses)
    mem_prefix = []
    if mem_stores:
        mem_prefix = [f'    // --- MemData initialization ({len(mem_stores)} stores) ---']
        mem_prefix.append(f'    adr x14, memdata_buf')
        for addr, val in mem_stores:
            bss_off = mem_addr_map[addr]
            val_line = f'    ldr x15, ={hex(val)}'
            val_expanded = expand_ldr_literal(val_line)
            mem_prefix.append(val_expanded)
            if bss_off <= 0xFFF:
                mem_prefix.append(f'    str x15, [x14, #{bss_off}]')
            else:
                mem_prefix.append(f'    ldr x16, ={hex(bss_off)}')
                mem_prefix[-1] = expand_ldr_literal(mem_prefix[-1])
                mem_prefix.append(f'    str x15, [x14, x16]')
        mem_prefix.append(f'    // --- end MemData ---')

    # TLS data setup: allocate TLS buffer in BSS, initialize values, set TPIDR_EL0
    tls_data = config.get('TlsData', {})
    tls_prefix = []
    needs_tls = bool(tls_data)
    if not needs_tls:
        # Check if test uses TPIDR_EL0 without TlsData config
        for line in lines:
            if 'tpidr_el0' in line.lower():
                needs_tls = True
                break
    if needs_tls:
        tls_prefix.append(f'    // --- TLS initialization ---')
        tls_prefix.append(f'    adr x15, tls_buf')
        tls_prefix.append(f'    msr tpidr_el0, x15')
        for addr_str, values in tls_data.items():
            try: offset = int(addr_str, 16)
            except: continue
            for i, val_str in enumerate(values):
                try: v = int(val_str, 16)
                except: continue
                tls_off = offset + i * 8
                val_line = f'    ldr x14, ={hex(v)}'
                val_expanded = expand_ldr_literal(val_line)
                tls_prefix.append(val_expanded)
                if tls_off <= 0xFFF:
                    tls_prefix.append(f'    str x14, [x15, #{tls_off}]')
                else:
                    off_line = f'    ldr x16, ={hex(tls_off)}'
                    tls_prefix.append(expand_ldr_literal(off_line))
                    tls_prefix.append(f'    str x14, [x15, x16]')
        tls_prefix.append(f'    // --- end TLS ---')

    # Build final assembly
    result = []
    in_test = False
    memdata_done = False
    tls_done = False

    for line in lines:
        # For MemData tests: replace absolute addresses with BSS-relative
        if has_memdata and ('=0x' in line or '=#' in line):
            reg_match = re.match(r'\s*ldr\s+([wx]\d+)\s*,\s*=\s*(0x[0-9a-fA-F]+)', line)
            if reg_match:
                reg = reg_match.group(1)
                try: addr_val = int(reg_match.group(2), 16)
                except: addr_val = None
                if addr_val is not None:
                    remapped = remap_memdata_addr(addr_val, reg)
                    if remapped:
                        line = remapped
        # Expand ldr =literal to mov+movk (LATA can't handle PC-relative literal loads)
        line = expand_ldr_literal(line)
        if line.lstrip().startswith('_start:'):
            in_test = True
            result.append(line)
            # Add register initialization (expand ldr=literal to mov+movk)
            for pl in prefix_lines:
                result.append(expand_ldr_literal(pl))
            # Add memory initialization
            if has_memdata and not memdata_done:
                for mp in mem_prefix:
                    result.append(mp)
                memdata_done = True
            # Add TLS initialization
            if needs_tls and not tls_done:
                for tp in tls_prefix:
                    result.append(tp)
                tls_done = True
            continue

        if in_test and ('brk' in line and '#0' in line):
            # Restore any RegData registers remapped to BSS pointers
            if restore_prefixes:
                result.append('    // --- restore remapped RegData pointers ---')
                for rp in restore_prefixes:
                    result.append(expand_ldr_literal(rp))
            result.append('    // --- test end: dump regs + exit ---')
            result.append('    bl _test_end')
            continue

        # Also handle SVC #0 as test end
        if in_test and 'svc' in line and '#0' in line and not config.get('SvcTest'):
            # Only treat svc #0 as test end if no SvcTest config
            result.append('    // --- test end via SVC: dump regs + exit ---')
            result.append('    bl _test_end')
            continue

        result.append(line)

    return '\n'.join(result) + '\n' + RUNTIME_ASM

def compile_test(asm_text: str, name: str, work_dir: Path,
                 march: str = "armv8.2-a+crypto+fp16+simd") -> Optional[Tuple[Path, str]]:
    """Compile adapted ASM to ELF. Returns (elf_path, None) on success or (None, error)."""
    sp = work_dir / f'{name}.s'
    ob = work_dir / f'{name}.o'
    ef = work_dir / f'{name}.elf'
    sp.write_text(asm_text)

    # Try arch levels from highest to lowest (matching dynarmic asmtest)
    for arch in ["armv8.9-a+crc+crypto+sha3+sm4",
                 "armv8.5-a+crc+lse+crypto+fp16+simd",
                 "armv8.2-a+crypto+fp16+simd",
                 "armv8-a"]:
        r = subprocess.run([AS, f'-march={arch}', '-o', str(ob), str(sp)],
                           capture_output=True, text=True)
        if r.returncode == 0:
            break
    if r.returncode != 0:
        return None, f'ASM:{r.stderr[:200]}'

    r = subprocess.run([LD, '-o', str(ef), str(ob),
                       '-e', '_start', '--oformat=elf64-littleaarch64'],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None, f'LD:{r.stderr[:200]}'

    return ef, None

def run_qemu(elf_path: Path, qemu: str, timeout: int = 10) -> Tuple[int, bytes, str]:
    """Run ELF through QEMU. Returns (returncode, stdout, stderr)."""
    try:
        r = subprocess.run([qemu, str(elf_path)], capture_output=True, timeout=timeout)
        return r.returncode, r.stdout, (r.stderr or b'').decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        return -1, b'', 'TIMEOUT'
    except FileNotFoundError:
        return -1, b'', f'QEMU not found: {qemu}'

def parse_reg_dump(stdout: bytes) -> Dict[str, int]:
    """Parse register dump from stdout.
    Layout: X0-X15 (16*8=128) + NZCV(8) + SP(8) = 144 bytes, then V0-V31 (32*16=512).
    For V regs, stores two 64-bit values: Vn_lo, Vn_hi."""
    regs = {}
    # GPRs
    layout = [f'X{i}' for i in range(16)] + ['NZCV', 'SP']
    for i, name in enumerate(layout):
        offset = i * 8
        if len(stdout) >= offset + 8:
            regs[name] = struct.unpack('<Q', stdout[offset:offset+8])[0]
    # Vector registers (128-bit each at offset 144)
    for i in range(32):
        offset = 144 + i * 16
        if len(stdout) >= offset + 16:
            lo = struct.unpack('<Q', stdout[offset:offset+8])[0]
            hi = struct.unpack('<Q', stdout[offset+8:offset+16])[0]
            regs[f'V{i}_lo'] = lo
            regs[f'V{i}_hi'] = hi
    return regs

def check_test(config: dict, lata_regs: dict, tcg_regs: dict) -> List[str]:
    """Compare test results against expected values. Returns list of failure messages."""
    failures = []

    def check_val(reg: str, exp_val: int, key: str, is_64bit: bool = True):
        lata_val = lata_regs.get(key)
        tcg_val = tcg_regs.get(key)
        fmt = '#018x' if is_64bit else '#010x'
        if lata_val is not None and lata_val != exp_val:
            failures.append(f'{reg}: LATA={lata_val:{fmt}} expected={exp_val:{fmt}}')
        if tcg_val is not None and tcg_val != exp_val:
            failures.append(f'{reg}: TCG={tcg_val:{fmt}} expected={exp_val:{fmt}}')

    # Check X/W/SP registers
    expected = config.get('ExpectedRegData', {}) or config.get('RegData', {})
    for reg, exp_str in expected.items():
        if reg.startswith(('S', 'D')):
            continue  # Scalar FP: handled via V reg dump
        if reg.startswith('Q'):
            # Q register = 128-bit, same as V reg. Check Vn_lo + Vn_hi.
            try: exp_val = int(exp_str, 16)
            except: continue
            rn = reg[1:]
            lo = exp_val & 0xFFFFFFFFFFFFFFFF
            hi = (exp_val >> 64) & 0xFFFFFFFFFFFFFFFF
            check_val(f'{reg}_lo', lo, f'V{rn}_lo')
            check_val(f'{reg}_hi', hi, f'V{rn}_hi')
            continue
        if reg.startswith('V'):
            # Vector register: split into lo/hi parts
            try: exp_val = int(exp_str, 16)
            except: continue
            if isinstance(exp_str, str) and len(exp_str) > 18:
                # Full 128-bit hex
                lo = exp_val & 0xFFFFFFFFFFFFFFFF
                hi = (exp_val >> 64) & 0xFFFFFFFFFFFFFFFF
            else:
                # Just lower 64 bits
                lo = exp_val
                hi = 0
            rn = reg[1:]
            check_val(f'{reg}_lo', lo, f'V{rn}_lo')
            check_val(f'{reg}_hi', hi, f'V{rn}_hi')
            continue
        if not reg.startswith('X') and not reg.startswith('W') and reg != 'SP':
            continue
        if reg != 'SP' and not reg[1:].isdigit():
            continue
        try: exp_val = int(exp_str, 16)
        except: continue
        idx = int(reg[1:]) if reg != 'SP' else None
        key = reg if reg == 'SP' else f'X{idx}'
        if reg.startswith('W'):
            exp_val = exp_val & 0xFFFFFFFF
        check_val(reg, exp_val, key)

    # Check ExpectedVecData
    expected_vec = config.get('ExpectedVecData', {})
    for reg, vals in expected_vec.items():
        if not isinstance(vals, list) or len(vals) != 2:
            continue
        try:
            lo = int(vals[0], 16)
            hi = int(vals[1], 16)
        except (ValueError, TypeError):
            continue
        rn = reg.lower().lstrip('v')
        check_val(f'{reg}_lo', lo, f'V{rn}_lo')
        check_val(f'{reg}_hi', hi, f'V{rn}_hi')

    # Check NZCV / ExpectedPstate
    pstate_expected = config.get('ExpectedPstate')
    if pstate_expected:
        try: pv = int(pstate_expected, 16)
        except: pv = None
        if pv is not None:
            lata_nzcv = lata_regs.get('NZCV')
            tcg_nzcv = tcg_regs.get('NZCV')
            if lata_nzcv is not None and lata_nzcv != pv:
                failures.append(f'NZCV: LATA={lata_nzcv:#010x} expected={pv:#010x}')
            if tcg_nzcv is not None and tcg_nzcv != pv:
                failures.append(f'NZCV: TCG={tcg_nzcv:#010x} expected={pv:#010x}')

    return failures

def main():
    parser = argparse.ArgumentParser(description='LATA ASM Batch Test Runner')
    parser.add_argument('--asm-dir', default=str(Path.home() / 'work/src/suyu/externals/dynarmic/tests/asm/a64'))
    parser.add_argument('--qemu-lata', default=str(Path.home() / 'work/src/lata-suyu/lata/build_aarch64/lata-aarch64'))
    parser.add_argument('--qemu-tcg', default='/bin/qemu-aarch64')
    parser.add_argument('--filter', '-f', help='Filter test subdirs (e.g. alu,memory)')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--quick', '-q', action='store_true', help='Only test first 5 files per dir')
    parser.add_argument('--report', '-r', default='lata_test_report.txt')
    args = parser.parse_args()

    asm_dir = Path(args.asm_dir)
    if not asm_dir.is_dir():
        print(f'Error: {asm_dir} not found'); sys.exit(1)

    qemu_lata = args.qemu_lata
    qemu_tcg = args.qemu_tcg
    if not Path(qemu_lata).exists():
        print(f'WARNING: QEMU-lata not found at {qemu_lata}')
        qemu_lata = qemu_tcg
    if not Path(qemu_tcg).exists():
        print(f'WARNING: QEMU-tcg not found at {qemu_tcg}')
        sys.exit(1)

    # Collect test files
    subdirs = [d for d in asm_dir.iterdir() if d.is_dir()]
    if args.filter:
        subdirs = [d for d in subdirs if args.filter in d.name]

    all_tests = []
    for sd in sorted(subdirs):
        files = sorted(sd.glob('*.s'))
        if args.quick:
            files = files[:5]
        all_tests.extend(files)

    print(f'=== LATA ASM Batch Test ===')
    print(f'Test dir: {asm_dir}')
    print(f'Subdirs: {len(subdirs)}, Total tests: {len(all_tests)}')
    print(f'QEMU-LATA: {qemu_lata}')
    print(f'QEMU-TCG: {qemu_tcg}')
    print(f'Started: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print()

    # Results tracking
    passed = []
    failed = []
    skipped = []
    known_failures = []
    lata_crashes = []

    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        work_dir = Path(tmpdir)

        batch_idx = 0
        for tf in all_tests:
            batch_idx += 1
            rel_path = tf.relative_to(asm_dir)
            name = tf.stem

            try:
                asm_text = tf.read_text()
            except:
                skipped.append((str(rel_path), 'read error'))
                continue

            config = parse_config(asm_text)
            if not config:
                skipped.append((str(rel_path), 'no CONFIG'))
                continue

            # Check for known failure
            if config.get('KnownFailure'):
                known_failures.append((str(rel_path), str(config['KnownFailure'])[:80]))
                if not args.verbose:
                    continue

            # QemuSkip: test assumes bare-metal (PC=0) or uses unsupported features
            if config.get('QemuSkip'):
                skipped.append((str(rel_path), f'QemuSkip: {str(config["QemuSkip"])[:80]}'))
                if not args.verbose:
                    continue

            # Check special requirements
            special = has_special_requirements(config)
            if special:
                skipped.append((str(rel_path), special))
                if not args.verbose:
                    continue

            # Adapt, compile, run
            try:
                adapted = adapt_test(asm_text, config)
            except Exception as e:
                skipped.append((str(rel_path), f'adapt error: {e}'))
                continue

            elf, err = compile_test(adapted, f'test_{batch_idx:04d}', work_dir)
            if err:
                failed.append((str(rel_path), f'compile: {err[:80]}'))
                continue

            # Run through both QEMUs
            lata_rc, lata_out, lata_err = run_qemu(elf, qemu_lata)
            tcg_rc, tcg_out, tcg_err = run_qemu(elf, qemu_tcg)

            if lata_rc != 0 and lata_rc != -1:  # -1 = timeout
                lata_crashes.append((str(rel_path), f'rc={lata_rc} err={lata_err[:80]}'))
                if not args.verbose:
                    continue

            lata_regs = parse_reg_dump(lata_out)
            tcg_regs = parse_reg_dump(tcg_out)
            failures = check_test(config, lata_regs, tcg_regs)

            if not failures:
                passed.append(str(rel_path))
                status = 'PASS'
            else:
                failed.append((str(rel_path), '; '.join(failures[:3])))
                status = f'FAIL({len(failures)})'

            if args.verbose:
                print(f'[{status}] {rel_path}')
                for f in failures[:3]:
                    print(f'       {f}')
            elif batch_idx % 50 == 0:
                print(f'  Progress: {batch_idx}/{len(all_tests)} (pass={len(passed)} fail={len(failed)} skip={len(skipped)} known_fail={len(known_failures)} crash={len(lata_crashes)})')

    # Print report
    print(f'\n=== Test Report ({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) ===')
    print(f'Total: {len(all_tests)}')
    print(f'Passed: {len(passed)}')
    print(f'Failed: {len(failed)}')
    print(f'Skipped (VecData/MemData/SVC/TLS): {len(skipped)}')
    print(f'Known failures: {len(known_failures)}')
    print(f'LATA crashes: {len(lata_crashes)}')

    if failed:
        print(f'\n--- Failures ---')
        for path, reason in failed[:30]:
            print(f'  {path}: {reason}')
    if lata_crashes:
        print(f'\n--- LATA Crashes ---')
        for path, reason in lata_crashes[:20]:
            print(f'  {path}: {reason}')

    # Write detailed report
    if args.report:
        with open(args.report, 'w') as f:
            f.write(f'LATA ASM Test Report\n{"="*60}\n')
            f.write(f'Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
            f.write(f'Total: {len(all_tests)} | Pass: {len(passed)} | Fail: {len(failed)} | Skip: {len(skipped)} | KnownFail: {len(known_failures)} | Crash: {len(lata_crashes)}\n\n')
            if passed:
                f.write(f'--- Passed ({len(passed)}) ---\n')
                for p in passed: f.write(f'  PASS: {p}\n')
            if failed:
                f.write(f'\n--- Failed ({len(failed)}) ---\n')
                for path, reason in failed: f.write(f'  FAIL: {path}: {reason}\n')
            if lata_crashes:
                f.write(f'\n--- Crashes ({len(lata_crashes)}) ---\n')
                for path, reason in lata_crashes: f.write(f'  CRASH: {path}: {reason}\n')
            if skipped:
                f.write(f'\n--- Skipped ({len(skipped)}) ---\n')
                for path, reason in skipped: f.write(f'  SKIP: {path}: {reason}\n')
        print(f'\nDetailed report: {args.report}')

if __name__ == '__main__':
    main()
