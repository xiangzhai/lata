#!/usr/bin/env python3
"""LATA ASM Test Runner - adapts dynarmic bare-metal AArch64 .s tests to Linux ELF and compares LATA vs TCG results."""

import sys, re, json, subprocess, tempfile, argparse, os
from pathlib import Path
from typing import Optional, Dict

AS = "aarch64-none-elf-as"
LD = "aarch64-none-elf-ld"

RUNTIME_ASM = """
_dump_reg:
    stp x29, x30, [sp, #-16]!
    stp x0, x1, [sp, #-16]!
    adr x0, outbuf
    bl _fmt64
    mov x0, #1
    adr x1, reg_hdr
    mov x2, #5
    mov x8, #64
    svc #0
    mov x0, #1
    adr x1, outbuf
    mov x2, #17
    mov x8, #64
    svc #0
    ldp x0, x1, [sp], #16
    ldp x29, x30, [sp], #16
    ret

_dx0: stp x1,x2,[sp,#-16]!; mov x1,x0; bl _dump_reg; ldp x1,x2,[sp],#16; ret
_dx1: stp x0,x2,[sp,#-16]!; bl _dump_reg; ldp x0,x2,[sp],#16; ret
_dx2: stp x0,x1,[sp,#-16]!; mov x1,x2; bl _dump_reg; ldp x0,x1,[sp],#16; ret
_dx3: stp x0,x1,[sp,#-16]!; mov x1,x3; bl _dump_reg; ldp x0,x1,[sp],#16; ret
_dx4: stp x0,x1,[sp,#-16]!; mov x1,x4; bl _dump_reg; ldp x0,x1,[sp],#16; ret
_dx5: stp x0,x1,[sp,#-16]!; mov x1,x5; bl _dump_reg; ldp x0,x1,[sp],#16; ret
_dx6: stp x0,x1,[sp,#-16]!; mov x1,x6; bl _dump_reg; ldp x0,x1,[sp],#16; ret
_dx7: stp x0,x1,[sp,#-16]!; mov x1,x7; bl _dump_reg; ldp x0,x1,[sp],#16; ret

_fmt64:
    mov x2, #60       // bit offset of highest nybble (bits 63:60)
    mov x6, #0        // byte offset in output buffer
1:  lsrv x3, x1, x2
    and x3, x3, #0xf
    cmp x3, #10
    add x3, x3, #0x30
    add x4, x3, #0x27
    cmp x3, #0x39
    csel x3, x4, x3, hi   // if x3>'9' use letter else keep digit
    strb w3, [x0, x6]
    add x6, x6, #1
    subs x2, x2, #4
    bpl 1b
    mov w3, #0x0a
    strb w3, [x0, x6]
    ret

.data
reg_hdr: .ascii "REG:X"
outbuf: .space 32
"""

def parse_config(asm_text: str) -> Optional[dict]:
    m = re.search(r'/\* CONFIG\s*(.*?)\s*\*/', asm_text, re.DOTALL)
    if not m: return None
    return json.loads(m.group(1))

def extract_test_body(asm_text: str) -> str:
    """Remove CONFIG block and comments before _start, keep test code."""
    config_start = asm_text.find('/* CONFIG')
    config_end = asm_text.find('*/', config_start)
    if config_start >= 0 and config_end > config_start:
        asm_text = asm_text[:config_start] + asm_text[config_end + 2:]
    return asm_text

def adapt_test(asm_text: str, config: dict) -> str:
    """Convert bare-metal ASM test to Linux ELF source.
    - Remove CONFIG block
    - Add register init from SetRegData/RegData after _start
    - Replace brk #0 with register dump + exit
    """
    body = extract_test_body(asm_text)
    lines = body.split('\n')
    result = []
    in_test = False

    for line in lines:
        if '_start:' in line:
            in_test = True
            result.append(line)

            # add reg initialization from config (use ldr= for large values)
            setreg = config.get('SetRegData', {})
            if not setreg:
                setreg = config.get('RegData', {})
            has_literals = False
            for reg, val in setreg.items():
                v = int(val, 16)
                rl = reg.lower()
                if reg.startswith('X') and reg[1:].isdigit():
                    if v <= 0xFFFF and (v & 0xFFFF) == v:
                        result.append(f'    mov {rl}, #{v}')
                    else:
                        result.append(f'    ldr {rl}, ={hex(v)}')
                        has_literals = True
                elif reg.startswith('W') and reg[1:].isdigit():
                    wval = v & 0xFFFFFFFF
                    if wval <= 0xFFFF:
                        result.append(f'    mov {rl}, #{wval}')
                    else:
                        result.append(f'    ldr {rl}, ={hex(wval)}')
                        has_literals = True
            if has_literals:
                result.append('    b 99f')
                result.append('    .ltorg')
                result.append('99:')
            continue

        if in_test and 'brk' in line and '#0' in line:
            result.append('    // --- dump regs and exit ---')
            for n in range(8):
                result.append(f'    bl _dx{n}')
            result.append('    mov x0, #0')
            result.append('    mov x8, #93')
            result.append('    svc #0')
            continue

        result.append(line)

    return '\n'.join(result) + '\n' + RUNTIME_ASM

def compile_run(qemu: str, asm_text: str, name: str) -> tuple:
    """Compile ASM to ELF and run via QEMU."""
    with tempfile.TemporaryDirectory() as d:
        wd = Path(d)
        sp = wd / f'{name}.s'
        op = wd / f'{name}.o'
        ep = wd / f'{name}.elf'
        sp.write_text(asm_text)

        r = subprocess.run([AS, '-o', str(op), str(sp)], capture_output=True, text=True)
        if r.returncode != 0:
            return None, f'ASM: {r.stderr[:300]}'

        r = subprocess.run([LD, '-o', str(ep), str(op),
                           '-e', '_start', '--oformat=elf64-littleaarch64'],
                          capture_output=True, text=True)
        if r.returncode != 0:
            return None, f'LD: {r.stderr[:300]}'

        try:
            r = subprocess.run([qemu, str(ep)], capture_output=True, timeout=10)
            regs = {}
            for line in r.stdout.decode('utf-8', errors='replace').split('\n'):
                if line.startswith('REG:X'):
                    try:
                        p = line[5:].split('=')
                        regs[p[0].strip()] = int(p[1].strip(), 16)
                    except: pass
            return regs, None
        except subprocess.TimeoutExpired:
            return None, 'TIMEOUT'
        except Exception as e:
            return None, str(e)

def main():
    p = argparse.ArgumentParser(description='LATA ASM Test Runner')
    p.add_argument('test_file')
    p.add_argument('--qemu-lata', default='')
    p.add_argument('--qemu-tcg', default='/bin/qemu-aarch64')
    p.add_argument('--verbose', '-v', action='store_true')
    args = p.parse_args()

    if not args.qemu_lata:
        for c in [
            Path('build_aarch64/lata-aarch64'),
            Path(__file__).parent.parent.parent.parent / 'build_aarch64' / 'lata-aarch64',
        ]:
            if c.exists(): args.qemu_lata = str(c.resolve()); break
    if not args.qemu_lata or not Path(args.qemu_lata).exists():
        args.qemu_lata = args.qemu_tcg

    tf = Path(args.test_file)
    if not tf.exists():
        print(f'Error: {tf} not found'); sys.exit(1)

    asm_text = tf.read_text()
    config = parse_config(asm_text)
    if not config:
        print('Error: no CONFIG'); sys.exit(1)

    print(f'Test: {tf.name}')
    adapted = adapt_test(asm_text, config)

    lata_regs, lata_err = compile_run(args.qemu_lata, adapted, tf.stem + '_lata')
    tcg_regs, tcg_err = compile_run(args.qemu_tcg, adapted, tf.stem + '_tcg')

    if lata_err or tcg_err:
        print(f'  Error: LATA={lata_err} TCG={tcg_err}')
        return

    expected = config.get('RegData', {})
    passed = failed = 0
    for reg, exp_str in expected.items():
        if not reg.startswith('X') or not reg[1:].isdigit(): continue
        exp = int(exp_str, 16)
        rn = reg[1:]
        lv = lata_regs.get(rn)
        tv = tcg_regs.get(rn)
        if lv == exp:
            passed += 1
            if args.verbose: print(f'  {reg}: OK ({lv:#018x})')
        else:
            failed += 1
            print(f'  {reg}: FAIL LATA={lv:#018x} TCG={tv:#018x} expected={exp:#018x}')

    print(f'Result: {passed} passed, {failed} failed')

if __name__ == '__main__':
    main()
