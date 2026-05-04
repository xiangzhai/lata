#!/usr/bin/env python3
"""LATA Binary Test Runner - runs dynarmic AArch64 ELF bintests through QEMU."""

import subprocess, sys, argparse, os, time
from pathlib import Path
from datetime import datetime
from typing import List, Tuple

def run_qemu(elf_path: Path, qemu: str, timeout: int = 30) -> Tuple[int, str, str]:
    """Run ELF through QEMU. Returns (exit_code, stdout, stderr)."""
    try:
        r = subprocess.run([qemu, str(elf_path)], capture_output=True,
                          text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, '', 'TIMEOUT'
    except FileNotFoundError:
        return -2, '', f'QEMU not found: {qemu}'

def check_pass(stdout: str) -> bool:
    """Check if test output indicates pass."""
    return '[PASS]' in stdout or 'All' in stdout and 'passed' in stdout

def collect_elfs(bintest_dir: Path) -> List[Path]:
    """Collect all .elf files from the bintest directory tree."""
    elfs = []
    skip_dirs = {'runner', 'simde', 'simde_simple'}
    for elf in sorted(bintest_dir.rglob('*.elf')):
        # Skip files in excluded directories
        parts = set(elf.parts)
        if parts & skip_dirs:
            continue
        if elf.is_file():
            elfs.append(elf)
    return elfs

def main():
    p = argparse.ArgumentParser(description='LATA Binary Test Runner')
    p.add_argument('--bintest-dir',
                   default=str(Path.home() / 'work/src/suyu/externals/dynarmic/tests/bintest/tests'))
    p.add_argument('--qemu-lata',
                   default=str(Path.home() / 'work/src/lata-suyu/lata/build/lata-aarch64'))
    p.add_argument('--qemu-tcg', default='/bin/qemu-aarch64')
    p.add_argument('--filter', '-f', help='Filter by subdirectory name')
    p.add_argument('--timeout', '-t', type=int, default=30)
    p.add_argument('--verbose', '-v', action='store_true')
    p.add_argument('--report', '-r', default='lata_bintest_report.txt')
    p.add_argument('--quick', '-q', action='store_true', help='Test only first 3 per dir')
    args = p.parse_args()

    bintest_dir = Path(args.bintest_dir)
    if not bintest_dir.is_dir():
        print(f'Error: {bintest_dir} not found'); sys.exit(1)

    qemu_lata = args.qemu_lata
    qemu_tcg = args.qemu_tcg

    elfs = collect_elfs(bintest_dir)
    if args.filter:
        elfs = [e for e in elfs if args.filter in str(e)]

    # Group by parent directory
    from collections import defaultdict
    by_dir = defaultdict(list)
    for e in elfs:
        by_dir[e.parent.name].append(e)

    print(f'=== LATA Binary Test Runner ===')
    print(f'Test dir: {bintest_dir}')
    print(f'Total ELFs: {len(elfs)} in {len(by_dir)} categories')
    print(f'QEMU-LATA: {qemu_lata}')
    print(f'QEMU-TCG: {qemu_tcg}')
    print()

    results = {'pass': [], 'fail': [], 'crash': [], 'timeout': [], 'tcg_only': []}
    lata_working = os.path.exists(qemu_lata)

    for cat, cat_elfs in sorted(by_dir.items()):
        tests = cat_elfs[:3] if args.quick else cat_elfs
        cat_pass = cat_fail = 0

        for elf in tests:
            name = f'{cat}/{elf.name}'

            # Run TCG first (oracle)
            tcg_rc, tcg_out, tcg_err = run_qemu(elf, qemu_tcg, args.timeout)
            tcg_ok = (tcg_rc == 0 and check_pass(tcg_out))

            # Run LATA
            lata_ok = False
            if lata_working:
                lata_rc, lata_out, lata_err = run_qemu(elf, qemu_lata, args.timeout)
                lata_ok = (lata_rc == 0 and check_pass(lata_out))
                if lata_rc == -1:
                    results['timeout'].append(name)
                    print(f'  TIMEOUT {name}')
                    continue
                if lata_rc not in (0, 1):
                    results['crash'].append(name)
                    if args.verbose: print(f'  CRASH(rc={lata_rc}) {name}')
                    continue
            else:
                results['tcg_only'].append(name)

            if lata_working:
                if tcg_ok == lata_ok:
                    results['pass'].append(name)
                    cat_pass += 1
                    if args.verbose: print(f'  PASS {name}')
                else:
                    results['fail'].append(name)
                    cat_fail += 1
                    print(f'  FAIL {name} TCG={tcg_rc}/{tcg_ok} LATA={lata_rc}/{lata_ok}')
                    if args.verbose:
                        if tcg_out: print(f'    TCG: {tcg_out[:200]}')
                        if lata_out: print(f'    LATA: {lata_out[:200]}')
            else:
                if tcg_ok:
                    results['pass'].append(name)
                    cat_pass += 1
                else:
                    results['fail'].append(name)
                    cat_fail += 1

        if cat_pass + cat_fail > 0:
            print(f'  {cat}: {cat_pass} pass, {cat_fail} fail')

    # Report
    total = len(results['pass']) + len(results['fail']) + len(results['crash']) + len(results['timeout'])
    print(f'\n=== Results ===')
    print(f'Total: {total}')
    print(f'Passed: {len(results["pass"])} ({100*len(results["pass"])/max(total,1):.1f}%)')
    print(f'Failed: {len(results["fail"])}')
    print(f'Crashed: {len(results["crash"])}')
    print(f'Timeout: {len(results["timeout"])}')

    if args.report:
        with open(args.report, 'w') as f:
            f.write(f'LATA Binary Test Report\n{"="*60}\n')
            f.write(f'Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
            f.write(f'Total: {total} | Pass: {len(results["pass"])} | Fail: {len(results["fail"])} | Crash: {len(results["crash"])} | Timeout: {len(results["timeout"])}\n\n')
            for cat in ['pass', 'fail', 'crash', 'timeout']:
                if results[cat]:
                    f.write(f'--- {cat.upper()} ({len(results[cat])}) ---\n')
                    for n in results[cat]:
                        f.write(f'  {n}\n')
        print(f'\nReport: {args.report}')

if __name__ == '__main__':
    main()
