#!/usr/bin/env python3
"""SIMDE Test Runner - runs SIMDE neon native-c tests through LATA."""

import subprocess, sys, os, re, time
from pathlib import Path
from datetime import datetime
from collections import defaultdict

SIMDE_DIR = Path.home() / 'work/src/simde/simde-arm/neon'
QEMU_LATA = Path.home() / 'work/src/lata-suyu/lata/build/lata-aarch64'
QEMU_TCG = '/bin/qemu-aarch64'

def run_qemu(elf_path: Path, qemu: str, timeout: int = 30):
    try:
        r = subprocess.run([qemu, str(elf_path)], capture_output=True,
                          text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, '', 'TIMEOUT'
    except Exception as e:
        return -2, '', str(e)

def parse_tap(stdout: str):
    """Parse TAP output, return (total, passed, failed, failures)."""
    passed = 0; failed = 0; failures = []
    for line in stdout.split('\n'):
        if line.startswith('ok '):
            passed += 1
        elif line.startswith('not ok '):
            failed += 1
            failures.append(line.strip())
    return passed + failed, passed, failed, failures

def main():
    import argparse
    p = argparse.ArgumentParser(description='SIMDE Test Runner')
    p.add_argument('--qemu-lata', default=str(QEMU_LATA))
    p.add_argument('--qemu-tcg', default=QEMU_TCG)
    p.add_argument('--simde-dir', default=str(SIMDE_DIR))
    p.add_argument('--timeout', '-t', type=int, default=30)
    p.add_argument('--verbose', '-v', action='store_true')
    p.add_argument('--quick', '-q', action='store_true', help='Test first 50')
    p.add_argument('--report', '-r', default='simde_test_report.txt')
    args = p.parse_args()

    simde_dir = Path(args.simde_dir)
    tests = sorted(simde_dir.glob('*-native-c'))
    if args.quick:
        tests = tests[:50]

    print(f'=== SIMDE Test Runner ===')
    print(f'Tests: {len(tests)} native-c ELFs')
    print(f'QEMU-LATA: {args.qemu_lata}')
    print()

    results = defaultdict(list)
    total_pass = 0; total_fail = 0; total_tap = 0
    lata_crashes = []

    for i, elf in enumerate(tests):
        name = elf.name.replace('-native-c', '')
        progress = f'[{i+1}/{len(tests)}]'

        lata_rc, lata_out, lata_err = run_qemu(elf, args.qemu_lata, args.timeout)

        if lata_rc == -1:
            results['timeout'].append(name)
            print(f'{progress} TIMEOUT {name}')
            continue
        if lata_rc not in (0, 1, None):
            results['crash'].append((name, lata_rc, lata_err.strip()))
            lata_crashes.append(name)
            if args.verbose: print(f'{progress} CRASH(rc={lata_rc}) {name}')
            continue

        total, passed, failed, failures = parse_tap(lata_out)
        total_pass += passed
        total_fail += failed
        total_tap += total

        if failed == 0:
            results['pass'].append((name, passed))
            if args.verbose: print(f'{progress} PASS {name} ({passed}/{total})')
        else:
            results['fail'].append((name, passed, total, failures))
            print(f'{progress} FAIL {name}: {passed}/{total} ({failed} failed)')
            if args.verbose:
                for f in failures[:5]:
                    print(f'    {f}')

    # Report
    print(f'\n=== SIMDE Results ===')
    n_tests = len(tests)
    n_pass = len(results['pass'])
    n_fail = len(results['fail'])
    n_crash = len(results['crash'])
    n_timeout = len(results['timeout'])
    print(f'Test files: {n_tests}')
    print(f'All PASS:   {n_pass}')
    print(f'Has FAIL:   {n_fail}')
    print(f'Crash:      {n_crash}')
    print(f'Timeout:    {n_timeout}')
    print(f'TAP total:  {total_tap} | passed: {total_pass} | failed: {total_fail}')
    if total_tap > 0:
        print(f'TAP pass rate: {total_pass}/{total_tap} ({100*total_pass/total_tap:.1f}%)')

    # Group failures by instruction prefix
    if results['fail']:
        print(f'\n--- Failure groups ---')
        by_prefix = defaultdict(list)
        for name, passed, total, failures in results['fail']:
            prefix = name.rsplit('_', 1)[0] if '_' in name else name
            by_prefix[prefix].append((name, passed, total))
        for prefix in sorted(by_prefix.keys()):
            tests_list = by_prefix[prefix]
            total_tests = sum(t for _, _, t in tests_list)
            total_pass_t = sum(p for _, p, _ in tests_list)
            print(f'  {prefix}: {total_pass_t}/{total_tests} pass ({len(tests_list)} files)')

    # Report file
    with open(args.report, 'w') as f:
        f.write(f'SIMDE Test Report\n{"="*60}\n')
        f.write(f'Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
        f.write(f'Files: {n_tests} | All-PASS: {n_pass} | Has-FAIL: {n_fail} | Crash: {n_crash}\n')
        f.write(f'TAP: {total_pass}/{total_tap} ({100*total_pass/max(total_tap,1):.1f}%)\n\n')
        for cat, label in [('pass', 'ALL PASS'), ('fail', 'HAS FAILURES'), ('crash', 'CRASH'), ('timeout', 'TIMEOUT')]:
            if results[cat]:
                f.write(f'--- {label} ({len(results[cat])}) ---\n')
                for item in results[cat]:
                    if cat == 'fail':
                        name, p, t, fl = item
                        f.write(f'  {name}: {p}/{t} pass\n')
                        for fline in fl:
                            f.write(f'    {fline}\n')
                    elif cat == 'crash':
                        f.write(f'  {item[0]}: rc={item[1]} {item[2]}\n')
                    elif cat == 'pass':
                        f.write(f'  {item[0]}: {item[1]}/{item[1]}\n')
                    else:
                        f.write(f'  {item}\n')
    print(f'\nReport: {args.report}')

if __name__ == '__main__':
    main()
