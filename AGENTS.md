# Project rules for LATA contributors

LATA is a QEMU fork with an AArch64 user-mode backend.  Changes to
`target/arm/lata`, `accel/tcg`, or `linux-user` can silently break the
translated code that codex/claude depend on, so every commit must pass
regression testing.

## Mandatory before every commit

1. Build the AArch64 user-mode target:

   ```sh
   ninja -C build_aarch64
   ```

2. Run the TCG regression tests for AArch64:

   ```sh
   make -C build_aarch64 check-tcg
   ```

   At minimum these tests must pass: `lata-flags`, `lata-movwide`,
   `lata-forkexit`, and `lata-tu-overlap`.  If the cross toolchain is not
   available, run the already-built equivalents manually with
   `build_aarch64/lata-aarch64 -L ~/linux-aarch64 <test-binary>`.

3. Run the real-application smoke gate:

   ```sh
   make -C build_aarch64 check-lata-apps
   ```

   This drives the real AArch64 `codex`/`claude` binaries through version
   checks and a pty-based TUI startup.  It must not be allowed to skip when
   `~/linux-aarch64`, `~/codex-aarch64-unknown-linux-musl`, and
   `~/linux-aarch64/bin/claude` are present.  In CI use:

   ```sh
   LATA_APP_GATE_REQUIRE=1 make -C build_aarch64 check-lata-apps
   ```

4. Clean core dumps before committing:

   ```sh
   find . -maxdepth 1 -name '*.core' -delete
   ```

## Commit hygiene

- Do not commit `issue.md` or `analysis.md`.
- Do not commit generated build directories, test binaries, or `*.core`.
- Commit only the files needed for the fix and its regression test.
- If any regression step fails, fix the problem first; never commit a known
  regression.
- In the commit message, name the regression tests that were run.

## Regression coverage expectations

- Bug fixes in translation/code generation must add or extend a test under
  `tests/tcg/aarch64/` and be listed in `AARCH64_TESTS`.
- Fork/thread/exit-request fixes must cover `lata-forkexit`.
- TU/overlap/branch-linking fixes must cover `lata-tu-overlap`.
- Keep `analysis.md` and `issue.md` local and uncommitted unless explicitly
  requested otherwise.
