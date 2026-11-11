# Testing and Release Process

## Local validation

Run from repository root:

```powershell
py -3 -m py_compile cf_ip_finder.py cf_ip_tester_legacy.py
py -3 cf_ip_finder.py --self-test
py -3 -m unittest discover -s tests -v
```

The built-in self-test is offline and exercises core parsing, persistence, candidate pipeline, sorting selection, exports, VLESS URI replacement and manual-stage runner wiring. The v0.1.5 tests cover exact selected-IP PING/TCPING/ASN/VLESS diagnostics and funnel immutability. The v0.1.6 test_v016_pipeline.py tests optional candidate filters, manual overrides, transient-vs-deterministic retry policy, persisted retry attempts, SQLite migration/reopen, and Local/Shodan one-click stage order. These offline tests do not prove real public IP availability or the user's ISP performance.

## GitHub Actions

Workflow: `.github/workflows/ci-release.yml`.

- Pull requests and pushes to `main`: run offline tests on Ubuntu and Windows.
- Release commits to `main` must use commit message `release: vX.Y.Z` and match `VERSION`.
- The release job runs only after the test matrix succeeds.
- Windows runner installs PyInstaller and builds a single-file GUI EXE.
- Workflow creates a clean versioned source ZIP (does not include `.git`, `__pycache__`, local task data or `xray.exe`), calculates SHA256, and creates/updates a GitHub Release with EXE, source archive and checksum file.
- Workflow permission is limited to `contents: write` for release publication; ordinary test jobs do not need repository write access.

## Release checklist

Before release:

- [ ] Update `VERSION` and `APP_VERSION` to the same new version.
- [ ] Update `CHANGELOG_CN.md`, `README_CN.md`, `README.md`, and build naming if required.
- [ ] Append to `dev_log.md` and update `SESSION_HANDOFF.md` / `REFACTOR_ROADMAP.md`.
- [x] Add tests for selected-IP exact target sets, funnel immutability and legacy VLESS delegation.
- [ ] `py_compile`, built-in `--self-test`, unittest discovery pass.
- [ ] Verify no task database, VLESS UUID, IP scan result, private token or `xray.exe` is staged.
- [ ] Commit to `main` with message `release: vX.Y.Z`.

After push:

- [ ] Open Actions and inspect `Validate and Release` run.
- [ ] Confirm Ubuntu and Windows tests passed.
- [ ] Confirm Windows PyInstaller build passed.
- [ ] Confirm Release tag `vX.Y.Z` exists.
- [ ] Confirm assets include `CF-IP-Finder-X.Y.Z-Windows-x64.exe`, `CF-IP-Finder-X.Y.Z-Source.zip`, `SHA256SUMS.txt`.
- [ ] Download the release assets and verify checksums if possible.
- [ ] Only then announce release as published.

## Versioning

Do not reuse a tag. Every release increments the version. The release workflow checks that the tag generated from the `VERSION` file does not overwrite a prior release. If an Action fails, inspect logs and fix the problem; don't claim release success based merely on the push commit.
