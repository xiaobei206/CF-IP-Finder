# CF IP Finder

**Current version: 0.1.3** · Windows 10/11 · Python 3.10+ · standard-library runtime

CF IP Finder is a staged IPv4 candidate discovery, Cloudflare-feature screening, connectivity diagnostics, and VLESS download-testing desktop tool. The user supplies the scan targets and controls each stage.

## Modes

- **Local CIDR mode** — enter one CIDR, IPv4 range, or IP per line. Run TCP 443, CF HTTP fingerprinting, PING, TCPING, VLESS download testing, and ASN/BGP lookup as separate manual steps.
- **Shodan import mode** — paste IPs or import Shodan CSV/JSON text. Since the source results are expected to have been found with `port:443`, the app skips the duplicate TCP 443 stage. Run CF filtering, PING, TCPING, VLESS testing, then manually request ASN for the fastest N successful VLESS results (default 30).

Both modes now use a candidate funnel: all CF hits are pinged, then PING Top-N (default 500) feeds TCPING, and TCPING Top-N (default 100) feeds VLESS. Enter 0 at either filter to include all candidates, including unresponsive/failed results. Candidate queues are persisted for exact resume. Every result column supports ascending/descending sorting. Missing values remain last. The current sort changes the table view only; it does not mutate stored results or Shodan ASN Top-N selection.

## Quick start

1. Download the Windows EXE or Source ZIP from [GitHub Releases](https://github.com/xiaobei206/CF-IP-Finder/releases).
2. Run `CF-IP-Finder-0.1.3-Windows-x64.exe`, or install Python 3.10+ with Tkinter and launch `run.bat` from the source package.
3. Paste target ranges or import Shodan IPs, create a task, then manually run each stage.
4. Configure Xray-core and a VLESS URI before the VLESS stage.
5. Export the complete CSV/JSON, CF-hit IP list, plain IP list, or VLESS URI list.

Detailed Chinese instructions: [README_CN.md](README_CN.md), [User Guide](docs/USER_GUIDE_CN.md).

## Handoff docs — read these before development

A new AI/developer session must read these in order:

1. [AI_BOOTSTRAP_PROMPT.md](AI_BOOTSTRAP_PROMPT.md)
2. [AI_DEVELOPMENT_PROTOCOL.md](AI_DEVELOPMENT_PROTOCOL.md)
3. [SESSION_HANDOFF.md](SESSION_HANDOFF.md)
4. [REFACTOR_ROADMAP.md](REFACTOR_ROADMAP.md)
5. [Architecture](docs/ARCHITECTURE.md)
6. [Testing and release](docs/TESTING_AND_RELEASE.md)
7. [Cumulative development log](dev_log.md)

The Git repository is the source of truth. Do not ask the user to re-upload source files or depend on previous chat history. Inspect the latest main HEAD, tags, releases, and Actions before making changes.

## Validation

Run from the repository root:

```powershell
py -3 -m py_compile cf_ip_finder.py cf_ip_tester_legacy.py
py -3 cf_ip_finder.py --self-test
py -3 -m unittest discover -s tests -v
py -3 tests/check_version.py
```

Offline tests do not prove real network availability or VLESS performance on the user's ISP.

## Privacy and safe operation

- Only test addresses and networks you own or are explicitly authorized to assess.
- Shodan mode imports user-provided results; it does not call the Shodan API or expand target ranges automatically.
- VLESS URIs may contain UUIDs. Task databases and configuration are stored locally and must not be committed or shared publicly.
- ASN/BGP metadata is public routing/registration data, not proof of the user's actual ISP transit path.
- PING failure does not mean TCP/VLESS is unusable. Final candidate quality is determined by real VLESS download tests.

## Versioning

The root `VERSION` file is authoritative and must match `APP_VERSION`, documentation, build filenames and release tags. Release commits to `main` must start with `release: vX.Y.Z`; GitHub Actions validates, builds the Windows EXE, creates a clean source archive, calculates SHA256 checksums, and publishes the GitHub Release.
