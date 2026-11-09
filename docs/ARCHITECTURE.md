# Architecture — CF IP Finder 0.1.3

## 1. Runtime overview

- Language: Python 3.10+.
- UI: Tkinter/ttk, defined by `App` in `cf_ip_finder.py`.
- Runtime dependencies: Python standard library only.
- VLESS runtime: external Xray-core executable selected/downloaded by the user; tester implementation is `cf_ip_tester_legacy.py`.
- Public network metadata: RIPEstat HTTP API, only when the ASN stage is manually run (and in Local mode according to the stage button; Shodan mode is never automatic).
- Persistence: SQLite (`checkpoint.db`) with WAL and `synchronous=FULL`, plus atomic JSONL stage snapshots.

## 2. Source modules

### `cf_ip_finder.py`

| Area | Responsibilities |
|---|---|
| IP parsing | `parse_targets`, `parse_shodan_targets` |
| Connectivity probes | `tcp_probe`, `ping_probe`, `tcping_probe` |
| HTTP / CF | `http_cleartext_probe`, response parsing, score and candidate evidence |
| TLS | `tls_probe`; supplemental handshake/trace diagnostics |
| Network metadata | `_ripestat_json`, `route_info_probe` |
| Persistence | `TaskStore`, SQLite schema/migrations, `write_stage_file` |
| Scheduling | `ScanRunner`, `ManualStageRunner` |
| Xray helper | locate/download Xray, config path settings |
| Output | CSV/TXT/VLESS/JSON exports and CF candidate list |
| UI | `App`, mode toggles, stage buttons, column sorting, progress and logs |

### `cf_ip_tester_legacy.py`

This module is intentionally separate. It preserves the historic CFIPTester VLESS test flow:

1. Parse VLESS URI into a template.
2. Build an Xray config replacing only target address; preserve UUID, port, SNI, Host, path and transport/security settings.
3. Run Xray config validation before testing.
4. Launch an isolated Xray process with a local SOCKS5 inbound.
5. Make a SOCKS5 connection and fetch the configured HTTP test URL through that proxy.
6. Verify download completion and calculate decimal MB/s.
7. Close sockets and terminate the Xray process in cleanup paths.

Do not move this code into the GUI module or add a parallel implementation without a compelling reason.

## 3. Pipeline and state semantics

### Local mode

`port → http → ping → tcping → speed → route`

- `port`: TCP connect to 443.
- `http`: send plain HTTP request to port 443; store response status, headers, body excerpt and CF indicators. TLS probe may be attached as diagnostic to hits.
- `ping`: system ICMP ping. Failure is a result, not a candidate deletion.
- `tcping`: repeat TCP connect to 443. Failure is diagnostic only.
- `speed`: build/restore the frozen TCPING Top-N cohort and run the legacy Xray/SOCKS5 complete download test for that cohort.
- `route`: RIPEstat network-info / prefix-overview lookup.

### Candidate funnel (both modes)

- PING runs for all CF hits; no ICMP reply is diagnostic only.
- ping_top_n defaults to 500. A positive value selects the lowest PING average latency; zero selects every CF hit, including no-reply IPs.
- TCPING runs only the stored PING cohort. tcping_top_n defaults to 100. A positive value selects the lowest TCP connect average latency; zero selects every TCPING cohort member, including failed/no-latency IPs.
- Ties use PING loss or TCPING success percentage and maximum latency as secondary ranking signals. Missing latency sorts last.
- Selection is persisted in SQLite and the two *_selected.txt snapshots. Resume reuses it; re-filtering requires a user-confirmed rerun after the stage is complete. UI column sorting never changes the selection.
- VLESS still uses the legacy full-download tester; only its own download result determines final speed ranking.

### Shodan mode

`http → ping → tcping → speed → route`

On import, `mark_shodan_imported()` marks port state as open and source as Shodan-confirmed, avoiding a second TCP 443 pass. HTTP/CF hit filter limits downstream candidate selection. ASN only runs when its button is clicked; Top-N selection is based on stored VLESS speed, not current visible sort.

## 4. Database

The `ips` table stores one row per unique IPv4, an input sequence, source line, and stage data. Important field groups:

- Port: `port_status`, `port_ms`, `port_error`, `port_source`.
- CF HTTP: `http_status`, `http_status_line`, `http_server`, `cf_ray`, `cf_text_match`, `cf_phrase_match`, `cf_score`, `cf_candidate`, `http_excerpt`, `http_error`.
- TLS: `tls_status`, `tls_ms`, `tls_version`, `tls_cipher`, certificate fingerprint and trace fields.
- PING: status, average/min/max, loss percentage, replies, error.
- TCPING: status, average/min/max, success percentage/count, error.
- VLESS: status, `speed_mbps`, bytes, TTFB, error and related metadata.
- ASN: status, ASN list, holder/organization, BGP prefix, source and error.

Other tables:

- `stages`: stage status and item count/time metadata.
- `stage_selections`: one durable selection definition per downstream stage, including source stage, configured N, count, and creation time.
- `stage_candidates`: immutable rank/IP rows for the selected TCPING or VLESS cohort.
- `logs`: task event/error history.
- `meta`: task mode, configuration and resume metadata.

DB connection is opened with `check_same_thread=False`, with a reentrant lock around operations. `save_result()` commits each IP result within a SQLite transaction. Stage file snapshots are written to `*.tmp`, flushed and fsynced, then atomically replaced.

## 5. Task layout

Default Windows root: `%LOCALAPPDATA%\\CF-IP-Finder\\tasks\\<task-id>\\`.

Common contents:

```text
<task-id>/
  checkpoint.db
  task_config.json
  task.log (if emitted by the app/runtime)
  stages/
    01_targets.txt
    02_port_scan.jsonl
    03_cf_probe.jsonl
    04_tls_probe.jsonl
    05_ping.jsonl
    05_ping_selected.txt
    06_tcping.jsonl
    06_tcping_selected.txt
    07_vless_speed.jsonl
    08_network_info.jsonl
```

A stage file is a snapshot for inspection/export/recovery diagnostics; SQLite is the authoritative per-IP state. Do not assume each stage file is appended on each row unless the code path explicitly does so.

## 6. UI sorting

`App._sort_by()` changes only `sort_column` and `sort_desc`; `_render_results()` uses those values for display order. Query selection uses SQL ordering in `TaskStore.pending_ips()`, not Treeview order. Shodan ASN Top-N is SQL-ranked by VLESS speed descending (then TTFB ascending and input sequence).

## 7. Operational cautions

- CF headers/body are heuristic evidence, not proof of a working reverse proxy.
- PING is ICMP; many networks drop it.
- TCPING measures TCP handshake, not TLS or VLESS.
- RIPEstat BGP origin and organization do not reveal the user's ISP path by themselves.
- Download speed depends on the user's ISP, Xray config, target URL/file, server status, concurrency and other traffic.
- Never put user task directories or UUID-bearing VLESS URI values into the public repository or CI logs.
