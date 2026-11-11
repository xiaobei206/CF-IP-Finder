# CF IP Finder v0.1.6 Release Notes

Release date: 2026-11-11

## One-click candidate selection

- Local mode: TCP 443 → Cloudflare fingerprint → PING → TCPING → VLESS full-file download.
- Shodan import mode: Cloudflare fingerprint → PING → TCPING → VLESS; imported port:443 results remain treated as already confirmed.
- The action is started only by an explicit user click. It uses only IPs already present in the task. It does not call the Shodan API, expand target ranges, or automatically run ASN/BGP lookups.
- The pipeline reuses the existing manual stage runners and supports resuming the one-click workflow after an interruption.

## Optional filtering and manual overrides

- Optional exclusions: 443 not open, no CF fingerprint, PING loss above 0%, TCPING success rate below 100%, VLESS failure.
- Filter state is saved per task. All raw IP rows and measurements stay in SQLite.
- Result views: all, eligible, filtered. Each filtered row shows its reason.
- Right-click actions: force keep, restore automatic filtering, or manually exclude.

## Reliability and result metadata

- Retry transient timeouts/resets once by default; configurable 0–3 retries. Deterministic connection-refused results are not retried.
- Persist attempt number, UTC timestamp, stage, status and error detail in SQLite.
- VLESS rows and CSV exports include test time, URL, timeout, concurrency and attempt count.
- Update rows by stable IP identifier during scanning; no automatic resorting during progress. Click a column header to sort.

## Compatibility

- The existing cf_ip_tester_legacy.py full-file download engine is unchanged.
- Existing v0.1.5 task databases are migrated in place with nullable columns and a retry-history table.
