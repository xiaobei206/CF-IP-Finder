import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cf_ip_finder as app


class FilterPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name) / "task"
        self.store = app.TaskStore(self.folder, create=True)
        self.ips = [f"192.0.2.{i}" for i in range(1, 5)]
        self.store.add_targets([(ip, i) for i, ip in enumerate(self.ips, 1)])
        self.store.mark_shodan_imported()
        for ip in self.ips:
            self.store.save_result(ip, {
                "http_status": 400, "cf_candidate": 1, "cf_text_match": 1, "cf_score": 7
            })
        self.store.stage_start("http")
        self.store.stage_finish("http", len(self.ips))

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_cf_filter_can_be_disabled_without_deleting_raw_rows(self):
        self.store.save_result(self.ips[0], {"http_status": 403, "cf_candidate": 0})
        self.assertEqual(self.store.pending_ips("ping"), self.ips[1:])
        filters = app.DEFAULT_FILTERS | {"prune_cf_miss": False}
        self.store.set_filters(filters)
        self.assertEqual(self.store.pending_ips("ping"), self.ips)
        self.assertEqual(len(self.store.all_rows()), 4)
        self.assertEqual(self.store.row_for_ip(self.ips[0])["http_status"], 403)

    def test_ping_filter_applies_when_building_tcping_cohort(self):
        for ip, loss in zip(self.ips, (0.0, 0.0, 25.0, 100.0)):
            self.store.save_result(ip, {
                "ping_status": "success" if loss == 0 else "timeout",
                "ping_ms": 15.0 if loss == 0 else None,
                "ping_loss_pct": loss,
            })
        self.store.stage_start("ping")
        self.store.stage_finish("ping", 4)
        filters = app.DEFAULT_FILTERS | {"prune_ping_loss": True}
        self.store.set_filters(filters)
        selected = self.store.prepare_stage_selection("tcping", 0, refresh=True)
        self.assertEqual(selected["item_count"], 2)
        self.assertEqual(self.store.stage_selection_ips("tcping"), self.ips[:2])

    def test_tcping_filter_applies_to_vless_cohort_and_can_be_recalculated(self):
        for ip in self.ips:
            self.store.save_result(ip, {
                "ping_status": "success", "ping_ms": 10.0, "ping_loss_pct": 0.0,
            })
        self.store.stage_start("ping")
        self.store.stage_finish("ping", 4)
        self.store.prepare_stage_selection("tcping", 0, refresh=True)
        statuses = [
            ("success", 100.0),
            ("failed", 0.0),
            ("partial", 60.0),
            ("success", 100.0),
        ]
        for ip, (status, pct) in zip(self.ips, statuses):
            self.store.save_result(ip, {
                "tcping_status": status, "tcping_success_pct": pct,
                "tcping_ms": 10.0 if pct else None,
            })
        self.store.stage_start("tcping")
        self.store.stage_finish("tcping", 4)
        self.store.set_filters(app.DEFAULT_FILTERS | {"prune_tcping_incomplete": True})
        filtered = self.store.prepare_stage_selection("speed", 0, refresh=True)
        self.assertEqual(filtered["item_count"], 2)
        self.assertEqual(self.store.stage_selection_ips("speed"), [self.ips[0], self.ips[3]])
        self.store.set_filters(app.DEFAULT_FILTERS)
        restored = self.store.prepare_stage_selection("speed", 0, refresh=True)
        self.assertEqual(restored["item_count"], 4)

    def test_manual_keep_and_exclude_override_auto_filters(self):
        self.store.save_result(self.ips[0], {"http_status": 400, "cf_candidate": 0})
        row = self.store.row_for_ip(self.ips[0])
        self.assertIn("CF 未命中", app.filter_reasons(row, app.DEFAULT_FILTERS))
        self.store.set_manual_override(self.ips[0], "keep")
        self.assertEqual(app.filter_reasons(self.store.row_for_ip(self.ips[0]), app.DEFAULT_FILTERS), [])
        self.store.set_manual_override(self.ips[0], "exclude")
        self.assertEqual(app.filter_reasons(self.store.row_for_ip(self.ips[0]), app.DEFAULT_FILTERS), ["手动排除"])
        self.store.set_manual_override(self.ips[0], "auto")
        self.assertIn("CF 未命中", app.filter_reasons(self.store.row_for_ip(self.ips[0]), app.DEFAULT_FILTERS))

    def test_attempt_history_survives_reopen_and_schema_migration(self):
        self.store.record_attempt(self.ips[0], "ping", 1, "timeout", "")
        self.store.record_attempt(self.ips[0], "ping", 2, "success", "")
        folder = self.folder
        self.store.close()
        self.store = app.TaskStore(folder)
        attempts = self.store.attempts_for(self.ips[0], "ping")
        self.assertEqual([row["status"] for row in attempts], ["timeout", "success"])
        self.assertTrue({"speed_tested_at", "speed_url", "speed_timeout_s",
                         "speed_concurrency", "speed_attempts", "manual_override"}.issubset(self.store.columns))

    def test_retry_policy_distinguishes_transient_and_deterministic_failures(self):
        self.assertTrue(app.ScanRunner._retryable_result("ping", {
            "ping_status": "timeout", "ping_error": ""
        }))
        self.assertFalse(app.ScanRunner._retryable_result("ping", {
            "ping_status": "error", "ping_error": "ping executable not found"
        }))
        self.assertTrue(app.ScanRunner._retryable_result("tcping", {
            "tcping_status": "failed", "tcping_error": "timed out"
        }))
        self.assertFalse(app.ScanRunner._retryable_result("tcping", {
            "tcping_status": "failed", "tcping_error": "Connection refused"
        }))

    def test_successful_initial_worker_result_is_not_reprobed(self):
        calls = []
        def worker(ip):
            calls.append(ip)
            return {"ping_status": "success", "ping_ms": 8.0, "ping_loss_pct": 0.0}
        runner = app.ScanRunner(self.store, {"retry_count": 1}, lambda *_: None)
        self.assertTrue(runner._run_stage("ping", [self.ips[0]], worker, 1))
        self.assertEqual(calls, [self.ips[0]])
        attempts = self.store.attempts_for(self.ips[0], "ping")
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0]["status"], "success")

    def test_http_retry_policy_handles_exception_text_without_crashing(self):
        self.assertFalse(app.ScanRunner._retryable_result("http", {
            "http_status": "error", "http_error": "connection refused"
        }))
        self.assertTrue(app.ScanRunner._retryable_result("http", {
            "http_status": -1, "http_error": "request timed out"
        }))

    def test_retry_attempts_are_persisted(self):
        runner = app.ScanRunner(self.store, {"retry_count": 1}, lambda *_: None)
        results = iter([
            {"ping_status": "timeout", "ping_error": ""},
            {"ping_status": "success", "ping_ms": 9.5, "ping_loss_pct": 0.0, "ping_error": ""},
        ])
        result = runner._run_with_retries("ping", lambda _ip: next(results), self.ips[0])
        self.assertEqual(result["_attempts"], 2)
        self.assertEqual([r["status"] for r in self.store.attempts_for(self.ips[0], "ping")],
                         ["timeout", "success"])

    def test_auto_pipeline_runs_expected_order_and_keeps_asn_manual(self):
        calls = []
        class FakeManualStageRunner:
            def __init__(self, store, config, emit, mode, stage, refresh_selection=False):
                self.emit = emit
                self.stage = stage
            def run(self):
                calls.append(self.stage)
                self.emit("done", (self.stage, "completed"))

        with tempfile.TemporaryDirectory() as td:
            xray = Path(td) / "xray.exe"
            xray.write_bytes(b"test placeholder")
            config = {"vless_uri": "vless://example", "xray_path": str(xray)}
            runner = app.AutoPipelineRunner(self.store, config, lambda *_: None, "shodan")
            with patch.object(app, "ManualStageRunner", FakeManualStageRunner):
                runner.run()
        self.assertEqual(calls, ["http", "ping", "tcping", "speed"])
        self.assertEqual(self.store.get_meta("auto_pipeline_active"), "0")
        self.assertEqual(self.store.get_meta("last_completed_stage"), "auto")

    def test_local_auto_pipeline_includes_tcp443_before_cf(self):
        calls = []
        class FakeManualStageRunner:
            def __init__(self, store, config, emit, mode, stage, refresh_selection=False):
                self.emit, self.stage = emit, stage
            def run(self):
                calls.append(self.stage)
                self.emit("done", (self.stage, "completed"))

        with tempfile.TemporaryDirectory() as td:
            xray = Path(td) / "xray.exe"
            xray.write_bytes(b"test placeholder")
            config = {"vless_uri": "vless://example", "xray_path": str(xray)}
            runner = app.AutoPipelineRunner(self.store, config, lambda *_: None, "local")
            with patch.object(app, "ManualStageRunner", FakeManualStageRunner):
                runner.run()
        self.assertEqual(calls, ["port", "http", "ping", "tcping", "speed"])


if __name__ == "__main__":
    unittest.main()
