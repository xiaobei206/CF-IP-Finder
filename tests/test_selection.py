import tempfile
import unittest
from pathlib import Path

import cf_ip_finder as app


class CandidateFunnelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = app.TaskStore(Path(self.temp.name) / "task", create=True)
        ips = [f"192.0.2.{i}" for i in range(1, 6)]
        self.store.add_targets([(ip, i) for i, ip in enumerate(ips, 1)])
        self.store.mark_shodan_imported()
        for ip in ips:
            self.store.save_result(ip, {
                "http_status": 400, "cf_candidate": 1, "cf_text_match": 1, "cf_score": 7
            })
        self.store.stage_start("http")
        self.store.stage_finish("http", len(ips))
        self.store.save_result("192.0.2.1", {"ping_status": "success", "ping_ms": 10.0, "ping_loss_pct": 0.0})
        self.store.save_result("192.0.2.2", {"ping_status": "success", "ping_ms": 20.0, "ping_loss_pct": 0.0})
        self.store.save_result("192.0.2.3", {"ping_status": "success", "ping_ms": 30.0, "ping_loss_pct": 0.0})
        self.store.save_result("192.0.2.4", {"ping_status": "timeout", "ping_ms": None, "ping_loss_pct": 100.0})
        self.store.save_result("192.0.2.5", {"ping_status": "error", "ping_ms": None, "ping_loss_pct": 100.0})
        self.store.stage_start("ping")
        self.store.stage_finish("ping", 5)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_ping_limit_zero_includes_all_nonresponders(self):
        selection = self.store.prepare_stage_selection("tcping", 0)
        self.assertEqual(selection["item_count"], 5)
        self.assertEqual(selection["missing_latency_count"], 2)
        self.assertEqual(self.store.stage_selection_ips("tcping"), [
            "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"
        ])

    def test_ping_positive_limit_uses_lowest_latency_first(self):
        selection = self.store.prepare_stage_selection("tcping", 2)
        self.assertEqual(selection["item_count"], 2)
        self.assertEqual(self.store.stage_selection_ips("tcping"), ["192.0.2.1", "192.0.2.2"])

    def test_ping_limit_can_fill_with_no_response_if_needed(self):
        self.store.prepare_stage_selection("tcping", 4)
        self.assertEqual(self.store.stage_selection_ips("tcping"), [
            "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"
        ])

    def test_tcping_limit_zero_includes_all_failed_connections(self):
        self.store.prepare_stage_selection("tcping", 0)
        self.store.save_result("192.0.2.1", {
            "tcping_status": "success", "tcping_ms": 5.0, "tcping_max_ms": 8.0, "tcping_success_pct": 100.0
        })
        self.store.save_result("192.0.2.2", {
            "tcping_status": "partial", "tcping_ms": 7.0, "tcping_max_ms": 12.0, "tcping_success_pct": 80.0
        })
        self.store.save_result("192.0.2.3", {
            "tcping_status": "failed", "tcping_ms": None, "tcping_success_pct": 0.0
        })
        self.store.save_result("192.0.2.4", {
            "tcping_status": "failed", "tcping_ms": None, "tcping_success_pct": 0.0
        })
        self.store.save_result("192.0.2.5", {
            "tcping_status": "failed", "tcping_ms": None, "tcping_success_pct": 0.0
        })
        self.store.stage_start("tcping")
        self.store.stage_finish("tcping", 5)
        selection = self.store.prepare_stage_selection("speed", 0)
        self.assertEqual(selection["item_count"], 5)
        self.assertEqual(selection["missing_latency_count"], 3)
        self.assertEqual(self.store.stage_selection_ips("speed"), [
            "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"
        ])

    def test_tcping_positive_limit_ranks_by_connect_latency(self):
        self.store.prepare_stage_selection("tcping", 0)
        values = [
            ("192.0.2.1", 5.0, 100.0, 8.0),
            ("192.0.2.2", 7.0, 80.0, 12.0),
            ("192.0.2.3", 4.0, 20.0, 30.0),
            ("192.0.2.4", None, 0.0, None),
            ("192.0.2.5", None, 0.0, None),
        ]
        for ip, avg, success, maximum in values:
            self.store.save_result(ip, {
                "tcping_status": "success" if success == 100 else ("partial" if success else "failed"),
                "tcping_ms": avg, "tcping_success_pct": success, "tcping_max_ms": maximum
            })
        self.store.stage_start("tcping")
        self.store.stage_finish("tcping", 5)
        self.store.prepare_stage_selection("speed", 2)
        self.assertEqual(self.store.stage_selection_ips("speed"), ["192.0.2.3", "192.0.2.1"])

    def test_snapshot_is_reused_after_results_or_settings_change(self):
        self.store.prepare_stage_selection("tcping", 2)
        self.store.save_result("192.0.2.1", {"ping_ms": 999.0})
        reused = self.store.prepare_stage_selection("tcping", 5)
        self.assertTrue(reused["reused"])
        self.assertEqual(reused["limit_n"], 2)
        self.assertEqual(self.store.stage_selection_ips("tcping"), ["192.0.2.1", "192.0.2.2"])
        refreshed = self.store.prepare_stage_selection("tcping", 1, refresh=True)
        self.assertFalse(refreshed["reused"])
        self.assertEqual(self.store.stage_selection_ips("tcping"), ["192.0.2.2"])

    def test_pending_stage_queue_uses_snapshot_not_table_order(self):
        self.store.prepare_stage_selection("tcping", 2)
        self.store.save_result("192.0.2.1", {"tcping_status": "success", "tcping_ms": 5.0})
        self.assertEqual(self.store.pending_ips("tcping"), ["192.0.2.2"])

    def test_selection_requires_completed_source_stage(self):
        other = app.TaskStore(Path(self.temp.name) / "empty", create=True)
        try:
            with self.assertRaisesRegex(ValueError, "请先完成 PING"):
                other.prepare_stage_selection("tcping", 0)
        finally:
            other.close()

    def test_selection_snapshot_survives_database_reopen(self):
        self.store.prepare_stage_selection("tcping", 0)
        folder = self.store.folder
        self.store.close()
        reopened = app.TaskStore(folder)
        try:
            self.assertEqual(len(reopened.stage_selection_ips("tcping")), 5)
            self.assertTrue((folder / "stages" / "05_ping_selected.txt").exists())
        finally:
            reopened.close()


    def test_speed_limit_zero_is_bounded_by_actual_tcping_cohort(self):
        # Only the two fastest PING results are actually sent to TCPING.
        self.store.prepare_stage_selection("tcping", 2)
        for ip in ("192.0.2.1", "192.0.2.2"):
            self.store.save_result(ip, {
                "tcping_status": "failed", "tcping_ms": None, "tcping_success_pct": 0.0
            })
        self.store.stage_start("tcping")
        self.store.stage_finish("tcping", 2)

        # 0=all means all TCPING candidates, including failures — not every CF hit.
        selection = self.store.prepare_stage_selection("speed", 0)
        self.assertEqual(selection["item_count"], 2)
        self.assertEqual(self.store.stage_selection_ips("speed"), ["192.0.2.1", "192.0.2.2"])

    def test_legacy_task_without_tcping_snapshot_uses_completed_tcping_rows(self):
        # 0.1.2 tasks have a completed TCPING stage but no durable selection table rows.
        for ip in [f"192.0.2.{i}" for i in range(1, 6)]:
            self.store.save_result(ip, {
                "tcping_status": "failed", "tcping_ms": None, "tcping_success_pct": 0.0
            })
        self.store.stage_start("tcping")
        self.store.stage_finish("tcping", 5)
        selection = self.store.prepare_stage_selection("speed", 0)
        self.assertEqual(selection["item_count"], 5)


if __name__ == "__main__":
    unittest.main()
