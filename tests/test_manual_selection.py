import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cf_ip_finder as app
import cf_ip_tester_legacy as legacy


URI = (
    "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?"
    "encryption=none&security=tls&sni=example.com&type=ws&"
    "host=cdn.example.com&path=%2Fws#manual-selection-test"
)


class ManualSelectionRunnerTests(unittest.TestCase):
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
        for index, ip in enumerate(self.ips, 1):
            self.store.save_result(ip, {
                "ping_status": "success", "ping_ms": float(index), "ping_loss_pct": 0.0
            })
        self.store.stage_start("ping")
        self.store.stage_finish("ping", len(self.ips))
        self.store.prepare_stage_selection("tcping", 1)
        self.snapshot = self.store.stage_selection_ips("tcping")
        self.events = []

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def _run(self, stage, selected, config=None):
        runner = app.ManualSelectionRunner(
            self.store, config or {}, lambda *event: self.events.append(event),
            "shodan", stage, selected
        )
        runner.run()
        return runner

    def test_tcping_runs_exact_selection_and_leaves_global_funnel_untouched(self):
        selected = [self.ips[2], self.ips[3]]
        before_stage_status = self.store.stage_status("tcping")
        before_active_stage = self.store.get_meta("active_stage", "")
        def fake_tcping(ip, count, timeout):
            return {"tcping_status": "success", "tcping_ms": 12.0,
                    "tcping_min_ms": 10.0, "tcping_max_ms": 14.0,
                    "tcping_success_pct": 100.0, "tcping_successes": count,
                    "tcping_error": ""}
        with patch.object(app, "tcping_probe", side_effect=fake_tcping) as probe:
            self._run("tcping", selected, {"tcping_count": 3, "tcping_timeout": 0.5, "probe_workers": 2})
        self.assertEqual({call.args[0] for call in probe.call_args_list}, set(selected))
        self.assertEqual(self.store.stage_selection_ips("tcping"), self.snapshot)
        self.assertEqual(self.store.stage_status("tcping"), before_stage_status)
        self.assertEqual(self.store.get_meta("active_stage", ""), before_active_stage)
        self.assertEqual(self.store.stage_status("speed"), "pending")
        rows = {row["ip"]: row for row in self.store.all_rows()}
        self.assertEqual(rows[selected[0]]["tcping_status"], "success")
        self.assertIsNone(rows[self.ips[0]]["tcping_status"])

    def test_route_lookup_uses_exact_selection_not_global_shodan_top_n(self):
        selected = [self.ips[1], self.ips[3]]
        def fake_route(ip):
            return {"asn_info_status": "ok", "asn": "AS64500", "organization": "Example",
                    "bgp_prefix": "192.0.2.0/24", "route_source": "test", "route_error": ""}
        with patch.object(app, "route_info_probe", side_effect=fake_route) as probe:
            self._run("route", selected, {"asn_limit": 1, "route_workers": 2})
        self.assertEqual({call.args[0] for call in probe.call_args_list}, set(selected))
        rows = {row["ip"]: row for row in self.store.all_rows()}
        for ip in selected:
            self.assertEqual(rows[ip]["asn_info_status"], "ok")
        self.assertIsNone(rows[self.ips[0]]["asn_info_status"])
        self.assertEqual(self.store.stage_status("route"), "pending")

    def test_selected_vless_uses_legacy_tester_without_global_speed_selection(self):
        selected = [self.ips[2], self.ips[0]]
        fake_result = {"ok": True, "speed": 2.75, "bytes": 102400, "latency": 120.0, "error": ""}
        with tempfile.TemporaryDirectory() as td:
            xray = Path(td) / "xray.exe"
            xray.write_bytes(b"test-only placeholder; validation is mocked")
            config = {
                "vless_uri": URI, "xray_path": str(xray), "speed_url": "http://example.test/file.bin",
                "speed_timeout": 5, "speed_workers": 1
            }
            with patch.object(legacy, "validate_xray_config", return_value=(True, "mock-valid")) as validate, \
                 patch.object(legacy, "test_one_ip", return_value=fake_result) as tester:
                self._run("speed", selected, config)
            validate.assert_called_once()
            self.assertEqual({call.args[0] for call in tester.call_args_list}, set(selected))
        self.assertIsNone(self.store.stage_selection_info("speed"))
        self.assertEqual(self.store.stage_status("speed"), "pending")
        rows = {row["ip"]: row for row in self.store.all_rows()}
        for ip in selected:
            self.assertEqual(rows[ip]["vless_status"], "success")
            self.assertEqual(rows[ip]["speed_mbps"], 2.75)
        self.assertIsNone(rows[self.ips[1]]["vless_status"])


if __name__ == "__main__":
    unittest.main()
