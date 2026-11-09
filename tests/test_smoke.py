import unittest

import cf_ip_finder as app
import cf_ip_tester_legacy as legacy


class ParserSmokeTests(unittest.TestCase):
    def test_cidr_includes_all_ipv4_addresses(self):
        targets = app.parse_targets("192.0.2.0/30")
        self.assertEqual([ip for ip, _ in targets], [
            "192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"
        ])

    def test_range_and_deduplication(self):
        targets = app.parse_targets("192.0.2.1-192.0.2.3\n192.0.2.2")
        self.assertEqual([ip for ip, _ in targets], [
            "192.0.2.1", "192.0.2.2", "192.0.2.3"
        ])

    def test_shodan_csv_extracts_ipv4(self):
        targets = app.parse_shodan_targets("ip_str,port\n192.0.2.10,443\n192.0.2.10,443")
        self.assertEqual([ip for ip, _ in targets], ["192.0.2.10"])

    def test_vless_template_parser(self):
        uri = ("vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?"
               "encryption=none&security=tls&sni=example.com&type=ws&"
               "host=cdn.example.com&path=%2Fws#smoke")
        parsed = app.parse_vless(uri)
        legacy_parsed = legacy.parse_vless_link(uri)
        config = legacy.build_xray_config(legacy_parsed, "192.0.2.22", 10888)
        outbound = config["outbounds"][0]
        self.assertEqual(parsed["network"], "ws")
        self.assertEqual(outbound["settings"]["address"], "192.0.2.22")
        self.assertEqual(outbound["streamSettings"]["tlsSettings"]["serverName"], "example.com")
        self.assertEqual(outbound["streamSettings"]["wsSettings"]["host"], "cdn.example.com")


if __name__ == "__main__":
    unittest.main()
