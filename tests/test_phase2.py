import unittest

from backend.header_analyzer import HeaderForensicAnalyzer
from backend.intelligence.ip_provider import IPIntelligenceProvider


class HeaderAndInfrastructureTests(unittest.TestCase):
    def test_relay_analysis_identifies_public_origin_candidate(self):
        parsed = {
            "metadata": {"from": "Security Team <security@google.com>"},
            "authentication_headers": {},
            "network_chain": [{"hop_index": 1, "extracted_ips": ["185.220.101.5"], "ip_classifications": ["public"], "timestamp": "2026-08-23T14:00:00+00:00"}],
        }
        result = HeaderForensicAnalyzer.analyze(parsed)
        self.assertEqual(result["originating_ip"], "185.220.101.5")
        self.assertEqual(result["origin_candidates"][0]["confidence"], 0.65)

    def test_private_address_is_not_geolocated_as_a_sender_location(self):
        result = IPIntelligenceProvider().lookup("192.168.1.10")
        self.assertFalse(result["available"])
        self.assertEqual(result["ip_classification"], "private")


if __name__ == "__main__":
    unittest.main()
