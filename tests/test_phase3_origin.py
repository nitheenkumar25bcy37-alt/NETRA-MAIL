import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from backend.database import ForensicLedgerDB
from backend.header_analyzer import HeaderForensicAnalyzer
from backend.intelligence.domain_provider import DomainIntelligenceProvider
from backend.intelligence.ip_provider import IPIntelligenceProvider
from backend.main import app
from backend.parser import ForensicEmailParser
from backend.services.analysis_orchestrator import AnalysisOrchestrator


class FakeAnswer:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class FakeResolver:
    timeout = 1
    lifetime = 1

    def resolve(self, domain, record_type):
        values = {
            ("example.test", "A"): ["8.8.8.8"],
            ("example.test", "AAAA"): ["2001:4860:4860::8888"],
            ("example.test", "MX"): ["10 mail.example.test."],
            ("example.test", "NS"): ["ns1.example.test."],
            ("example.test", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.test", "TXT"): ["v=DMARC1; p=reject"],
        }
        if (domain, record_type) not in values:
            raise OSError("not found")
        return [FakeAnswer(value) for value in values[(domain, record_type)]]


class Phase3OriginTests(unittest.TestCase):
    def email_with_headers(self, received):
        return ("Received: " + received[0] + "\n" + "\n".join("Received: " + item for item in received[1:]) + "\nFrom: Sender <sender@example.test>\nTo: analyst@example.test\nMessage-ID: <x@example.test>\n\nHello").encode()

    def test_received_order_ipv4_ipv6_private_and_origin_candidates(self):
        raw = self.email_with_headers([
            "from edge.example (8.8.8.8) by mx.example; Sun, 23 Aug 2026 14:00:00 +0000",
            "from internal (2001:4860:4860::8888) by edge.example; Sun, 23 Aug 2026 13:59:00 +0000",
            "from local (10.0.0.5) by internal; Sun, 23 Aug 2026 13:58:00 +0000",
        ])
        parsed = ForensicEmailParser().parse_eml_bytes(raw)
        self.assertEqual([hop["header_order"] for hop in parsed["network_chain"]], [0, 1, 2])
        self.assertEqual(parsed["network_chain"][0]["source_hostname"], "edge.example")
        self.assertEqual(parsed["network_chain"][0]["destination_hostname"], "mx.example")
        self.assertIn("public", parsed["network_chain"][0]["ip_classifications"])
        self.assertIn("private", parsed["network_chain"][2]["ip_classifications"])
        result = HeaderForensicAnalyzer.analyze(parsed)
        self.assertTrue(result["origin_candidates"])
        self.assertLessEqual(result["origin_candidates"][0]["confidence"], 1.0)
        self.assertTrue(any("human sender" in item.lower() for item in result["limitations"]))

    def test_timestamp_disorder_malformed_and_repeated_hops(self):
        raw = self.email_with_headers([
            "from relay (8.8.8.8) by mx.example; Sun, 23 Aug 2026 13:00:00 +0000",
            "from relay (8.8.8.8) by mx.example; Sun, 23 Aug 2026 14:00:00 +0000",
            "malformed relay (8.8.8.8)",
        ])
        parsed = ForensicEmailParser().parse_eml_bytes(raw)
        result = HeaderForensicAnalyzer.analyze(parsed)
        rules = {finding["rule"] for finding in result["findings"]}
        self.assertIn("malformed_received", rules)
        self.assertIn("received_timestamp_order", rules)
        self.assertEqual(len(result["origin_candidates"]), 3)

    def test_ip_provider_unavailable_private_and_cache(self):
        provider = IPIntelligenceProvider(endpoint="", cache_dir=tempfile.mkdtemp())
        unavailable = provider.lookup("8.8.8.8")
        self.assertFalse(unavailable["available"])
        self.assertEqual(unavailable["source"], "unconfigured")
        private = provider.lookup("192.168.1.1")
        self.assertEqual(private["source"], "local_validation")
        self.assertIn("does not prove", private["limitation"])

        response = Mock(status_code=200)
        response.json.return_value = {"country": "Example", "asn": "AS1", "confidence": 0.7}
        with patch("backend.intelligence.ip_provider.requests.get", return_value=response) as request:
            configured = IPIntelligenceProvider(endpoint="https://intel.test", cache_dir=tempfile.mkdtemp())
            first = configured.lookup("1.1.1.1")
            second = configured.lookup("1.1.1.1")
            self.assertEqual(first["country"], "Example")
            self.assertEqual(second["asn"], "AS1")
            request.assert_called_once()

    def test_ip_provider_timeout_is_graceful(self):
        with patch("backend.intelligence.ip_provider.requests.get", side_effect=TimeoutError("slow")):
            result = IPIntelligenceProvider(endpoint="https://intel.test", cache_dir=tempfile.mkdtemp()).lookup("1.1.1.1")
        self.assertFalse(result["available"])
        self.assertEqual(result["source"], "provider_unavailable")

    def test_domain_records_and_dns_failure(self):
        provider = DomainIntelligenceProvider(resolver=FakeResolver())
        result = provider.inspect("example.test", related_ips=["1.1.1.1"])
        self.assertIn("A", result["records"])
        self.assertIn("MX", result["records"])
        self.assertIn("SPF", result["records"])
        self.assertIn("dmarc", result)
        missing = DomainIntelligenceProvider(resolver=FakeResolver()).inspect("missing.test")
        self.assertIn("missing_mx", {finding["rule"] for finding in missing["findings"]})

    def test_orchestrator_and_api_persist_trace(self):
        raw = self.email_with_headers(["from edge.example (8.8.8.8) by mx.example; Sun, 23 Aug 2026 14:00:00 +0000"])
        result = AnalysisOrchestrator().analyze(raw)
        self.assertIn("origin_trace", result.parsed)
        self.assertIn("domain_intelligence", result.parsed)
        with tempfile.TemporaryDirectory() as directory:
            database = ForensicLedgerDB(str(Path(directory) / "ledger.db"))
            database.record_v2_analysis(result.email_id, result.evidence.sha256, result.model_dump())
            self.assertEqual(database.get_v2_analysis(result.email_id)["email_id"], result.email_id)
        client = TestClient(app)
        response = client.post("/api/v2/emails/analyze", json={"subject": "Trace", "sender": "a@example.test", "body": "Hello"})
        self.assertEqual(response.status_code, 200)
        email_id = response.json()["email_id"]
        trace = client.get(f"/api/v2/emails/{email_id}/trace")
        self.assertEqual(trace.status_code, 200)
        self.assertIn("origin_candidates", trace.json())
        self.assertIn("limitations", trace.json())
        self.assertEqual(client.get("/api/v2/intelligence/ip/192.168.1.1").status_code, 200)
        self.assertEqual(client.get("/api/v2/intelligence/domain/example.test").status_code, 200)


if __name__ == "__main__":
    unittest.main()


def test_default_geo_provider_maps_network_owner_and_validates_coordinates(tmp_path, monkeypatch):
    monkeypatch.delenv("NETRA_IP_INTEL_URL", raising=False)
    response = Mock(status_code=200)
    response.json.return_value = {"ip": "8.8.8.8", "success": True, "country": "United States", "city": "Example", "latitude": 0, "longitude": 0, "connection": {"asn": 15169, "org": "Google LLC", "isp": "Google LLC"}}
    with patch("backend.intelligence.ip_provider.requests.get", return_value=response) as request:
        provider = IPIntelligenceProvider(cache_dir=str(tmp_path))
        result = provider.lookup("8.8.8.8")
        assert result["available"] and result["location_available"]
        assert result["organization"] == "Google LLC" and result["asn"] == 15169
        assert result["vpn"] is None and result["source"] == "ipwho.is"
        provider.lookup("8.8.8.8")
        request.assert_called_once_with("https://ipwho.is/8.8.8.8", timeout=3.0, allow_redirects=False)


def test_geo_service_failure_and_nonpublic_ips(tmp_path):
    response = Mock(status_code=200)
    response.json.return_value = {"success": False, "message": "Quota exceeded"}
    with patch("backend.intelligence.ip_provider.requests.get", return_value=response) as request:
        provider = IPIntelligenceProvider(endpoint="https://ipwho.is", cache_dir=str(tmp_path))
        assert not provider.lookup("8.8.8.8")["available"]
        assert not provider.lookup("192.168.1.2")["available"]
        assert not provider.lookup("203.0.113.1")["available"]
        assert request.call_count == 1


def test_geo_invalid_coordinates_do_not_reach_map(tmp_path):
    response = Mock(status_code=200)
    response.json.return_value = {"country": "Example", "latitude": "nan", "longitude": 190}
    with patch("backend.intelligence.ip_provider.requests.get", return_value=response):
        result = IPIntelligenceProvider(endpoint="https://ipwho.is", cache_dir=str(tmp_path)).lookup("8.8.8.8")
    assert result["available"] and not result["location_available"]
    assert result["latitude"] is None and result["longitude"] is None


def test_origin_lookup_budget_and_duplicate_caching():
    from backend.services.origin_trace import OriginTraceService
    provider = Mock()
    provider.lookup.return_value = {"available": True}
    hops = [{"extracted_ips": [f"8.8.8.{i}"], "ip_classifications": ["public"]} for i in [1, 2, 3, 4, 5, 5]]
    result = OriginTraceService.build({"network_chain": hops}, provider)
    assert provider.lookup.call_count == 4
    assert any(c["intelligence"]["source"] == "lookup_budget" for c in result["origin_candidates"] if not c["intelligence"].get("available"))
