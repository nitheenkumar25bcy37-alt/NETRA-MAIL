import unittest
from email.message import EmailMessage

from backend.attachment_analyzer import AttachmentAnalyzer
from backend.header_analyzer import HeaderForensicAnalyzer
from backend.parser import ForensicEmailParser
from backend.services.analysis_orchestrator import AnalysisOrchestrator
from backend.url_analyzer import URLAnalyzer


class DetectionIntelligenceTests(unittest.TestCase):
    def make_email(self, body="Hello", html=None, headers=None, attachment=None):
        message = EmailMessage()
        message["From"] = "Security Team <security@example.test>"
        message["To"] = "user@example.test"
        message["Subject"] = "Notice"
        for key, value in (headers or {}).items():
            message[key] = value
        message.set_content(body)
        if html is not None:
            message.add_alternative(html, subtype="html")
        if attachment:
            message.add_attachment(attachment["data"], maintype=attachment["maintype"], subtype=attachment["subtype"], filename=attachment["filename"])
        return message.as_bytes()

    def test_parser_preserves_multipart_html_forms_headers_and_raw_bytes(self):
        raw = self.make_email(
            body="Plain body https://example.test/login",
            html='<form action="https://evil.test"><input type="hidden" name="token" value="x"><a href="https://evil.test/login">Verify</a></form><img src="cid:image1">',
            headers={"Cc": "copy@example.test", "Sender": "sender@example.test", "Message-ID": "<id@example.test>", "Received": "from host (2001:db8::1) by mx.test; Sun, 23 Aug 2026 14:00:00 +0000", "Content-ID": "<image1>"},
        )
        parsed = ForensicEmailParser().parse_eml_bytes(raw)
        self.assertEqual(parsed["raw_bytes"], raw)
        self.assertEqual(parsed["metadata"]["cc"], "copy@example.test")
        self.assertTrue(parsed["body"]["html_forms"])
        self.assertTrue(parsed["body"]["hidden_elements"])
        self.assertTrue(parsed["html_analysis"]["inline_images"])
        self.assertTrue(parsed["mime_structure"])
        self.assertTrue(parsed["received_headers"])

    def test_header_mismatch_auth_failures_ipv4_ipv6_and_private_ip(self):
        raw = ("Reply-To: help@other.test\nReturn-Path: bounce@other.test\nAuthentication-Results: mx.test; spf=fail smtp.mailfrom=other.test; dkim=fail header.d=other.test; dmarc=fail header.from=example.test\nReceived: from internal (192.168.1.5) by mx.test; Sun, 23 Aug 2026 14:00:00 +0000\nReceived: from relay (2001:db8::1) by internal; Sun, 23 Aug 2026 13:00:00 +0000\nFrom: Security <security@example.test>\nTo: user@example.test\n\nHello").encode()
        parsed = ForensicEmailParser().parse_eml_bytes(raw)
        result = HeaderForensicAnalyzer.analyze(parsed)
        rules = {finding["rule"] for finding in result["findings"]}
        self.assertIn("from_reply_to_mismatch", rules)
        self.assertIn("from_return_path_mismatch", rules)
        self.assertIn("spf_failure", rules)
        self.assertIn("dkim_failure", rules)
        self.assertIn("dmarc_failure", rules)
        self.assertIn("non_public_origin_ip", rules)
        self.assertTrue(result["relay_chain"])

    def test_authentication_alignment_and_timestamp_anomaly(self):
        raw = self.make_email(
            headers={
                "Authentication-Results": "mx.test; spf=pass smtp.mailfrom=sender.test; dkim=pass header.d=signer.test; dmarc=pass header.from=example.test",
                "Received": "from relay (203.0.113.10) by mx.test; not-a-date",
            }
        )
        result = HeaderForensicAnalyzer.analyze(ForensicEmailParser().parse_eml_bytes(raw))
        rules = {finding["rule"] for finding in result["findings"]}
        self.assertIn("spf_misalignment", rules)
        self.assertIn("dkim_misalignment", rules)
        self.assertIn("received_timestamp_anomaly", rules)
        self.assertFalse(any(finding["rule"] == "dmarc_failure" for finding in result["findings"]))

    def test_url_structured_findings_without_network_fetch(self):
        result = URLAnalyzer.analyze_references([
            {"href": "https://bit.ly/abc", "visible_text": "https://example.test/login"},
            {"href": "https://xn--pypal-4ve.test/login", "visible_text": ""},
            {"href": "http://127.0.0.1:8080/login", "visible_text": ""},
            {"href": "https://example.test/login?redirect=https%3A%2F%2Fevil.test", "visible_text": ""},
        ])
        rules = {finding["rule"] for finding in result["findings"]}
        self.assertIn("visible_href_mismatch", rules)
        self.assertIn("url_shortener", rules)
        self.assertIn("idn_or_mixed_script", rules)
        self.assertTrue(any("redirect" in item.get("redirect_indicators", []) for item in result["urls"]))
        self.assertFalse(result["network_fetch_performed"])

    def test_attachment_static_findings(self):
        result = AttachmentAnalyzer.analyze([
            {"filename": "invoice.pdf.exe", "content_type": "application/pdf", "size_bytes": 12, "sha256": "hash"},
            {"filename": "document.docm", "content_type": "application/vnd.ms-word.document.macroEnabled.12", "size_bytes": 12, "sha256": "hash2"},
            {"filename": "archive.zip", "content_type": "application/zip", "archive_members": [{"filename": "update.js", "encrypted": False}], "size_bytes": 12, "sha256": "hash3"},
            {"filename": "report.pdf", "content_type": "application/octet-stream", "size_bytes": 12, "sha256": "hash4"},
        ])
        # The attachment analyser exposes human-readable, static evidence;
        # raw archive bytes are required before a nested member can be claimed.
        reasons = " ".join(result["findings"])
        self.assertIn("Dangerous executable/script attachment", reasons)
        self.assertIn("Double-extension filename", reasons)
        self.assertIn("Macro-enabled Office document", reasons)
        self.assertGreaterEqual(result["score"], 80)

    def test_legitimate_email_has_no_high_risk_findings(self):
        raw = self.make_email(body="The meeting notes are attached. Please review when convenient.")
        result = AnalysisOrchestrator().analyze(raw)
        self.assertLess(result.risk_score, 50)
        self.assertFalse(any(f.severity in {"high", "critical"} for f in result.findings))


if __name__ == "__main__":
    unittest.main()
