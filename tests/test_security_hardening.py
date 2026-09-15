import unittest

from backend.auth_analyzer import AuthenticationAnalyzer
from backend.security import valid_api_key


class AuthenticationEvidenceTests(unittest.TestCase):
    def test_dkim_header_without_trusted_result_is_not_a_pass(self):
        result = AuthenticationAnalyzer.analyze_headers(
            {"DKIM-Signature": "v=1; a=rsa-sha256; d=example.test"},
            "Security Team <security@example.test>",
        )
        self.assertEqual(result["dkim_status"], "UNVERIFIED")
        self.assertFalse(result["authenticated"])
        self.assertTrue(result["dkim_signature_present"])

    def test_upstream_authentication_result_is_explicitly_labelled(self):
        result = AuthenticationAnalyzer.analyze_headers(
            {"Authentication-Results": "mx.example; spf=pass; dkim=pass; dmarc=pass"},
            "Security Team <security@example.test>",
        )
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["authentication_source"], "upstream_authentication_results")
        self.assertIn("does not cryptographically", result["verification_scope"])


class AccessKeyTests(unittest.TestCase):
    def test_key_validation_requires_both_values(self):
        self.assertTrue(valid_api_key("demo-secret", "demo-secret"))
        self.assertFalse(valid_api_key("incorrect", "demo-secret"))
        self.assertFalse(valid_api_key("", "demo-secret"))
        self.assertFalse(valid_api_key("demo-secret", ""))


if __name__ == "__main__":
    unittest.main()
