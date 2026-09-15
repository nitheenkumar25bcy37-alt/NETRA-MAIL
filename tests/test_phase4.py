import unittest

from backend.compliance import IndiaPrivacyPreserver


class PrivacySafeguardTests(unittest.TestCase):
    def test_sensitive_identifiers_are_masked_but_email_domain_is_preserved(self):
        source = "Contact victim.name@enterprise.com; card 4532-1122-3344-5566; PAN ABCDE1234F."
        redacted = IndiaPrivacyPreserver.redact_text(source)
        self.assertNotIn("victim.name", redacted)
        self.assertIn("***@enterprise.com", redacted)
        self.assertNotIn("4532", redacted)
        self.assertIn("[REDACTED_PAYMENT_CARD]", redacted)
        self.assertIn("[REDACTED_PAN]", redacted)


if __name__ == "__main__":
    unittest.main()
