import unittest

from backend.nlp_engine import NLPEngine


class NLPDetectionTests(unittest.TestCase):
    def test_bec_and_credential_language_is_explained(self):
        result = NLPEngine.analyze_text("Urgent: verify your credentials immediately and process the wire transfer.")
        self.assertGreaterEqual(result["score"], 50)
        self.assertIn("urgent", result["categories"]["urgency"])
        self.assertIn("wire transfer", result["categories"]["financial_fraud"])
        self.assertIn("Credential Phishing", result["attack_classification"])

    def test_ordinary_message_remains_low_risk(self):
        result = NLPEngine.analyze_text("The project meeting is scheduled for Wednesday afternoon.")
        self.assertEqual(result["risk_level"], "LOW")


if __name__ == "__main__":
    unittest.main()
