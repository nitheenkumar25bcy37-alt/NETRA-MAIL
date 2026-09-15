import json
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app


class Phase6DashboardTests(unittest.TestCase):
    def test_dashboard_summary_and_email_list_schema(self):
        client = TestClient(app)
        summary = client.get("/api/v2/dashboard/summary")
        emails = client.get("/api/v2/emails", params={"limit": 2, "offset": 0})
        self.assertEqual(summary.status_code, 200)
        self.assertIn("total_emails", summary.json())
        self.assertIn("provider_status", summary.json())
        self.assertEqual(emails.status_code, 200)
        self.assertIn("items", emails.json())
        self.assertLessEqual(len(emails.json()["items"]), 2)

    def test_unavailable_provider_and_unknown_email_are_honest(self):
        client = TestClient(app)
        provider = client.get("/api/v2/intelligence/ip/192.168.1.1")
        missing = client.get("/api/v2/emails/does-not-exist")
        self.assertEqual(provider.status_code, 200)
        self.assertFalse(provider.json()["available"])
        self.assertIn("limitation", provider.json())
        self.assertEqual(missing.status_code, 404)

    def test_extension_permissions_and_user_triggered_api_contract(self):
        manifest = json.loads(Path("extension/manifest.json").read_text(encoding="utf-8"))
        content = Path("extension/content.js").read_text(encoding="utf-8")
        popup = Path("extension/popup.js").read_text(encoding="utf-8")
        self.assertEqual(manifest["manifest_version"], 3)
        self.assertNotIn("<all_urls>", manifest.get("host_permissions", []))
        self.assertIn("NETRA_ANALYZE_CURRENT_EMAIL", content)
        background = Path("extension/background.js").read_text(encoding="utf-8")
        self.assertIn("/api/v2/emails/analyze", background)
        self.assertNotIn("scheduleScan();", content)
        self.assertIn("Analyze current email", Path("extension/popup.html").read_text(encoding="utf-8"))
        self.assertIn("NETRA_ANALYZE_CURRENT_EMAIL", popup)


if __name__ == "__main__":
    unittest.main()
