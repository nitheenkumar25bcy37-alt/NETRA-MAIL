import json
import os
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from backend.main import app
from dashboard.api_client import APIClient


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

    def test_render_dashboard_uses_the_same_api_as_the_extension(self):
        render_config = Path("render.yaml").read_text(encoding="utf-8")
        self.assertIn("value: https://netra-mail.onrender.com", render_config)
        connection = Path("extension/connection.js").read_text(encoding="utf-8")
        self.assertIn(
            'NETRA_DEFAULT_API_ORIGIN = "https://netra-mail.onrender.com"',
            connection,
        )
        background = Path("extension/background.js").read_text(encoding="utf-8")
        self.assertIn('url.searchParams.set("api_origin", netraOrigin(apiOrigin))', background)
        dashboard = Path("dashboard/app.py").read_text(encoding="utf-8")
        self.assertIn(
            'configured.base_url == "https://netra-mail-api.onrender.com"',
            dashboard,
        )

    def test_dashboard_explains_email_not_found_backend_mismatch(self):
        response = Mock(status_code=404)
        with patch.dict(os.environ, {}, clear=False), patch(
            "dashboard.api_client.requests.request", return_value=response
        ):
            client = APIClient("https://netra-mail.onrender.com")
            with self.assertRaisesRegex(
                RuntimeError, "dashboard and Gmail extension use the same API address"
            ):
                client.email("d8beb0a3-d9e4-47fe-b716-77fa3d89581d")


if __name__ == "__main__":
    unittest.main()
