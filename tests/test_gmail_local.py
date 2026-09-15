import json
from types import SimpleNamespace
from backend import gmail_local
from evaluation.html_report import render_report


def test_oauth_uses_readonly_loopback_pkce_without_token_file(tmp_path, monkeypatch):
    from google_auth_oauthlib.flow import InstalledAppFlow
    client = tmp_path / "client.json"
    client.write_text(json.dumps({"installed": {"auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token"}}))
    def factory(config, scopes, **kwargs):
        assert scopes == [gmail_local.SCOPE]
        assert kwargs["autogenerate_code_verifier"] is True
        class Flow:
            def run_local_server(self, **options):
                assert options["host"] == "127.0.0.1"
                assert options["port"] == 0
                assert options["timeout_seconds"] == 180
                return SimpleNamespace(token="mock")
        return Flow()
    monkeypatch.setattr(InstalledAppFlow, "from_client_config", factory)
    assert gmail_local.authorize(client).token == "mock"
    assert list(tmp_path.iterdir()) == [client]


def test_report_escapes_dataset_names():
    report = {"scope": "test", "threshold": 25, "limitations": [], "rows": [{"path": "<script>alert(1)</script>"}]}
    result = render_report(report)
    assert "<script>" not in result
    assert "&lt;script&gt;" in result
