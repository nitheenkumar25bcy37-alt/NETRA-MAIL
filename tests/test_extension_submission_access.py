import hashlib
import json

from fastapi.testclient import TestClient

from backend.access_control import AccessPolicy


def test_extension_origin_alone_cannot_authorize_reconstructed_email(monkeypatch):
    import backend.main as main

    origin = "chrome-extension://knckclcnbppcnhinmehnpajloflmjcgm"
    identities = [{
        "subject": "admin",
        "role": "admin",
        "key_sha256": hashlib.sha256(b"admin-secret").hexdigest(),
    }]
    monkeypatch.setattr(main, "access_policy", AccessPolicy(json.dumps(identities)))
    monkeypatch.setattr(main, "ALLOW_EXTENSION_SUBMISSIONS", True)
    monkeypatch.setattr(main, "NETRA_EXTENSION_ORIGIN", origin)
    monkeypatch.setattr(main, "ALLOWED_ORIGINS", [origin])
    monkeypatch.setattr(main.v2_orchestrator.domain_provider, "inspect", lambda *args, **kwargs: {"findings": []})

    client = TestClient(main.app)
    response = client.post(
        "/api/v2/emails/analyze",
        headers={"Origin": origin},
        json={"subject": "Project meeting", "body": "Tomorrow at ten."},
    )
    assert response.status_code == 401, response.text

    # The original-message route has the same scoped submission identity.
    invalid_original = client.post("/api/v2/mailbox/analyze", headers={"Origin": origin}, json={})
    assert invalid_original.status_code == 400, invalid_original.text

    assert client.get("/api/v2/me", headers={"Origin": origin}).status_code == 401
    assert client.post(
        "/api/v2/emails/analyze",
        json={"subject": "Missing origin", "body": "This must be rejected."},
    ).status_code == 401
