import hashlib
import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from backend.access_control import AccessPolicy


def record(subject, **extra):
    return {"subject": subject, "role": "submitter", "key_sha256": hashlib.sha256(subject.encode()).hexdigest(), **extra}


def test_submitters_can_only_read_their_own_analysis(monkeypatch):
    import backend.main as main
    monkeypatch.setattr(main, "access_policy", AccessPolicy(json.dumps([record("alice"), record("bob")])))
    monkeypatch.setattr(main.v2_orchestrator.domain_provider, "inspect", lambda *a, **kw: {"findings": []})
    client = TestClient(main.app)
    alice = {"X-NETRA-API-Key": "alice"}
    bob = {"X-NETRA-API-Key": "bob"}
    response = client.post("/api/v2/emails/analyze", headers=alice, json={"subject": "Private meeting", "body": "Tomorrow"})
    assert response.status_code == 200, response.text
    result = response.json()
    assert "correlation" not in result
    path = "/api/v2/emails/" + result["email_id"]
    assert client.get(path, headers=alice).status_code == 200
    assert client.get(path, headers=bob).status_code == 404
    assert client.get(path + "/findings", headers=bob).status_code == 404
    assert client.get("/api/v2/emails", headers=alice).status_code == 403
    assert client.get(path + "/graph", headers=alice).status_code == 403
    assert client.get("/api/v2/cases", headers=alice).status_code == 403
    assert client.get("/api/v2/me", headers=alice).json()["role"] == "submitter"


def test_disabling_all_keys_does_not_enable_local_admin(monkeypatch):
    import backend.main as main
    monkeypatch.setattr(main, "access_policy", AccessPolicy(json.dumps([record("alice", disabled=True)])))
    response = TestClient(main.app).get("/api/v2/cases")
    assert response.status_code == 401


def test_expired_credentials_are_rejected():
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    policy = AccessPolicy(json.dumps([record("alice", expires_at=yesterday)]))
    assert policy.authenticate("alice") is None


def test_invalid_disabled_flag_is_rejected():
    import pytest
    with pytest.raises(ValueError):
        AccessPolicy(json.dumps([record("alice", disabled="true")]))
