import hashlib
import json

from fastapi.testclient import TestClient

from backend.access_control import AccessPolicy


def test_authenticated_analysis_case_evidence_and_report(monkeypatch):
    import backend.main as main
    identities = [
        {"subject": "alice", "role": "analyst", "key_sha256": hashlib.sha256(b"alice-token").hexdigest()},
        {"subject": "audit", "role": "auditor", "key_sha256": hashlib.sha256(b"audit-token").hexdigest()},
    ]
    monkeypatch.setattr(main, "access_policy", AccessPolicy(json.dumps(identities)))
    monkeypatch.setattr(main.v2_orchestrator.domain_provider, "inspect", lambda *args, **kwargs: {"findings": []})
    client = TestClient(main.app)
    headers = {"X-NETRA-API-Key": "alice-token"}
    raw = b"From: test@example.test\r\nSubject: Project meeting\r\n\r\nWe meet tomorrow."
    uploaded = client.post("/api/v2/emails/upload", files={"file": ("message.eml", raw, "message/rfc822")}, headers=headers)
    assert uploaded.status_code == 200, uploaded.text
    analysis = uploaded.json()
    assert analysis["evidence"]["sha256"] == hashlib.sha256(raw).hexdigest()
    email_id = analysis["email_id"]
    evidence_id = analysis["evidence_reference"]["evidence_id"]
    case = client.post("/api/v2/cases", json={"title": "Workflow test"}, headers=headers).json()
    case_id = case["case_id"]
    assert client.post(f"/api/v2/cases/{case_id}/emails/{email_id}", headers=headers).status_code == 200
    assert client.post(f"/api/v2/cases/{case_id}/evidence/{evidence_id}", headers=headers).status_code == 200
    noted = client.post(f"/api/v2/cases/{case_id}/notes", json={"note": "Reviewed", "actor": "forged-admin"}, headers=headers)
    assert noted.status_code == 200
    assert noted.json()["notes"][-1]["actor"] == "alice"
    report = client.post(f"/api/v2/cases/{case_id}/reports", params={"report_format": "json"}, headers=headers)
    assert report.status_code == 200, report.text
    assert report.json()["integrity_verified"]
    assert client.get(f"/api/v2/reports/{report.json()['report_id']}/download", headers=headers).status_code == 200
    summary = client.get(f"/api/v2/emails/{email_id}", headers=headers).json()
    assert summary["parsed"]["verified_authentication"]["status"] == "unsigned"
    audit = {"X-NETRA-API-Key": "audit-token"}
    assert client.get(f"/api/v2/cases/{case_id}", headers=audit).status_code == 200
    assert client.post("/api/v2/cases", json={"title": "Forbidden"}, headers=audit).status_code == 403
    assert client.get(f"/api/v2/evidence/{evidence_id}/verify", headers=audit).status_code == 403


def test_reconstructed_message_preservation_is_explicit(monkeypatch):
    import backend.main as main
    monkeypatch.setattr(main.v2_orchestrator.domain_provider, "inspect", lambda *args, **kwargs: {"findings": []})
    response = TestClient(main.app).post("/api/v2/emails/analyze", json={"subject": "Meeting", "body": "Tomorrow at ten."})
    assert response.status_code == 200, response.text
    result = response.json()
    evidence = main.evidence_service.get(result["evidence_reference"]["evidence_id"])
    assert evidence["evidence_type"] == "reconstructed_eml"
    assert any("reconstructed" in limitation for limitation in result["limitations"])


def test_header_injection_returns_validation_error():
    import backend.main as main
    response = TestClient(main.app).post("/api/v2/emails/analyze", json={"subject": "Hello\r\nBcc: stolen@example.test"})
    assert response.status_code == 400
