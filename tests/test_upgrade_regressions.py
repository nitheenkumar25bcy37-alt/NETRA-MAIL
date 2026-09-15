import hashlib
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.access_control import AccessPolicy, Principal
from backend.header_analyzer import HeaderForensicAnalyzer
from backend.ml_classifier import LocalMLClassifier
from backend.services.risk_engine import RiskEngine
from backend.url_analyzer import URLAnalyzer


def finding(category, severity, rule):
    return dict(category=category, severity=severity, rule=rule, confidence=0.9)


def test_informational_attachment_cannot_turn_sender_warning_into_malware():
    result = RiskEngine.evaluate([
        finding("Attachment", "info", "attachment_metadata"),
        finding("Sender identity", "high", "impersonation"),
    ])
    assert result["classification"] != "Malware delivery"


def test_info_authentication_does_not_classify_email_as_phishing():
    result = RiskEngine.evaluate([finding("Authentication", "info", "missing_auth")])
    assert result["classification"] == "Legitimate or low risk"
    assert result["risk_score"] == 0


@pytest.mark.parametrize("status", ["softfail", "temperror", "permerror", "bestguesspass"])
def test_authentication_status_preserves_uncertainty(status):
    assert HeaderForensicAnalyzer._status("spf", "spf=" + status) == status


def test_private_relay_is_not_a_threat():
    result = HeaderForensicAnalyzer.analyze({"network_chain": [
        {"extracted_ips": ["10.0.0.1"], "ip_classifications": ["private"]}
    ]})
    assert result["header_risk_score"] == 0


def test_url_dataset_rejected_for_email_training(tmp_path):
    path = tmp_path / "url.csv"
    path.write_text("url,label\nhttps://example.com,0\n")
    with patch.object(LocalMLClassifier, "DATASET_PATH", path):
        with pytest.raises(ValueError, match="text,label"):
            LocalMLClassifier._dataset()


def test_corrupt_model_is_never_silently_overwritten(tmp_path):
    path = tmp_path / "model.joblib"
    path.write_bytes(b"corrupt artifact")
    with patch.object(LocalMLClassifier, "MODEL_PATH", path):
        with pytest.raises(RuntimeError, match="explicit retraining"):
            LocalMLClassifier._load()
    assert path.read_bytes() == b"corrupt artifact"


def test_access_roles_and_token_digests():
    import json
    digest = hashlib.sha256(b"test-token").hexdigest()
    policy = AccessPolicy(json.dumps([dict(subject="auditor-1", role="auditor", key_sha256=digest)]))
    identity = policy.authenticate("test-token")
    assert identity.subject == "auditor-1"
    assert policy.authenticate("wrong-token") is None
    assert policy.allowed(identity, "GET", "/api/v2/cases")
    assert not policy.allowed(identity, "POST", "/api/v2/cases")
    assert not policy.allowed(identity, "GET", "/api/v2/evidence/id/verify")
    assert not policy.allowed(Principal("analyst", "analyst"), "DELETE", "/api/v2/cases/x/emails/y")


def test_remote_unauthenticated_client_is_rejected():
    import backend.main as main
    with patch.object(main, "API_AUTH_REQUIRED", False):
        client = TestClient(main.app, client=("203.0.113.8", 1234))
        assert client.get("/api/v2/cases").status_code == 401
        assert client.get("/health").status_code == 200


def test_browser_origin_cannot_bypass_local_mode():
    from backend.main import app
    response = TestClient(app).get("/api/v2/cases", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403


def test_ledger_detects_verdict_tampering(tmp_path):
    from backend.database import ForensicLedgerDB
    db = ForensicLedgerDB(str(tmp_path / "ledger.db"))
    db.record_evidence("case1", "a" * 64, 80, "HIGH", {})
    assert db.verify_chain_integrity()["valid"]
    with db._connect() as conn:
        conn.execute("UPDATE evidence_ledger SET verdict='SAFE'")
        conn.commit()
    assert not db.verify_chain_integrity()["valid"]


def test_concurrent_ledger_appends_have_one_chain(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from backend.database import ForensicLedgerDB
    db = ForensicLedgerDB(str(tmp_path / "ledger.db"))
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda index: db.record_evidence(str(index), "b" * 64, 10, "LOW", {}), range(12)))
    result = db.verify_chain_integrity()
    assert result["valid"]
    assert result["total_records"] == 12


def test_url_expander_cannot_contact_internal_services():
    from backend.url_expander import URLExpander
    with patch("requests.Session.head", side_effect=AssertionError("network request attempted")):
        assert URLExpander.expand("http://127.0.0.1/admin")["error"] == "isolated_fetch_disabled"


def test_evidence_reference_cannot_escape_storage(tmp_path):
    from backend.database import ForensicLedgerDB
    from backend.evidence_service import EvidenceService
    db = ForensicLedgerDB(str(tmp_path / "ledger.db"))
    service = EvidenceService(db, str(tmp_path / "evidence"))
    evidence = service.register(b"test", "sample.eml", "message/rfc822")
    (tmp_path / "outside.txt").write_bytes(b"test")
    with db._connect() as conn:
        conn.execute("UPDATE evidence SET storage_reference='../outside.txt'")
        conn.commit()
    assert service.verify(evidence["evidence_id"])["integrity_status"] == "unavailable"
def test_at_sign_in_query_is_not_url_userinfo():
    result = URLAnalyzer.analyze_url("https://fonts.googleapis.com/css2?family=Roboto:wght@400&display=swap")
    assert result["userinfo_present"] is False
    assert "Google" not in result.get("impersonated_brands", [])


def test_low_authentication_review_signal_is_not_classified_as_phishing():
    result = RiskEngine.evaluate([{"category": "Authentication", "rule": "message_id_domain_mismatch",
        "severity": "low", "confidence": 0.72, "title": "Review signal"}])
    assert result["classification"] == "Legitimate or low risk"


def test_internal_hostname_is_warning_not_automatic_ssrf_block():
    from backend.main import _apply_ssrf_decision_override, _apply_ssrf_scoring_override
    url = {"urls": [{"hostname": "portal.company.internal", "ssrf_risk": True,
                     "is_local_hostname": True, "risk_score": 39}]}
    scoring = _apply_ssrf_scoring_override({"threat_score": 28, "confidence": 30}, url)
    decision = _apply_ssrf_decision_override(
        {"risk": "MEDIUM", "score": 28, "action": "REVIEW", "confidence": 30},
        scoring, url,
    )
    assert scoring["threat_score"] == 28
    assert decision["action"] == "REVIEW"


def test_private_ip_remains_high_confidence_ssrf_block():
    from backend.main import _apply_ssrf_decision_override, _apply_ssrf_scoring_override
    url = {"urls": [{"hostname": "127.0.0.1", "ssrf_risk": True,
                     "is_ip_address": True, "is_loopback": True, "risk_score": 79}]}
    scoring = _apply_ssrf_scoring_override({"threat_score": 20, "confidence": 30}, url)
    decision = _apply_ssrf_decision_override(
        {"risk": "SAFE", "score": 20, "action": "ALLOW", "confidence": 30},
        scoring, url,
    )
    assert scoring["threat_score"] >= 75
    assert decision["action"] == "BLOCK"
