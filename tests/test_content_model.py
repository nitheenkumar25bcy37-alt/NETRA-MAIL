import gzip
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from backend.content_model import ROOT, content_text, normalize, predict
from backend.services.risk_engine import RiskEngine


def test_header_and_contact_features_are_excluded():
    text = content_text({"metadata": {"subject": "Meeting", "from": "Hidden Sender <secret@example.test>"},
                         "body": {"plain": "Hello"}, "headers": {"Received": "Corpus-specific marker"}})
    assert "Hidden" not in text and "marker" not in text
    assert normalize("For alice@example.org, alice: visit https://secret.test/token123 on 2026") == normalize("For bob@example.net, bob: visit https://different.test/private456 on 1999")


def test_bundled_model_and_explicit_disable(monkeypatch):
    result = predict("Our team will meet tomorrow to discuss the proposed software changes and review the project schedule.")
    assert result["available"] and result["training_samples"] == 240
    assert result["public_training_samples"] == 200 and result["synthetic_context_samples"] == 40
    assert result["request_review"] is False
    monkeypatch.setenv("NETRA_CONTENT_MODEL_ENABLED", "false")
    assert predict("Hello")["available"] is False


def test_corrupt_artifact_fails_safely(tmp_path, monkeypatch):
    path = tmp_path / "broken.json.gz"
    path.write_bytes(b"not a model")
    path.with_suffix(".manifest.json").write_text(json.dumps({"sha256": "0" * 64}))
    monkeypatch.setenv("NETRA_CONTENT_MODEL_PATH", str(path))
    assert predict("Hello")["available"] is False


def test_correct_hash_does_not_bypass_schema_validation(tmp_path, monkeypatch):
    path = tmp_path / "broken.json.gz"
    data = gzip.compress(json.dumps({"schema": 1, "weights": [0], "intercept": 0, "threshold": .5}).encode())
    path.write_bytes(data)
    path.with_suffix(".manifest.json").write_text(json.dumps({"sha256": hashlib.sha256(data).hexdigest()}))
    monkeypatch.setenv("NETRA_CONTENT_MODEL_PATH", str(path))
    assert predict("Hello")["available"] is False


def test_model_review_is_inconclusive_and_cannot_erase_malware():
    model = {"category": "Machine learning", "rule": "content_model_review", "severity": "medium", "confidence": .8}
    result = RiskEngine.evaluate([model])
    assert result["risk_score"] == 35 and result["classification"] == "Suspicious but inconclusive"
    malware = {"category": "Attachment", "rule": "attachment_hash_blocklist", "severity": "critical", "confidence": 1}
    assert RiskEngine.evaluate([malware])["risk_score"] >= 75


def test_training_hashes_disjoint_from_all_reported_test_sets():
    manifest = json.loads((ROOT / "linear.json.manifest.json").read_text())
    train = set(manifest["training_hashes"])
    old = json.loads(Path("evaluation_results/upgrades/reliability_before.json").read_text())
    fresh = json.loads(Path("evaluation_results/upgrades/reliability_audit_before.json").read_text())
    old_hashes = {r["sha256"] for r in old["rows"]}
    fresh_hashes = {r["sha256"] for r in fresh["rows"]}
    final = json.loads(Path("evaluation_results/upgrades/reliability_final_audit_before.json").read_text())
    final_hashes = {r["sha256"] for r in final["rows"]}
    assert len(train) == 200 and len(old_hashes) == 200 and len(fresh_hashes) == 200
    assert not (train & old_hashes or train & fresh_hashes or old_hashes & fresh_hashes)
    assert len(final_hashes) == 200 and not final_hashes & (train | old_hashes | fresh_hashes)


def test_content_model_works_without_legacy_pickle(monkeypatch):
    from email.message import EmailMessage
    from backend.services.analysis_orchestrator import AnalysisOrchestrator
    from evaluation.evaluate_v2 import OfflineDomains, OfflineIPs
    monkeypatch.setattr("backend.services.analysis_orchestrator.LocalMLClassifier.predict", lambda *args: (_ for _ in ()).throw(RuntimeError("missing")))
    msg = EmailMessage()
    msg["Subject"] = "Verify your mailbox password immediately"
    msg.set_content("Your email account will be suspended. Verify your password now to prevent termination of your mailbox and loss of incoming messages.")
    with patch("backend.dkim_verifier.DKIMVerifier.verify", return_value={"status": "unavailable"}), patch("backend.email_authentication.EmailAuthenticationVerifier._arc", return_value={"status": "unavailable"}):
        result = AnalysisOrchestrator(ip_provider=OfflineIPs(), domain_provider=OfflineDomains()).analyze(msg.as_bytes())
    assert result.parsed["content_model"]["available"]
    assert result.risk_score >= 35
