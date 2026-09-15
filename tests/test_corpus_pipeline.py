from pathlib import Path
import pytest
from evaluation.evaluate_v2 import OfflineDomains, OfflineIPs
from backend.services.analysis_orchestrator import AnalysisOrchestrator

CORPUS = Path(__file__).resolve().parents[1] / "evaluation" / "deterministic" / "emails"


@pytest.mark.parametrize("path", sorted(CORPUS.glob("*.eml")), ids=lambda path: path.name)
def test_every_corpus_message_produces_serializable_findings(path, monkeypatch):
    monkeypatch.setattr("backend.dkim_verifier.DKIMVerifier.verify", lambda *args: {"status": "unavailable", "limitations": []})
    result = AnalysisOrchestrator(ip_provider=OfflineIPs(), domain_provider=OfflineDomains()).analyze(path.read_bytes())
    assert 0 <= result.risk_score <= 100
    # Serialization catches raw attachment bytes leaking into API responses.
    assert result.model_dump_json()
    if path.name in {"08_executable_attachment.eml", "09_double_extension.eml", "14_mime_mismatch.eml"}:
        assert result.risk_score >= 75
    if path.name == "19_malformed_like.eml":
        assert result.risk_score < 25
