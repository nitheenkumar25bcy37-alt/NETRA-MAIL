from backend.presentation import explain_analysis, explanation_lines
from backend.report_service import ReportService


def sample():
    return {"classification": "Phishing", "risk_score": 80, "confidence": .9, "findings": [{"severity": "high", "title": "Password request", "description": "Requests a password on an unrelated site", "evidence": {"credential_cues": ["verify password"]}}], "parsed": {"nlp_analysis": {"categories": {"credential_harvesting": ["verify password"]}}, "multilingual_analysis": {"language": "Tamil"}, "url_analysis": {"urls": [{"url": "https://example.invalid/login", "hostname": "example.invalid", "risk_score": 70, "risk_reasons": ["Brand impersonation"]}]}}}


def test_actual_text_and_url_evidence_without_changing_verdict():
    result = sample()
    view = explain_analysis(result)
    text = "\n".join(explanation_lines(view))
    assert "verify password" in text and "Brand impersonation" in text
    assert "Tamil" in text and "example.invalid" in text
    assert result["risk_score"] == view["risk_score"] == 80


def test_missing_checks_and_zero_confidence_do_not_claim_safety():
    view = explain_analysis({"risk_score": 0})
    assert "does not guarantee" in view["summary"]
    assert "No finding-based" in view["confidence_note"]
    assert "unavailable" in view["url_analysis"]["summary"]
    assert all("not an authentication failure" in item["interpretation"] for item in view["authentication"])


def test_authentication_pass_is_not_safe_intent():
    view = explain_analysis({"parsed": {"verified_authentication": {"dkim": {"status": "pass"}}}})
    assert "does not prove safe intent" in view["authentication"][1]["interpretation"]


def test_report_exports_explanations_and_escapes_untrusted_text():
    result = sample()
    result["findings"][0]["title"] = "<script>alert(1)</script>"
    result["explanation"] = explain_analysis(result)
    report = {"report_id": "test", "case_id": "case", "observed_evidence": {"emails": [result]}, "evidence_count": 0, "integrity_verified": False, "evidence_inventory": [], "limitations": [], "attribution_disclaimer": "Review required"}
    html = ReportService._render(report, "html").decode()
    assert "Brand impersonation" in html and "verify password" in html
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert ReportService._render(report, "pdf").startswith(b"%PDF")
