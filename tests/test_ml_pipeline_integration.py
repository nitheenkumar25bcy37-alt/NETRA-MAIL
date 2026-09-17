from email.message import EmailMessage

from backend.services.analysis_orchestrator import AnalysisOrchestrator
from backend.url_analyzer import URLAnalyzer


def _email(subject, body):
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = "sender@example.test"
    message["To"] = "recipient@example.test"
    message.set_content(body)
    return message.as_bytes()


def test_url_ml_is_available_but_cannot_create_a_verdict_alone():
    safe = URLAnalyzer.analyze_url("https://github.com/python/cpython")
    assert safe["ml_analysis"]["available"]
    assert not safe["ml_analysis"]["used_in_score"]
    assert safe["risk_score"] < 30


def test_url_ml_supports_independent_structural_evidence_on_unseen_domain():
    url = "https://netra-judge-93817.top/account/login/verify?password=confirm"
    result = URLAnalyzer.analyze_url(url)
    assert result["ml_analysis"]["available"]
    assert result["risk_score"] >= 30
    assert result["suspicious_keywords"]


def test_structural_detection_takes_priority_over_email_ml():
    orchestrator = AnalysisOrchestrator()
    orchestrator.domain_provider.inspect = lambda *args, **kwargs: {"findings": []}
    phishing = orchestrator.analyze(_email(
        "Urgent account suspension",
        "Login immediately and verify your password at https://netra-judge-93817.top/account/login/verify",
    ))
    assert phishing.parsed["ml_analysis"]["available"]
    assert not phishing.parsed["ml_analysis"]["used_in_decision"]
    assert phishing.risk_score >= 35
    assert any(item.rule == "contextual_social_engineering" for item in phishing.findings)

    safe = orchestrator.analyze(_email(
        "Project meeting",
        "The architecture review is tomorrow at 10 AM in conference room two.",
    ))
    assert safe.parsed["ml_analysis"]["available"]
    assert not safe.parsed["ml_analysis"]["used_in_decision"]
    assert not any(item.rule == "corroborated_email_ml" for item in safe.findings)
