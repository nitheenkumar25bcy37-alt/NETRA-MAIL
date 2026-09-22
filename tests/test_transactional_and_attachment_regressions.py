import io
from email.message import EmailMessage
from unittest.mock import patch

import cv2
from PIL import Image
import pytest

from backend.inspection_client import inspect_attachment
from backend.parser import ForensicEmailParser
from backend.presentation import explain_analysis
from backend.services.analysis_orchestrator import AnalysisOrchestrator
from backend.services.risk_engine import RiskEngine


def _png_qr(target):
    matrix = cv2.QRCodeEncoder_create().encode(target)
    image = Image.fromarray(matrix).resize((280, 280), Image.Resampling.NEAREST)
    output = io.BytesIO()
    image.save(output, "PNG")
    return output.getvalue()


def test_background_resources_are_not_treated_as_clickable_links():
    message = EmailMessage()
    message["Subject"] = "Account statement"
    message["From"] = "statements@example.com"
    message.set_content("Your monthly statement is ready.")
    message.add_alternative("""
      <p>Your monthly statement is ready.</p>
      <img src="https://pixel.tracker.invalid/login?account=123&redirect=1">
      <a href="https://example.com/statements">Open statement</a>
    """, subtype="html")
    parsed = ForensicEmailParser().parse_eml_bytes(message.as_bytes())
    assert "https://example.com/statements" in parsed["urls"]
    assert not any("pixel.tracker.invalid" in value for value in parsed["urls"])


def test_lexical_nouns_do_not_add_risk_in_authenticated_transactional_context():
    result = RiskEngine.evaluate([], {"categories": {
        "credential_harvesting": ["password"],
        "financial_fraud": ["transactions"],
    }, "trusted_transactional_context": True})
    assert result["risk_score"] == 0
    assert result["classification"] == "Legitimate or low risk"


def test_direct_link_deception_reaches_review_threshold():
    result = RiskEngine.evaluate([{
        "category": "URL", "rule": "visible_href_mismatch", "severity": "high",
        "confidence": 0.94, "title": "Visible destination differs",
    }])
    assert result["risk_score"] >= 50
    assert result["classification"] == "Phishing"


def test_explained_first_party_redirect_does_not_trigger_deception_floor():
    result = RiskEngine.evaluate([{
        "category": "URL", "rule": "visible_href_mismatch", "severity": "info",
        "confidence": 0.94, "title": "Authenticated first-party campaign redirect",
    }])
    assert result["risk_score"] == 0
    assert result["classification"] == "Legitimate or low risk"


def test_moderate_model_probability_does_not_force_transactional_review(monkeypatch):
    message = EmailMessage()
    message["Subject"] = "Kindly validate your email ID in our records"
    message["From"] = "alerts@example-bank.test"
    message["To"] = "customer@example.test"
    message["Authentication-Results"] = "mx.google.com; spf=pass smtp.mailfrom=example-bank.test; dmarc=pass header.from=example-bank.test"
    message.set_content("We are validating the email ID in our records. Select correct or not correct.")
    monkeypatch.setattr("backend.services.analysis_orchestrator.LocalMLClassifier.predict", lambda text: {
        "available": True, "calibration_status": "platt_scaling",
        "phishing_probability": 0.61, "classification": "PHISHING",
        "limitations": [],
    })
    orchestrator = AnalysisOrchestrator()
    orchestrator.domain_provider.inspect = lambda *args, **kwargs: {"findings": []}
    with patch("backend.email_authentication.DKIMVerifier.verify", return_value={"status": "unsigned", "signatures": [], "limitations": []}), \
         patch("backend.email_authentication.EmailAuthenticationVerifier._arc", return_value={"status": "none", "source": "test", "chain": []}):
        result = orchestrator.analyze(message.as_bytes(), "eml", trusted_receiver="gmail")
    rules = {item.rule for item in result.findings}
    assert result.risk_score < 35
    assert result.classification == "Legitimate or low risk"
    assert "calibrated_ml_observation" in rules
    assert "calibrated_ml_review" not in rules


@pytest.mark.parametrize("subject,sender,body,link,attachment", [
    ("Report: Contract Note", "noreply@groww.in",
     "Your successful trades are in the attached password-protected contract note. Use your PAN in capital letters to view it.",
     "https://groww.in/help", True),
    ("Kindly validate your email ID in HDFC Bank records", "HDFC Bank InstaAlerts <alerts@hdfcbank.bank.in>",
     "We are validating the email ID mapped to your customer ID. Select My Email ID is Correct or Not Correct.",
     "https://hdfcbank.bank.in/profile", False),
    ("Trades executed at NSE", "nse-direct@nse.co.in",
     "Information about your transactions is attached. The PDF password is your PAN number in upper case.",
     "https://www.sebi.gov.in/legal/circulars/investor-protection.html", True),
    ("Your SBI monthly statement", "statements@sbi.example",
     "Your password-protected monthly statement is attached. Visit the official portal for account support.",
     "https://sbi.example/support", True),
])
def test_authenticated_transactional_mail_is_not_flagged_by_nouns_or_resources(
        monkeypatch, subject, sender, body, link, attachment):
    domain = sender.rsplit("@", 1)[-1].rstrip(">")
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = "customer@example.test"
    message["Authentication-Results"] = f"mx.google.com; spf=pass smtp.mailfrom={domain}; dmarc=pass header.from={domain}"
    message.set_content(body)
    message.add_alternative(
        f'<p>{body}</p><a href="{link}">Official information</a>'
        '<img src="https://tracking-cdn.invalid/pixel/login?account=123&redirect=1">',
        subtype="html",
    )
    if attachment:
        message.add_attachment(b"%PDF-1.4\n%%EOF", maintype="application", subtype="pdf", filename="statement.pdf")
    monkeypatch.setenv("NETRA_INSPECTION_MODE", "portable")
    orchestrator = AnalysisOrchestrator()
    orchestrator.domain_provider.inspect = lambda *args, **kwargs: {"findings": []}
    with patch("backend.email_authentication.DKIMVerifier.verify", return_value={"status": "unsigned", "signatures": [], "limitations": []}), \
         patch("backend.email_authentication.EmailAuthenticationVerifier._arc", return_value={"status": "none", "source": "test", "chain": []}):
        result = orchestrator.analyze(message.as_bytes(), "eml", trusted_receiver="gmail")
    assert result.risk_score < 35
    assert result.classification == "Legitimate or low risk"
    assert not any("tracking-cdn.invalid" in item.get("href", "") for item in result.parsed["url_analysis"]["urls"])


def test_portable_worker_decodes_qr_and_static_attachment(monkeypatch):
    target = "https://credential-lure.invalid/login"
    monkeypatch.setenv("NETRA_INSPECTION_MODE", "portable")
    result = inspect_attachment(_png_qr(target), "qr.png", "image/png", timeout=35)
    assert result["available"] is True
    assert result["inspection_mode"] == "portable_subprocess"
    assert target in result["image_analysis"]["qr_payloads"]
    assert target in result["embedded_urls"]
    assert result["static_analysis"]["image_analysis"]["ocr_available"] is True


def test_attachment_explanation_states_qr_ocr_and_inspection_status():
    view = explain_analysis({"risk_score": 0, "classification": "Legitimate or low risk", "parsed": {
        "attachment_analysis": {"attachments": [{
            "filename": "qr.png", "content_type": "image/png", "size_bytes": 1200,
            "score": 25, "risk_level": "MEDIUM", "analysis_skipped": False,
            "reasons": ["Image contains a QR code; decoded targets were inspected as URLs when applicable."],
            "image_analysis": {"qr_payloads": ["https://example.test"], "ocr_available": True,
                               "ocr_text_present": True, "limitations": []},
        }]},
    }, "findings": [], "limitations": []})
    item = view["attachment_analysis"]["attachments"][0]
    assert item["status"] == "Static content inspection completed"
    assert item["qr_payloads"] == ["https://example.test"]
    assert item["ocr_text_present"] is True


def test_extension_accepts_attachment_only_open_message():
    source = open("extension/content.js", encoding="utf-8").read()
    assert "!sender ||\n        !body" not in source
    assert "visible sender and subject" in source


def test_authenticated_sbi_campaign_links_do_not_become_phishing(monkeypatch):
    message = EmailMessage()
    message["Subject"] = "Your card, your rules: Customize your transaction limits on YONO SBI"
    message["From"] = "SBI <sbi@communications.sbi.co.in>"
    message["To"] = "customer@example.test"
    message["Authentication-Results"] = (
        "mx.google.com; spf=pass smtp.mailfrom=communications.sbi.co.in; "
        "dmarc=pass header.from=communications.sbi.co.in"
    )
    message.set_content(
        "Manage access for transactions. For help visit the SBI website. "
        "SBI never asks for your password or OTP. Act immediately if your card is lost."
    )
    message.add_alternative(
        '<p>Manage access for transactions. SBI never asks for your password or OTP. '
        'Act immediately if your card is lost.</p>'
        '<a href="https://deliveryalerts.sbi.co.in/campaign?id=123">https://play.google.com/store/apps/details?id=com.sbi.lotusintouch</a>'
        '<a href="https://deliveryalerts.sbi.co.in/campaign?id=456">https://apps.apple.com/in/app/yono-sbi/id123</a>'
        '<a href="https://onlinesbi.sbi.bank.in/">Online SBI</a>',
        subtype="html",
    )
    monkeypatch.setattr("backend.services.analysis_orchestrator.LocalMLClassifier.predict", lambda text: {
        "available": True, "calibration_status": "platt_scaling",
        "phishing_probability": 0.81, "classification": "PHISHING", "limitations": [],
    })
    orchestrator = AnalysisOrchestrator()
    orchestrator.domain_provider.inspect = lambda *args, **kwargs: {"findings": []}
    with patch("backend.email_authentication.DKIMVerifier.verify", return_value={"status": "unsigned", "signatures": [], "limitations": []}), \
         patch("backend.email_authentication.EmailAuthenticationVerifier._arc", return_value={"status": "none", "source": "test", "chain": []}):
        result = orchestrator.analyze(message.as_bytes(), "eml", trusted_receiver="gmail")
    assert result.risk_score < 35
    assert result.classification == "Legitimate or low risk"
    assert not any(
        item.rule == "visible_href_mismatch" and item.severity != "info"
        for item in result.findings
    )
    online_sbi = next(
        item for item in result.parsed["url_analysis"]["urls"]
        if item.get("hostname") == "onlinesbi.sbi.bank.in"
    )
    assert online_sbi["registered_domain"] == "sbi.bank.in"
    assert "SBI" not in online_sbi["brand_impersonation"]


def test_authenticated_sender_does_not_hide_unrelated_deceptive_domain(monkeypatch):
    message = EmailMessage()
    message["Subject"] = "SBI account notice"
    message["From"] = "SBI <sbi@communications.sbi.co.in>"
    message["Authentication-Results"] = (
        "mx.google.com; spf=pass smtp.mailfrom=communications.sbi.co.in; "
        "dmarc=pass header.from=communications.sbi.co.in"
    )
    message.set_content("Review your account.")
    message.add_alternative(
        '<a href="https://sbi-login.attacker.example/verify">https://onlinesbi.sbi.bank.in/</a>',
        subtype="html",
    )
    orchestrator = AnalysisOrchestrator()
    orchestrator.domain_provider.inspect = lambda *args, **kwargs: {"findings": []}
    with patch("backend.email_authentication.DKIMVerifier.verify", return_value={"status": "unsigned", "signatures": [], "limitations": []}), \
         patch("backend.email_authentication.EmailAuthenticationVerifier._arc", return_value={"status": "none", "source": "test", "chain": []}):
        result = orchestrator.analyze(message.as_bytes(), "eml", trusted_receiver="gmail")
    assert result.risk_score >= 50
    assert any(
        item.rule == "visible_href_mismatch" and item.severity == "high"
        for item in result.findings
    )
