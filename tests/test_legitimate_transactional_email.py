from email.message import EmailMessage

from backend.services.analysis_orchestrator import AnalysisOrchestrator
from backend.url_analyzer import URLAnalyzer


def test_visible_url_with_trailing_support_text_is_not_a_mismatch():
    result = URLAnalyzer.analyze_references([{
        "href": "https://equery.irctc.co.in",
        "visible_text": "https://equery.irctc.co.in or call us at 14646",
    }])
    assert not any(item["rule"] == "visible_href_mismatch" for item in result["findings"])
    assert result["urls"][0]["visible_host"] == "equery.irctc.co.in"


def test_google_redirect_wrapper_scores_the_embedded_destination_only():
    wrapped = (
        "https://www.google.com/url?"
        "q=https%3A%2F%2Fcontents.irctc.co.in%2Fen%2FREFUND%2520RULES.pdf"
        "&source=gmail&usg=example"
    )
    result = URLAnalyzer.analyze_url(wrapped)
    assert result["redirect_wrapper"] == "www.google.com"
    assert result["redirect_target"].startswith("https://contents.irctc.co.in/")
    assert result["risk_score"] < 30


def test_googleusercontent_is_recognized_as_google_infrastructure():
    result = URLAnalyzer.analyze_url("https://ci3.googleusercontent.com/mail-sig/example.png")
    assert not result["brand_impersonation"]
    assert result["risk_score"] < 30


def test_legitimate_ticket_confirmation_does_not_become_bec_or_phishing():
    message = EmailMessage()
    message["Subject"] = "Booking Confirmation on IRCTC, Train 12696"
    message["From"] = "ticketadmin@irctc.co.in"
    message["To"] = "passenger@example.test"
    message.set_content("Your railway ticket is confirmed.")
    message.add_alternative("""
        <p>This is a system generated ticket confirmation.</p>
        <p>Aadhaar authentication is mandatory for Tatkal tickets.</p>
        <p>Payment transaction reference: TEST-12345.</p>
        <p>Do not provide credit or debit card details to anyone.</p>
        <a href="https://equery.irctc.co.in">https://equery.irctc.co.in or call us at 14646</a>
        <a href="https://www.google.com/url?q=https%3A%2F%2Fcontents.irctc.co.in%2Fen%2FREFUND%2520RULES.pdf&amp;source=gmail">Refund rules</a>
        <img src="https://ci3.googleusercontent.com/mail-sig/example.png">
    """, subtype="html")
    orchestrator = AnalysisOrchestrator()
    orchestrator.domain_provider.inspect = lambda *args, **kwargs: {"findings": []}
    result = orchestrator.analyze(message.as_bytes(), "regression")
    rules = {item.rule for item in result.findings}
    assert result.risk_score < 35
    assert result.classification == "Legitimate or low risk"
    assert "payment_authority_combination" not in rules
    assert "visible_href_mismatch" not in rules
    assert "credential_request_with_suspicious_link" not in rules
