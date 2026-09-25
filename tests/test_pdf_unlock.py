import hashlib
import io
import json
from email.message import EmailMessage
from unittest.mock import patch

import pytest
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas

from backend.pdf_inspection import inspect_pdf
from backend.attachment_review import review_pdf, original_attachment
from backend.inspection_client import inspect_attachment


def pdf_fixture(text="Your monthly statement. No action is required.", pages=1, javascript=False):
    plain = io.BytesIO()
    document = canvas.Canvas(plain)
    for _ in range(pages):
        document.drawString(30, 750, text)
        document.linkURL("https://example.org/statement", (30, 710, 250, 730), relative=0)
        document.showPage()
    document.save()
    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(plain.getvalue())))
    if javascript:
        writer.add_js("app.alert('test only')")
    writer.encrypt("sample-secret-987", algorithm="AES-256")
    encrypted = io.BytesIO()
    writer.write(encrypted)
    return encrypted.getvalue()


@pytest.fixture
def fast_image(monkeypatch):
    monkeypatch.setattr("backend.image_analyzer.analyze_image", lambda *args: {
        "available": True, "ocr_available": True, "qr_available": True,
        "qr_payloads": [], "ocr_text": "", "limitations": []})


def test_decrypt_extract_and_link_without_echoing_password(fast_image):
    result = inspect_pdf(pdf_fixture(), "sample-secret-987")
    assert result["available"] and result["encrypted"]
    assert "monthly statement" in result["pages"][0]["text"]
    assert "https://example.org/statement" in result["pages"][0]["urls"]
    assert "sample-secret-987" not in json.dumps(result)


def test_wrong_password_and_malformed_pdf():
    assert inspect_pdf(pdf_fixture(), "incorrect")["error"] == "incorrect_password"
    assert inspect_pdf(b"%PDF-broken", "x")["available"] is False
    assert inspect_pdf(b"not a pdf", "x")["error"] == "not_pdf"


def test_page_limit_and_active_objects(fast_image):
    result = inspect_pdf(pdf_fixture(pages=6, javascript=True), "sample-secret-987")
    assert len(result["pages"]) == 5 and result["total_pages"] == 6
    assert "/JavaScript" in result["active_content"]
    assert any("first 5" in note for note in result["limitations"])


def test_review_no_plaintext_and_no_false_positive(fast_image):
    data = pdf_fixture()
    with patch("backend.attachment_review.inspect_attachment", lambda *a, **k: inspect_pdf(data, k["password"])):
        result = review_pdf(data, "sample-secret-987", "email", hashlib.sha256(data).hexdigest(), "analyst")
    assert result["status"] in {"limited", "no_threats_detected"}
    assert not result["pages"][0]["warnings"]
    assert "sample-secret-987" not in json.dumps(result)
    assert "monthly statement" not in json.dumps(result)
    assert "text" not in result["pages"][0]  # only check status is kept


def test_suspicious_request_and_url(fast_image):
    data = pdf_fixture("Send your password immediately to https://paypal.verify-account.xyz.com/login")
    with patch("backend.attachment_review.inspect_attachment", lambda *a, **k: inspect_pdf(data, k["password"])):
        result = review_pdf(data, "sample-secret-987", "email", "f" * 64, "analyst")
    assert result["status"] == "suspicious"
    assert any("sensitive" in message for message in result["pages"][0]["warnings"])


def test_failure_does_not_claim_safe():
    with patch("backend.attachment_review.inspect_attachment", return_value={"available": False, "error": "incorrect_password"}):
        result = review_pdf(b"", "wrong", "email", "f" * 64, "analyst")
    assert result["status"] == "not_inspected"
    assert "password did not unlock" in result["summary"]


def test_subprocess_real_wrong_password(monkeypatch):
    monkeypatch.setenv("NETRA_INSPECTION_MODE", "portable")
    result = inspect_attachment(pdf_fixture(), "document.pdf", "application/pdf", password="incorrect")
    assert result == {"available": False, "error": "incorrect_password"}


def stored_email(tmp_path):
    from backend.database import ForensicLedgerDB
    from backend.evidence_service import EvidenceService
    db = ForensicLedgerDB(str(tmp_path / "reviews.sqlite"))
    service = EvidenceService(db, str(tmp_path / "evidence"))
    data = pdf_fixture()
    digest = hashlib.sha256(data).hexdigest()
    message = EmailMessage()
    message["From"] = "sender@example.org"
    message.set_content("Statement attached")
    message.add_attachment(data, maintype="application", subtype="pdf", filename="statement.pdf")
    raw = message.as_bytes()
    reference = service.register(raw, "original.eml", "message/rfc822", "raw_eml", "test", "email")
    result = {"email_id": "email", "evidence_reference": reference,
              "evidence": {"sha256": hashlib.sha256(raw).hexdigest()},
              "parsed": {"attachment_analysis": {"attachments": [{"sha256": digest}]}}}
    db.record_v2_analysis("email", result["evidence"]["sha256"], result)
    return db, service, result, data, digest


def test_original_bound_to_email_and_hash(tmp_path):
    _, service, result, data, digest = stored_email(tmp_path)
    assert original_attachment(result, service, "email", digest) == data
    with pytest.raises(ValueError):
        original_attachment(result, service, "someone-else", digest)
    with pytest.raises(ValueError):
        original_attachment(result, service, "email", "f" * 64)
    result["evidence"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="original_integrity_failed"):
        original_attachment(result, service, "email", digest)


def test_review_in_html_and_pdf_exports():
    from backend.report_service import ReportService
    from backend.presentation import explain_analysis
    report = {"report_id": "report", "case_id": "case", "evidence_count": 0,
              "integrity_verified": False, "limitations": [], "attribution_disclaimer": "No human attribution",
              "observed_evidence": {"emails": [{"email_id": "email", "explanation": explain_analysis({}),
                  "attachment_reviews": [{"summary": "PDF REVIEW TEST", "attachment_sha256": "a" * 64,
                       "pages": [], "warnings": ["Active content found"], "limitations": ["Not executed"]}]}]}}
    assert b"PDF REVIEW TEST" in ReportService._render(report, "html")
    content = ReportService._render(report, "pdf")
    text = " ".join(page.extract_text() for page in PdfReader(io.BytesIO(content)).pages)
    assert "PDF REVIEW TEST" in text and "Active content found" in text


def test_endpoint_consent_authorization_and_append_only(tmp_path, monkeypatch, fast_image):
    import backend.main as main
    from backend.access_control import AccessPolicy
    from fastapi.testclient import TestClient
    db, service, original, data, digest = stored_email(tmp_path)
    monkeypatch.setattr(main, "db", db)
    monkeypatch.setattr(main, "evidence_service", service)
    monkeypatch.setattr(main, "access_policy", AccessPolicy(json.dumps([
        {"subject": role, "role": role, "key_sha256": hashlib.sha256(role.encode()).hexdigest()}
        for role in ["analyst", "auditor", "submitter"]])))
    monkeypatch.setattr("backend.attachment_review.inspect_attachment", lambda *a, **k: inspect_pdf(data, k["password"]))
    client = TestClient(main.app)
    url = f"/api/v2/emails/email/attachments/{digest}/unlock"
    body = {"password": "sample-secret-987", "consent": True}
    assert client.post(url, json=body).status_code == 401
    for role in ("auditor", "submitter"):
        assert client.post(url, json=body, headers={"X-NETRA-API-Key": role}).status_code == 403
    headers = {"X-NETRA-API-Key": "analyst"}
    assert client.post(url, json={**body, "consent": False}, headers=headers).status_code == 400
    assert client.post(url, json={**body, "password": "x" * 257}, headers=headers).status_code == 400
    assert client.post(url.replace(digest, "e" * 64), json=body, headers=headers).status_code == 404
    response = client.post(url, json=body, headers=headers)
    assert response.status_code == 200, response.text
    assert "sample-secret-987" not in response.text
    assert db.get_v2_analysis("email") == original
    assert len(db.list_attachment_reviews("email")) == 1
    retry = client.post(url, json={**body, "password": "wrong"}, headers=headers)
    assert retry.json()["status"] == "not_inspected"
    assert len(db.list_attachment_reviews("email")) == 2
    assert "sample-secret-987" not in (tmp_path / "reviews.sqlite").read_bytes().decode(errors="ignore")


def test_remote_plain_http_password_submission_is_rejected():
    from dashboard.api_client import APIClient
    with patch("dashboard.api_client.requests.request") as send:
        with pytest.raises(ValueError):
            APIClient("http://remote.example").unlock_pdf("email", "a" * 64, "secret")
        send.assert_not_called()


def test_unlock_form_consent_and_clearing():
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_string('''
import streamlit as st
from dashboard.attachment_review_ui import unlock_form
class Client:
    def unlock_pdf(self, email_id, digest, password):
        st.session_state["called"] = password == "document-password"
if not st.session_state.get("called"):
    unlock_form(Client(), "email", "a" * 64, "statement.pdf")
''', default_timeout=15).run()
    assert not app.exception
    app.text_input[0].set_value("document-password")
    next(button for button in app.button if button.label == "Unlock and analyse").click().run()
    assert app.warning and "called" not in app.session_state
    app.text_input[0].set_value("document-password")
    app.checkbox[0].check()
    next(button for button in app.button if button.label == "Unlock and analyse").click().run()
    assert not app.exception
    assert app.session_state["called"] is True
    assert not app.text_input
