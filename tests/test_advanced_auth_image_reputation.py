import io
import pytest
from PIL import Image

from backend.email_authentication import EmailAuthenticationVerifier
from backend.image_analyzer import analyze_image
from backend.intelligence.reputation_provider import URLReputationProvider


def test_trusted_spf_and_verified_dkim_form_dmarc(monkeypatch):
    monkeypatch.setattr("backend.email_authentication.DKIMVerifier.verify", lambda *a: {
        "status": "pass", "signatures": [{"status": "pass", "domain": "example.com"}], "limitations": []})
    monkeypatch.setattr(EmailAuthenticationVerifier, "_arc", lambda *a: {"status": "none"})
    raw = (b"From: Person <p@example.com>\r\nAuthentication-Results: mx.google.com; "
           b"spf=pass smtp.mailfrom=bounce@example.com; dmarc=pass header.from=example.com\r\n\r\nhello")
    result = EmailAuthenticationVerifier(trusted_authserv_ids="mx.google.com").verify(
        raw, trusted_receiver="gmail"
    )
    assert result["spf"]["status"] == "pass"
    assert result["dmarc"]["status"] == "pass"


def test_untrusted_authentication_results_never_supply_spf(monkeypatch):
    monkeypatch.setattr("backend.email_authentication.DKIMVerifier.verify", lambda *a: {"status": "unsigned", "signatures": [], "limitations": []})
    monkeypatch.setattr(EmailAuthenticationVerifier, "_arc", lambda *a: {"status": "none"})
    raw = b"From: p@example.com\r\nAuthentication-Results: attacker.invalid; spf=pass smtp.mailfrom=example.com\r\n\r\nx"
    assert EmailAuthenticationVerifier(trusted_authserv_ids="mx.google.com").verify(raw)["spf"]["status"] == "unavailable"


def test_uploaded_eml_cannot_activate_configured_gmail_trust(monkeypatch):
    monkeypatch.setattr("backend.email_authentication.DKIMVerifier.verify", lambda *a: {
        "status": "unsigned", "signatures": [], "limitations": []})
    monkeypatch.setattr(EmailAuthenticationVerifier, "_arc", lambda *a: {"status": "none"})
    raw = (b"From: p@example.com\r\nAuthentication-Results: mx.google.com; "
           b"spf=pass smtp.mailfrom=example.com\r\n\r\nx")
    result = EmailAuthenticationVerifier(trusted_authserv_ids="mx.google.com").verify(raw)
    assert result["spf"]["status"] == "unavailable"
    assert result["trusted_authserv_ids"] == []
    assert result["delivery_source"] == "untrusted_upload"


def test_image_limits_and_valid_decode():
    output = io.BytesIO(); Image.new("RGB", (20, 20), "white").save(output, "PNG")
    result = analyze_image(output.getvalue(), "image/png")
    assert result["available"] is True
    assert result["qr_payloads"] == []
    assert analyze_image(b"bad", "image/png")["available"] is False


def test_qr_payload_is_decoded():
    import cv2
    matrix = cv2.QRCodeEncoder_create().encode("https://example.test/login")
    ok, encoded = cv2.imencode(".png", matrix)
    assert ok
    assert analyze_image(encoded.tobytes(), "image/png")["qr_payloads"] == ["https://example.test/login"]


def test_portable_ocr_extracts_image_text():
    from PIL import ImageDraw, ImageFont
    image = Image.new("RGB", (700, 140), "white")
    ImageDraw.Draw(image).text((20, 30), "URGENT LOGIN VERIFY ACCOUNT", fill="black", font=ImageFont.load_default(size=42))
    output = io.BytesIO(); image.save(output, "PNG")
    result = analyze_image(output.getvalue(), "image/png")
    assert result["ocr_available"] is True
    assert "LOGIN" in result["ocr_text"]


def test_direct_spf_context_is_bounded(monkeypatch):
    import spf
    def check2(**kwargs):
        assert kwargs["timeout"] == 2 and kwargs["querytime"] == 5
        return "pass", "sender permitted"
    monkeypatch.setattr(spf, "check2", check2)
    assert EmailAuthenticationVerifier.verify_spf_context("203.0.113.8", "bounce@example.com", "mail.example.com")["status"] == "pass"


class Response:
    status_code = 200
    content = b"{}"
    def raise_for_status(self): pass
    def json(self): return self.value
    def iter_content(self, size):
        yield self.content
    def close(self): pass


def test_reputation_exact_match_and_disabled_privacy():
    class Session:
        trust_env = True
        def __init__(self): self.calls = []
        def post(self, url, **kwargs):
            self.calls.append((url, kwargs)); response = Response()
            response.value = ({"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "https://bad.example/x"}}]}
                if "googleapis" in url else {"query_status": "no_results"})
            import json
            response.content = json.dumps(response.value).encode()
            return response
    session = Session()
    result = URLReputationProvider(session=session, enabled=True, google_key="test", urlhaus_key="test").lookup(["https://bad.example/x"])
    assert result["findings"][0]["severity"] == "critical"
    assert all(call[1]["allow_redirects"] is False for call in session.calls)
    assert all(call[1]["stream"] is True for call in session.calls)
    assert session.calls[-1][1]["headers"] == {"Auth-Key": "test"}
    disabled = Session(); assert URLReputationProvider(session=disabled, enabled=False).lookup(["https://bad.example"])["results"] == []
    assert disabled.calls == []
