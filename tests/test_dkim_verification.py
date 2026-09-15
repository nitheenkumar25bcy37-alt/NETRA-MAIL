import base64

import dkim
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.dkim_verifier import DKIMVerifier


@pytest.fixture(scope="module")
def signed_message():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    raw = b"From: alice@example.com\r\nTo: bob@example.net\r\nSubject: Meeting\r\n\r\nMeeting tomorrow.\r\n"
    signature = dkim.sign(raw, b"test", b"example.com", private, include_headers=[b"from", b"to", b"subject"])
    return signature + raw, b"v=DKIM1; k=rsa; p=" + base64.b64encode(public)


def test_actual_signature_passes_and_modified_body_fails(signed_message):
    message, key = signed_message
    verifier = DKIMVerifier(dnsfunc=lambda name, timeout: key)
    assert verifier.verify(message)["status"] == "pass"
    assert verifier.verify(message.replace(b"Meeting tomorrow.", b"Transfer funds now."))["status"] == "fail"


def test_reconstructed_message_is_not_verified(signed_message):
    message, key = signed_message
    assert DKIMVerifier().verify(message, "api")["status"] == "unavailable"


def test_dns_outage_is_unavailable_not_forgery(signed_message):
    def unavailable(name, timeout):
        raise TimeoutError()
    assert DKIMVerifier(unavailable).verify(signed_message[0])["status"] == "unavailable"


def test_unsigned_email_has_explicit_status():
    assert DKIMVerifier().verify(b"From: alice@example.com\r\n\r\nHello")["status"] == "unsigned"
