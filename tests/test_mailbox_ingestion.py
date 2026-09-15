import base64
import json
import pytest
from backend.mailbox_ingestion import fetch_original, bounded_response
from backend.mailbox_ingestion import validate_backend_origin


class Response:
    status_code = 200
    def __init__(self, content):
        self.content = content
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def iter_content(self, size):
        yield self.content


@pytest.mark.parametrize("provider", ["gmail", "microsoft"])
def test_original_mime_preserved_and_redirects_disabled(provider):
    raw = b"From: a@example.org\r\nSubject: Original\r\n\r\nExact bytes\r\n"
    class Session:
        def get(self, url, **kwargs):
            assert kwargs["allow_redirects"] is False
            assert kwargs["stream"] is True
            assert kwargs["headers"] == {"Authorization": "Bearer test-only"}
            assert "evil%2Fid" in url
            return Response(json.dumps({"raw": base64.urlsafe_b64encode(raw).decode()}).encode() if provider == "gmail" else raw)
    assert fetch_original(provider, "evil/id", "test-only", Session()) == raw


def test_redirect_and_oversize_rejected():
    response = Response(b"12345")
    with pytest.raises(ValueError, match="size"):
        bounded_response(response, 4)
    response.status_code = 302
    with pytest.raises(ValueError, match="302"):
        bounded_response(response, 10)


@pytest.mark.parametrize("origin", ["http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000", "https://netra.example"])
def test_local_and_https_backends_allowed(origin):
    validate_backend_origin(origin)


@pytest.mark.parametrize("origin", ["http://example.org", "http://127.0.0.1.evil.org", "https://user:pass@example.org", "http://localhost:8000/path"])
def test_unsafe_backend_rejected(origin):
    with pytest.raises(ValueError):
        validate_backend_origin(origin)
