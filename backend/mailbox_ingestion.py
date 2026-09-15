"""Fetch one explicitly selected message and submit its original MIME bytes.

OAuth consent/token acquisition is performed by the deployment identity layer.
This module never lists mailboxes, sends mail, or stores provider tokens.
"""
import argparse
import base64
import json
import os
import time
from urllib.parse import quote, urlsplit

import requests

MAX_MESSAGE = 10 * 1024 * 1024


def bounded_response(response, limit):
    with response:
        if response.status_code != 200:
            raise ValueError("Remote service rejected request (HTTP %d)" % response.status_code)
        result = bytearray()
        deadline = time.monotonic() + 30
        for chunk in response.iter_content(65536):
            if time.monotonic() > deadline:
                raise ValueError("Remote response exceeded time budget")
            result.extend(chunk)
            if len(result) > limit:
                raise ValueError("Remote response exceeded size limit")
        return bytes(result)


def fetch_original(provider, message_id, token, session=None):
    if provider not in {"gmail", "microsoft"}:
        raise ValueError("Unsupported mailbox provider")
    if not message_id or len(message_id) > 2048 or not token or "\n" in token or "\r" in token:
        raise ValueError("Message ID and valid OAuth access token are required")
    identifier = quote(message_id, safe="")
    if provider == "gmail":
        url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/" + identifier + "?format=raw"
    else:
        url = "https://graph.microsoft.com/v1.0/me/messages/" + identifier + "/$value"
    owned = session is None
    session = session or requests.Session()
    if owned:
        session.trust_env = False
    try:
        content = bounded_response(session.get(url, headers={"Authorization": "Bearer " + token},
            timeout=(5, 10), allow_redirects=False, stream=True), MAX_MESSAGE * 2)
        if provider == "gmail":
            encoded = json.loads(content).get("raw")
            if not isinstance(encoded, str):
                raise ValueError("Provider did not return original MIME")
            content = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        if not content or len(content) > MAX_MESSAGE:
            raise ValueError("Original MIME is empty or oversized")
        return content
    finally:
        if owned:
            session.close()


def validate_backend_origin(backend_origin):
    url = urlsplit(backend_origin)
    local = url.hostname in {"localhost", "127.0.0.1", "::1"}
    if (url.scheme != "https" and not (local and url.scheme == "http")) or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}:
        raise ValueError("Use HTTPS or a loopback HTTP backend without a path")
    return local


def ingest_selected(provider, message_id, oauth_token, backend_origin, api_key):
    local = validate_backend_origin(backend_origin)
    if not api_key and not local:
        raise ValueError("A scoped NETRA API credential is required")
    with requests.Session() as session:
        session.trust_env = False
        result = bounded_response(session.post(backend_origin.rstrip("/") + "/api/v2/mailbox/analyze",
            headers={"X-NETRA-API-Key": api_key},
            json={"provider": provider, "message_id": message_id, "access_token": oauth_token},
            timeout=(5, 180), allow_redirects=False, stream=True), 5 * 1024 * 1024)
        return json.loads(result)


def main():
    parser = argparse.ArgumentParser(description="Analyze one authorized mailbox message using original MIME")
    parser.add_argument("--provider", choices=["gmail", "microsoft"], required=True)
    parser.add_argument("--message-id", required=True)
    args = parser.parse_args()
    result = ingest_selected(args.provider, args.message_id, os.environ["NETRA_MAILBOX_ACCESS_TOKEN"],
        os.environ["NETRA_PUBLIC_ORIGIN"], os.environ["NETRA_API_ACCESS_KEY"])
    print(json.dumps({key: result.get(key) for key in ("email_id", "risk_score", "classification")}))


if __name__ == "__main__":
    main()
