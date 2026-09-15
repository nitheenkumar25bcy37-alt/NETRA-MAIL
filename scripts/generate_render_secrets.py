"""Generate one-time values for the NETRA Render Blueprint prompts."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def main() -> None:
    extension_token = secrets.token_urlsafe(48)
    dashboard_token = secrets.token_urlsafe(48)
    identities = [
        {
            "subject": "gmail-extension",
            "role": "submitter",
            "key_sha256": token_digest(extension_token),
        },
        {
            "subject": "soc-dashboard",
            "role": "admin",
            "key_sha256": token_digest(dashboard_token),
        },
    ]
    evidence_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")

    print("NETRA_API_IDENTITIES=" + json.dumps(identities, separators=(",", ":")))
    print("NETRA_EVIDENCE_KEYS_JSON=" + json.dumps({"render-v1": evidence_key}))
    print("EXTENSION_ACCESS_KEY=" + extension_token)
    print("DASHBOARD_ACCESS_KEY=" + dashboard_token)


if __name__ == "__main__":
    main()
