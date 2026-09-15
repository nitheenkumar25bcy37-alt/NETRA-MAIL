"""Single-organization API identities. Tokens are configured as SHA-256 digests."""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str
    expires_at: datetime | None = None


class AccessPolicy:
    def __init__(self, encoded: str = "[]"):
        records = json.loads(encoded)
        if not isinstance(records, list):
            raise ValueError("NETRA_API_IDENTITIES must be a JSON list")
        self.enabled = bool(records)
        self.identities = []
        seen = set()
        seen_digests = set()
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("disabled", False), bool):
                raise ValueError("Invalid API identity record")
            subject = record.get("subject", "")
            role = record.get("role", "")
            digest = record.get("key_sha256", "").lower()
            if not subject or len(subject) > 100 or role not in {"admin", "analyst", "auditor", "submitter"}:
                raise ValueError("Invalid API identity subject or role")
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("API identity requires a SHA-256 token digest")
            if subject in seen or digest in seen_digests:
                raise ValueError("Duplicate API identity")
            seen.add(subject)
            seen_digests.add(digest)
            expires = datetime.fromisoformat(record["expires_at"]) if record.get("expires_at") else None
            if expires is not None and expires.tzinfo is None:
                raise ValueError("Credential expiry requires a timezone")
            if record.get("disabled") is True:
                continue
            self.identities.append((digest, Principal(subject, role, expires)))

    def authenticate(self, token: str) -> Principal | None:
        if not token or len(token) > 512:
            return None
        candidate = hashlib.sha256(token.encode("utf-8")).hexdigest()
        for digest, principal in self.identities:
            if secrets.compare_digest(candidate, digest):
                if principal.expires_at and datetime.now(timezone.utc) >= principal.expires_at:
                    return None
                return principal
        return None

    @staticmethod
    def allowed(principal: Principal, method: str, path: str) -> bool:
        if principal.role == "admin":
            return True
        if path == "/api/v2/me" and method == "GET":
            return True
        if principal.role == "submitter":
            if method == "POST":
                return path in {"/api/v2/emails/upload", "/api/v2/emails/analyze", "/api/v2/mailbox/analyze"}
            parts = path.strip("/").split("/")
            return method == "GET" and len(parts) in {4, 5} and parts[:3] == ["api", "v2", "emails"] and (len(parts) == 4 or parts[4] in {"findings", "trace"})
        # Verification appends custody events despite its legacy GET route.
        if principal.role == "auditor":
            return method in {"GET", "HEAD", "OPTIONS"} and not path.endswith("/verify")
        return method != "DELETE"
