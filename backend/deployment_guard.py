"""Fail closed on missing minimum hosted configuration. No secret output."""
import os
import re
from urllib.parse import urlsplit

from backend.access_control import AccessPolicy
from backend.protected_storage import ProtectedStorage


def validate_hosted_environment():
    if os.getenv("NETRA_DEPLOYMENT_MODE", "local") != "hosted":
        return
    policy = AccessPolicy(os.getenv("NETRA_API_IDENTITIES", "[]"))
    if not policy.identities:
        raise ValueError("Hosted mode requires configured API identities")
    if not any(principal.role == "admin" for _, principal in policy.identities):
        raise ValueError("Hosted mode requires an administrator identity")
    if os.getenv("NETRA_REQUIRE_EVIDENCE_ENCRYPTION", "").lower() not in {"true", "1", "yes"}:
        raise ValueError("Hosted mode requires evidence encryption")
    ProtectedStorage(None, os.getenv("NETRA_EVIDENCE_STORAGE_DIR", "."))
    origin = urlsplit(os.getenv("NETRA_PUBLIC_ORIGIN", ""))
    if origin.scheme != "https" or not origin.hostname or origin.username or origin.password or origin.query or origin.fragment or origin.path not in {"", "/"}:
        raise ValueError("Hosted mode requires an HTTPS public origin")
    extension_id = os.getenv("NETRA_EXTENSION_ID", "")
    if not re.fullmatch(r"[a-p]{32}", extension_id):
        raise ValueError("Hosted mode requires the installed extension ID")
    if not os.getenv("NETRA_ALLOWED_ORIGINS", "").strip() or "*" in os.getenv("NETRA_ALLOWED_ORIGINS", ""):
        raise ValueError("Hosted mode requires explicit browser origins")
    for name in ("NETRA_DATABASE_PATH", "NETRA_EVIDENCE_STORAGE_DIR"):
        if not os.getenv(name):
            raise ValueError("Hosted mode requires explicit persistent storage paths")


if __name__ == "__main__":
    validate_hosted_environment()
    print("Configuration checks passed; deployment and external security validation remain separate.")
