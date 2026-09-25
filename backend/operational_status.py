"""Local configuration inventory. Never returns credentials or private paths."""
import json
import os
import subprocess


def status():
    enabled = os.getenv("NETRA_URL_REPUTATION_ENABLED", "false").lower() in {"1", "true", "yes"}
    keys = {"google_safe_browsing": bool(os.getenv("NETRA_GOOGLE_SAFE_BROWSING_KEY")),
            "urlhaus": bool(os.getenv("NETRA_URLHAUS_AUTH_KEY"))}
    image = os.getenv("NETRA_INSPECTION_IMAGE", "netra-inspector:4.6.0")
    worker = "unavailable"
    try:
        result = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True, timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode == 0:
            worker = "image_installed_runtime_acceptance_pending"
    except (OSError, subprocess.SubprocessError):
        pass
    return {"version": "4.4.0", "inspection_worker": worker,
        "url_expansion_enabled": os.getenv("NETRA_EXPAND_SHORT_URLS", "0").lower() in {"1", "true", "yes"},
        "reputation": {"enabled": enabled, "credentials_present": keys,
            "activation": "configured_live_acceptance_pending" if enabled and any(keys.values()) else "external_setup_required"},
        "gmail_authentication": "trusted_only_after_server_side_provider_fetch",
        "uploaded_authentication_headers": "untrusted",
        "release": "implementation_candidate_acceptance_deferred"}


if __name__ == "__main__":
    print(json.dumps(status(), indent=2))
