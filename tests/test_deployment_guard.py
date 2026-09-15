import base64
import json
import pytest
from backend.deployment_guard import validate_hosted_environment


def test_hosted_configuration_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv("NETRA_DEPLOYMENT_MODE", "hosted")
    with pytest.raises(ValueError, match="identities"):
        validate_hosted_environment()
    monkeypatch.setenv("NETRA_API_IDENTITIES", json.dumps([{"subject": "admin", "role": "admin", "key_sha256": "a" * 64}]))
    with pytest.raises(ValueError, match="encryption"):
        validate_hosted_environment()
    monkeypatch.setenv("NETRA_REQUIRE_EVIDENCE_ENCRYPTION", "true")
    monkeypatch.setenv("NETRA_EVIDENCE_KEYS_JSON", json.dumps({"k1": base64.b64encode(b"x" * 32).decode()}))
    monkeypatch.setenv("NETRA_EVIDENCE_ACTIVE_KEY", "k1")
    monkeypatch.setenv("NETRA_PUBLIC_ORIGIN", "https://netra.example.org")
    monkeypatch.setenv("NETRA_EXTENSION_ID", "a" * 32)
    monkeypatch.setenv("NETRA_ALLOWED_ORIGINS", "https://netra.example.org")
    monkeypatch.setenv("NETRA_DATABASE_PATH", str(tmp_path / "db.sqlite"))
    monkeypatch.setenv("NETRA_EVIDENCE_STORAGE_DIR", str(tmp_path))
    validate_hosted_environment()
    monkeypatch.setenv("NETRA_ALLOWED_ORIGINS", "*")
    with pytest.raises(ValueError, match="origins"):
        validate_hosted_environment()
