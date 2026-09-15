import base64
import json
import os

import pytest

from backend.audit_context import actor
from backend.database import ForensicLedgerDB
from backend.evidence_service import EvidenceService
from backend.protected_storage import ProtectedStorage, StorageIntegrityError, StorageKeyUnavailable
from backend.report_service import ReportService


@pytest.fixture
def encrypted_service(tmp_path, monkeypatch):
    keys = {"first": base64.b64encode(os.urandom(32)).decode()}
    monkeypatch.setenv("NETRA_EVIDENCE_KEYS_JSON", json.dumps(keys))
    monkeypatch.setenv("NETRA_EVIDENCE_ACTIVE_KEY", "first")
    db = ForensicLedgerDB(str(tmp_path / "ledger.db"))
    service = EvidenceService(db, str(tmp_path / "files"))
    return service, keys


def test_evidence_is_encrypted_but_original_hash_still_verifies(encrypted_service):
    service, _ = encrypted_service
    original = b"Subject: Private financial evidence\r\n\r\nConfidential content"
    item = service.register(original, "message.eml", "message/rfc822")
    stored = (service.storage_dir / item["storage_reference"]).read_bytes()
    assert original not in stored
    assert stored.startswith(ProtectedStorage.MAGIC)
    assert service.verify(item["evidence_id"])["match"]
    assert service.get(item["evidence_id"])["storage_protection"] == "AES-256-GCM"


def test_wrong_path_cannot_authenticate_ciphertext(encrypted_service):
    service, _ = encrypted_service
    service.storage.write("a.bin", b"same")
    service.storage.write("b.bin", b"same")
    (service.storage_dir / "b.bin").write_bytes((service.storage_dir / "a.bin").read_bytes())
    with pytest.raises(StorageIntegrityError):
        service.storage.read("b.bin", 100)


def test_ciphertext_tampering_is_failure_and_missing_key_is_unavailable(encrypted_service):
    service, _ = encrypted_service
    item = service.register(b"private", "message.eml", "message/rfc822")
    service.storage.keys.clear()
    assert service.verify(item["evidence_id"])["integrity_status"] == "unavailable"
    service.storage.keys["first"] = os.urandom(32)
    assert service.verify(item["evidence_id"])["integrity_status"] == "failed"


def test_key_rotation_keeps_old_objects_readable(encrypted_service):
    service, keys = encrypted_service
    service.storage.write("old.bin", b"old evidence")
    keys["second"] = base64.b64encode(os.urandom(32)).decode()
    rotated = ProtectedStorage(service.db, service.storage_dir, keys=keys, active_key="second")
    rotated.write("new.bin", b"new evidence")
    assert rotated.read("old.bin", 100) == b"old evidence"
    assert rotated.read("new.bin", 100) == b"new evidence"
    assert service.db.get_storage_blob("old.bin")["key_id"] == "first"
    assert service.db.get_storage_blob("new.bin")["key_id"] == "second"


def test_storage_write_cannot_overwrite_original(encrypted_service):
    service, _ = encrypted_service
    service.storage.write("original.bin", b"original")
    with pytest.raises(FileExistsError):
        service.storage.write("original.bin", b"replacement")
    assert service.storage.read("original.bin", 100) == b"original"


def test_required_encryption_without_key_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("NETRA_REQUIRE_EVIDENCE_ENCRYPTION", "true")
    db = ForensicLedgerDB(str(tmp_path / "db"))
    with pytest.raises(ValueError, match="required"):
        ProtectedStorage(db, tmp_path, keys={}, active_key="")


def test_report_download_decrypts_and_custody_records_real_actor(encrypted_service):
    service, _ = encrypted_service
    from backend.services.case_service import CaseService
    context = actor.set("alice")
    try:
        case = CaseService(service.db).create({"title": "Protected case"})
        item = service.register(b"original", "message.eml", "message/rfc822", case_id=case["case_id"])
        reports = ReportService(service.db, service, str(service.storage_dir))
        report = reports.generate(case["case_id"], "html")
    finally:
        actor.reset(context)
    assert b"NETRA-Mail" in reports.download(report["report_id"])
    assert b"NETRA-Mail" not in (service.storage_dir / report["download_reference"]).read_bytes()
    assert {event["actor"] for event in service.custody(item["evidence_id"])} == {"alice"}
    assert actor.get() == "system"


def test_reports_never_mark_failed_evidence_verified(encrypted_service):
    service, _ = encrypted_service
    from backend.services.case_service import CaseService
    case = CaseService(service.db).create({"title": "Tampered case"})
    item = service.register(b"original", "message.eml", "message/rfc822", case_id=case["case_id"])
    (service.storage_dir / item["storage_reference"]).write_bytes(b"tampered")
    report = ReportService(service.db, service, str(service.storage_dir)).generate(case["case_id"])
    assert not report["integrity_verified"]
    assert not service.custody(item["evidence_id"])[-1]["integrity_verified"]
