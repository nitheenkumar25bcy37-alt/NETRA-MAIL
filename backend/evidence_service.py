from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4
from backend.config import MAX_EVIDENCE_SIZE_BYTES
from backend.protected_storage import ProtectedStorage, StorageIntegrityError
from backend.audit_context import current_actor


class EvidenceService:
    ALLOWED_TYPES = {"raw_eml", "reconstructed_eml", "attachment", "report"}
    MAX_FILENAME = 180

    def __init__(self, db: Any, storage_dir: str):
        self.db = db
        self.storage_dir = Path(storage_dir).resolve()
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.storage = ProtectedStorage(db, self.storage_dir)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def _filename(cls, filename: str) -> str:
        raw_name = filename or "evidence.bin"
        if Path(raw_name).name != raw_name or "/" in raw_name or "\\" in raw_name:
            raise ValueError("Unsafe evidence filename")
        name = Path(raw_name).name
        name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[: cls.MAX_FILENAME]
        if name in {"", ".", ".."}:
            raise ValueError("Invalid evidence filename")
        return name

    @staticmethod
    def _validate_hash(value: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value or ""))

    def register(self, raw: bytes, filename: str, media_type: str, evidence_type: str = "raw_eml", source: str = "uploaded_file", email_id: str | None = None, case_id: str | None = None) -> Dict[str, Any]:
        if len(raw) > MAX_EVIDENCE_SIZE_BYTES:
            raise ValueError("Evidence exceeds the configured size limit")
        if evidence_type not in self.ALLOWED_TYPES:
            raise ValueError("Unsupported evidence type")
        if not raw:
            raise ValueError("Evidence is empty")
        safe_name = self._filename(filename)
        digest = hashlib.sha256(raw).hexdigest()
        existing = self.db.find_evidence_by_hash(digest, email_id)
        if existing:
            self._custody(existing["evidence_id"], case_id, "evidence_referenced", "Previously preserved evidence was referenced during registration.", digest, digest, False)
            if case_id:
                self.link_case(existing["evidence_id"], case_id)
            return existing
        evidence_id = "evidence_" + uuid4().hex[:12]
        version_id = "version_" + uuid4().hex[:12]
        relative = Path(evidence_id) / "v1" / safe_name
        destination = self.storage_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=False)
        self.storage.write(relative, raw)
        now = self._now()
        evidence = {"evidence_id": evidence_id, "email_id": email_id, "case_id": case_id, "evidence_type": evidence_type, "filename": safe_name, "media_type": media_type or "application/octet-stream", "size_bytes": len(raw), "sha256": digest, "created_at": now, "collected_at": now, "source": source, "storage_reference": str(relative).replace("\\", "/"), "integrity_status": "verified", "preserved": True, "limitations": ["A hash verifies file integrity, not truthfulness.", "Evidence availability depends on storage and permissions."], "current_version": 1}
        version = {"version_id": version_id, "evidence_id": evidence_id, "version": 1, "sha256": digest, "size_bytes": len(raw), "storage_reference": evidence["storage_reference"], "created_at": now, "reason": "initial_registration"}
        self.db.create_evidence(evidence, version)
        self._custody(evidence_id, case_id, "evidence_collected", "Raw evidence was collected.", digest, digest)
        self._custody(evidence_id, case_id, "evidence_registered", "Raw evidence was registered.", digest, digest)
        if case_id:
            self.link_case(evidence_id, case_id)
        return evidence

    def get(self, evidence_id: str) -> Dict[str, Any] | None:
        evidence = self.db.get_evidence(evidence_id)
        if evidence:
            blob = self.db.get_storage_blob(evidence["storage_reference"])
            evidence["storage_protection"] = "AES-256-GCM" if blob and blob["key_id"] else "plaintext"
        return evidence

    def verify(self, evidence_id: str) -> Dict[str, Any]:
        evidence = self.db.get_evidence(evidence_id)
        if not evidence:
            raise KeyError("Evidence was not found")
        try:
            raw = self.storage.read(evidence["storage_reference"], MAX_EVIDENCE_SIZE_BYTES)
            computed = hashlib.sha256(raw).hexdigest()
            match = computed == evidence["sha256"]
            status = "verified" if match else "failed"
            self.db.update_evidence_integrity(evidence_id, status)
            self._custody(evidence_id, evidence.get("case_id"), "evidence_hash_verified" if match else "evidence_integrity_failed", "Evidence hash verification completed.", evidence["sha256"], computed, match)
            return {"evidence_id": evidence_id, "stored_sha256": evidence["sha256"], "computed_sha256": computed, "integrity_status": status, "verified_at": self._now(), "match": match, "limitations": evidence.get("limitations", [])}
        except StorageIntegrityError:
            self.db.update_evidence_integrity(evidence_id, "failed")
            self._custody(evidence_id, evidence.get("case_id"), "evidence_integrity_failed", "Stored evidence failed authentication or integrity verification.", evidence["sha256"], None, False)
            return {"evidence_id": evidence_id, "stored_sha256": evidence["sha256"], "computed_sha256": None, "integrity_status": "failed", "verified_at": self._now(), "match": False}
        except (OSError, ValueError):
            self.db.update_evidence_integrity(evidence_id, "unavailable")
            self._custody(evidence_id, evidence.get("case_id"), "evidence_integrity_failed", "Original evidence bytes could not be accessed.", evidence["sha256"], None, False)
            return {"evidence_id": evidence_id, "stored_sha256": evidence["sha256"], "computed_sha256": None, "integrity_status": "unavailable", "verified_at": self._now(), "match": False, "limitations": ["The original evidence bytes could not be accessed."]}

    def versions(self, evidence_id: str) -> List[Dict[str, Any]]:
        if not self.db.get_evidence(evidence_id):
            raise KeyError("Evidence was not found")
        return self.db.list_evidence_versions(evidence_id)

    def create_version(self, evidence_id: str, raw: bytes, filename: str | None = None, reason: str = "replacement_preserved_as_new_version") -> Dict[str, Any]:
        if len(raw) > MAX_EVIDENCE_SIZE_BYTES:
            raise ValueError("Evidence exceeds the configured size limit")
        evidence = self.db.get_evidence(evidence_id)
        if not evidence:
            raise KeyError("Evidence was not found")
        if not raw:
            raise ValueError("Evidence version is empty")
        safe_name = self._filename(filename or evidence["filename"])
        version_number = evidence["current_version"] + 1
        digest = hashlib.sha256(raw).hexdigest()
        relative = Path(evidence_id) / f"v{version_number}" / safe_name
        destination = self.storage_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=False)
        self.storage.write(relative, raw)
        now = self._now()
        version = {"version_id": "version_" + uuid4().hex[:12], "evidence_id": evidence_id, "version": version_number, "sha256": digest, "size_bytes": len(raw), "storage_reference": str(relative).replace("\\", "/"), "created_at": now, "reason": reason}
        self.db.create_evidence_version(version)
        self._custody(evidence_id, evidence.get("case_id"), "evidence_registered", "A new evidence version was registered without overwriting the original.", evidence["sha256"], digest)
        return version

    def export_metadata(self, evidence_id: str) -> Dict[str, Any]:
        evidence = self.get(evidence_id)
        if not evidence:
            raise KeyError("Evidence was not found")
        self._custody(evidence_id, evidence.get("case_id"), "evidence_exported", "Evidence metadata was exported.", evidence["sha256"], evidence["sha256"])
        return {key: value for key, value in evidence.items() if key != "storage_reference"}

    def custody(self, evidence_id: str) -> List[Dict[str, Any]]:
        if not self.db.get_evidence(evidence_id):
            raise KeyError("Evidence was not found")
        return self.db.get_custody(evidence_id)

    def link_case(self, evidence_id: str, case_id: str) -> Dict[str, Any]:
        evidence = self.db.get_evidence(evidence_id)
        if not evidence:
            raise KeyError("Evidence was not found")
        if not self.db.get_case_record(case_id):
            raise KeyError("Case was not found")
        added = self.db.link_evidence_case(evidence_id, case_id)
        if added:
            self.db.add_case_timeline({"event_id": "event_" + uuid4().hex[:12], "case_id": case_id, "event_type": "evidence_attached", "description": f"Evidence {evidence_id} was attached to the case.", "actor": current_actor(), "evidence_refs": [evidence_id], "created_at": self._now()})
            self._custody(evidence_id, case_id, "evidence_attached_to_case", "Evidence was attached to a case.", evidence["sha256"], evidence["sha256"])
        return self.db.get_evidence(evidence_id)

    def list_for_case(self, case_id: str) -> List[Dict[str, Any]]:
        if not self.db.get_case_record(case_id):
            raise KeyError("Case was not found")
        return self.db.list_evidence_for_case(case_id)

    def _custody(self, evidence_id: str, case_id: str | None, event_type: str, description: str, before: str | None, after: str | None, verified: bool = True) -> None:
        self.db.add_custody({"custody_event_id": "custody_" + uuid4().hex[:12], "evidence_id": evidence_id, "case_id": case_id, "event_type": event_type, "timestamp": self._now(), "actor": current_actor(), "description": description, "sha256_before": before, "sha256_after": after, "integrity_verified": verified, "metadata": {}})
