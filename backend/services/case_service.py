from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4
from backend.audit_context import current_actor


class CaseService:
    STATUS = {"open", "investigating", "contained", "resolved", "closed", "false_positive"}
    SEVERITY = {"low", "medium", "high", "critical"}
    PRIORITY = {"low", "normal", "high", "urgent"}

    def __init__(self, db: Any):
        self.db = db

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def create(self, data: Dict[str, Any]) -> Dict[str, Any]:
        self._validate(data)
        now = self._now()
        case = {"case_id": "case_" + uuid4().hex[:12], "title": data["title"].strip(), "description": data.get("description", "").strip(), "status": data.get("status", "open"), "severity": data.get("severity", "medium"), "priority": data.get("priority", "normal"), "analyst": data.get("analyst", "analyst"), "created_at": now, "updated_at": now, "tags": []}
        self.db.create_case(case)
        self.timeline(case["case_id"], "case_created", f"Case {case['case_id']} was created.", evidence_refs=[])
        return self.db.get_case_record(case["case_id"])

    def update(self, case_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        case = self.require(case_id)
        self._validate(data, partial=True)
        updated = self.db.update_case(case_id, data)
        changed = ", ".join(key for key in data if data[key] is not None)
        self.timeline(case_id, "case_updated", f"Case fields updated: {changed}.", evidence_refs=[])
        return updated

    def require(self, case_id: str) -> Dict[str, Any]:
        case = self.db.get_case_record(case_id)
        if not case:
            raise KeyError("Case was not found")
        return case

    def add_email(self, case_id: str, email_id: str) -> Dict[str, Any]:
        self.require(case_id)
        if not self.db.get_v2_analysis(email_id):
            raise KeyError("Email analysis was not found")
        added = self.db.add_case_email(case_id, email_id)
        if added:
            self.timeline(case_id, "email_added", f"Email {email_id} was added to the case.", [email_id])
        return self.require(case_id)

    def remove_email(self, case_id: str, email_id: str) -> Dict[str, Any]:
        self.require(case_id)
        removed = self.db.remove_case_email(case_id, email_id)
        if not removed:
            raise KeyError("Email is not linked to this case")
        self.timeline(case_id, "email_removed", f"Email {email_id} was removed from the case.", [email_id])
        return self.require(case_id)

    def add_campaign(self, case_id: str, campaign_id: str) -> Dict[str, Any]:
        self.require(case_id)
        if not self.db.get_campaign(campaign_id):
            raise KeyError("Campaign was not found")
        if self.db.add_case_campaign(case_id, campaign_id):
            self.timeline(case_id, "campaign_linked", f"Campaign {campaign_id} was linked to the case.", [campaign_id])
        return self.require(case_id)

    def add_note(self, case_id: str, note: str, actor: str = "analyst") -> Dict[str, Any]:
        self.require(case_id)
        if not note or len(note.strip()) > 4000:
            raise ValueError("Note must contain 1 to 4000 characters")
        record = {"note_id": "note_" + uuid4().hex[:12], "case_id": case_id, "note": note.strip(), "actor": actor.strip() or "analyst", "created_at": self._now()}
        self.db.add_case_note(record)
        self.timeline(case_id, "note_added", "An analyst note was added to the case.", [])
        return record

    def add_tag(self, case_id: str, tag: str) -> Dict[str, Any]:
        case = self.require(case_id)
        tag = tag.strip().lower()
        if not tag or len(tag) > 80:
            raise ValueError("Tag must contain 1 to 80 characters")
        tags = list(dict.fromkeys(case.get("tags", []) + [tag]))
        self.db.update_case(case_id, {"tags": tags})
        self.timeline(case_id, "tag_added", f"Tag {tag} was added to the case.", [])
        return self.require(case_id)

    def timeline(self, case_id: str, event_type: str, description: str, evidence_refs: List[str]) -> Dict[str, Any]:
        event = {"event_id": "event_" + uuid4().hex[:12], "case_id": case_id, "event_type": event_type, "description": description, "actor": current_actor(), "evidence_refs": evidence_refs, "created_at": self._now()}
        return self.db.add_case_timeline(event)

    def _validate(self, data: Dict[str, Any], partial: bool = False) -> None:
        if not partial and not str(data.get("title", "")).strip():
            raise ValueError("Case title is required")
        if data.get("status") is not None and data["status"] not in self.STATUS:
            raise ValueError("Invalid case status")
        if data.get("severity") is not None and data["severity"] not in self.SEVERITY:
            raise ValueError("Invalid case severity")
        if data.get("priority") is not None and data["priority"] not in self.PRIORITY:
            raise ValueError("Invalid case priority")
