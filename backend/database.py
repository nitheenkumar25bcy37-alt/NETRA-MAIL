import sqlite3
import hashlib
import json
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional


GENESIS_HASH = "GENESIS_BLOCK_00000000000000000000000000000000"


class ForensicLedgerDB:
    """
    Tamper-evident SQLite forensic ledger.

    Stores every analyzed email using:

        case_id
        raw SHA-256
        threat score
        verdict
        forensic payload
        previous block hash
        current block hash
    """

    def __init__(self, db_path: str = "forensic_ledger.db"):

        self.db_path = db_path if db_path == ":memory:" else str(Path(db_path).resolve())

        self._init_db()

    def _connect(self):
        return closing(sqlite3.connect(self.db_path))

    # ============================================================
    # DATABASE INITIALIZATION
    # ============================================================

    def _init_db(self):

        with self._connect() as conn:

            cursor = conn.cursor()

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_ledger (

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    case_id TEXT UNIQUE NOT NULL,

                    timestamp TEXT NOT NULL,

                    raw_sha256 TEXT NOT NULL,

                    threat_score INTEGER NOT NULL,

                    verdict TEXT NOT NULL,

                    forensic_payload TEXT NOT NULL,

                    previous_hash TEXT NOT NULL,

                    block_hash TEXT NOT NULL
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS v2_analyses (
                    email_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    analysis_json TEXT NOT NULL
                )
                """
            )

            cursor.executescript(
                """
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'suspected',
                    confidence REAL NOT NULL DEFAULT 0,
                    analyst_confirmed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    primary_indicators TEXT NOT NULL DEFAULT '[]'
                );
                CREATE TABLE IF NOT EXISTS campaign_emails (
                    campaign_id TEXT NOT NULL,
                    email_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (campaign_id, email_id)
                );
                CREATE TABLE IF NOT EXISTS campaign_relationships (
                    source_email_id TEXT NOT NULL,
                    target_email_id TEXT NOT NULL,
                    relationship_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    relationship_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (source_email_id, target_email_id, relationship_type)
                );
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    severity TEXT NOT NULL DEFAULT 'medium',
                    priority TEXT NOT NULL DEFAULT 'normal',
                    analyst TEXT NOT NULL DEFAULT 'analyst',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    tags_json TEXT NOT NULL DEFAULT '[]'
                );
                CREATE TABLE IF NOT EXISTS case_emails (
                    case_id TEXT NOT NULL,
                    email_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (case_id, email_id)
                );
                CREATE TABLE IF NOT EXISTS case_campaigns (
                    case_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (case_id, campaign_id)
                );
                CREATE TABLE IF NOT EXISTS case_notes (
                    note_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    note TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_timeline (
                    event_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_campaign_relationship_source ON campaign_relationships(source_email_id);
                CREATE INDEX IF NOT EXISTS idx_campaign_relationship_target ON campaign_relationships(target_email_id);
                CREATE INDEX IF NOT EXISTS idx_case_timeline_case_time ON case_timeline(case_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_case_emails_email ON case_emails(email_id);
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    email_id TEXT,
                    case_id TEXT,
                    evidence_type TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    storage_reference TEXT NOT NULL,
                    integrity_status TEXT NOT NULL,
                    preserved INTEGER NOT NULL,
                    limitations_json TEXT NOT NULL,
                    current_version INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS evidence_versions (
                    version_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    storage_reference TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    reason TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence_case_links (
                    evidence_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (evidence_id, case_id)
                );
                CREATE TABLE IF NOT EXISTS chain_of_custody (
                    custody_event_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    case_id TEXT,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    description TEXT NOT NULL,
                    sha256_before TEXT,
                    sha256_after TEXT,
                    integrity_verified INTEGER NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    format TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    evidence_count INTEGER NOT NULL,
                    integrity_verified INTEGER NOT NULL,
                    download_reference TEXT NOT NULL,
                    report_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_email ON evidence(email_id);
                CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
                CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence(sha256);
                CREATE INDEX IF NOT EXISTS idx_custody_evidence_time ON chain_of_custody(evidence_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_reports_case ON reports(case_id);
                CREATE TABLE IF NOT EXISTS storage_blobs (
                    reference TEXT PRIMARY KEY,
                    key_id TEXT,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS analysis_owners (
                    email_id TEXT PRIMARY KEY,
                    subject TEXT NOT NULL
                );
                """
            )

            conn.commit()

    def record_v2_analysis(self, email_id: str, sha256: str, analysis: Dict[str, Any]) -> None:
        payload = json.dumps(analysis, sort_keys=True, ensure_ascii=False)
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO v2_analyses (email_id, created_at, sha256, analysis_json) VALUES (?, ?, ?, ?)",
                (email_id, datetime.now(timezone.utc).isoformat(), sha256, payload),
            )
            conn.commit()

    def record_storage_blob(self, reference, key_id, sha256, size_bytes):
        with self._connect() as conn:
            conn.execute("INSERT INTO storage_blobs (reference, key_id, sha256, size_bytes) VALUES (?, ?, ?, ?)", (reference, key_id, sha256, size_bytes))
            conn.commit()

    def set_analysis_owner(self, email_id, subject):
        with self._connect() as conn:
            conn.execute("INSERT INTO analysis_owners (email_id, subject) VALUES (?, ?)", (email_id, subject))
            conn.commit()

    def analysis_owner(self, email_id):
        with self._connect() as conn:
            row = conn.execute("SELECT subject FROM analysis_owners WHERE email_id=?", (email_id,)).fetchone()
        return row[0] if row else None

    def get_storage_blob(self, reference):
        with self._connect() as conn:
            row = conn.execute("SELECT key_id, sha256, size_bytes FROM storage_blobs WHERE reference=?", (reference,)).fetchone()
        return {"key_id": row[0], "sha256": row[1], "size_bytes": row[2]} if row else None

    def get_v2_analysis(self, email_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT analysis_json FROM v2_analyses WHERE email_id = ?", (email_id,)).fetchone()
        if not row:
            return None
        return json.loads(row[0])

    def list_v2_analyses(self) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT analysis_json FROM v2_analyses ORDER BY created_at ASC").fetchall()
        return [json.loads(row[0]) for row in rows]

    def list_v2_analyses_page(self, limit: int = 50, offset: int = 0, risk_level: str | None = None) -> Dict[str, Any]:
        limit = max(1, min(200, int(limit)))
        offset = max(0, int(offset))
        with self._connect() as conn:
            rows = conn.execute("SELECT analysis_json FROM v2_analyses ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        analyses = [json.loads(row[0]) for row in rows]
        if risk_level:
            normalized = risk_level.upper()
            analyses = [item for item in analyses if str(item.get("classification", "")).upper() == normalized or str(item.get("risk_level", "")).upper() == normalized]
        return {"items": analyses, "limit": limit, "offset": offset, "count": len(analyses)}

    def dashboard_summary(self) -> Dict[str, Any]:
        analyses = self.list_v2_analyses()
        high = 0
        critical = 0
        for item in analyses:
            score = int(item.get("risk_score", 0) or 0)
            critical += score >= 75
            high += score >= 50
        cases = self.list_cases()
        campaigns = self.list_campaigns()
        integrity_warnings = 0
        with self._connect() as conn:
            integrity_warnings = conn.execute("SELECT COUNT(*) FROM evidence WHERE integrity_status IN ('failed', 'unavailable')").fetchone()[0]
        return {"total_emails": len(analyses), "critical_emails": critical, "high_risk_emails": high, "open_cases": sum(case.get("status") in {"open", "investigating", "contained"} for case in cases), "suspected_campaigns": sum(campaign.get("status") in {"suspected", "under_review"} for campaign in campaigns), "integrity_warnings": integrity_warnings, "provider_status": {"ip_intelligence": "configured" if __import__("os").getenv("NETRA_IP_INTEL_URL") else "unavailable", "domain_intelligence": "available"}, "limitations": ["Summary metrics reflect persisted v2 records only."]}

    def save_relationship(self, relationship: Dict[str, Any]) -> bool:
        source = relationship["source_email_id"]
        target = relationship["target_email_id"]
        relationship_type = relationship["relationship_type"]
        with self._connect() as conn:
            cursor = conn.execute("INSERT OR IGNORE INTO campaign_relationships (source_email_id, target_email_id, relationship_type, confidence, relationship_json, created_at) VALUES (?, ?, ?, ?, ?, ?)", (source, target, relationship_type, relationship["confidence"], json.dumps(relationship, sort_keys=True), relationship["created_at"]))
            conn.commit()
        return cursor.rowcount > 0

    def get_relationships(self, email_id: str) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT relationship_json FROM campaign_relationships WHERE source_email_id = ? OR target_email_id = ? ORDER BY created_at ASC", (email_id, email_id)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def create_campaign(self, campaign: Dict[str, Any]) -> Dict[str, Any]:
        with self._connect() as conn:
            conn.execute("INSERT INTO campaigns (campaign_id, name, description, status, confidence, analyst_confirmed, created_at, updated_at, primary_indicators) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (campaign["campaign_id"], campaign["name"], campaign.get("description", ""), campaign.get("status", "suspected"), campaign.get("confidence", 0), int(campaign.get("analyst_confirmed", False)), campaign["created_at"], campaign["updated_at"], json.dumps(campaign.get("primary_indicators", []))))
            conn.commit()
        return campaign

    def list_campaigns(self) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT campaign_id, name, description, status, confidence, analyst_confirmed, created_at, updated_at, primary_indicators FROM campaigns ORDER BY created_at DESC").fetchall()
        return [self._campaign_row(row) for row in rows]

    @staticmethod
    def _campaign_row(row: tuple) -> Dict[str, Any]:
        return {"campaign_id": row[0], "name": row[1], "description": row[2], "status": row[3], "confidence": row[4], "analyst_confirmed": bool(row[5]), "created_at": row[6], "updated_at": row[7], "primary_indicators": json.loads(row[8])}

    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT campaign_id, name, description, status, confidence, analyst_confirmed, created_at, updated_at, primary_indicators FROM campaigns WHERE campaign_id = ?", (campaign_id,)).fetchone()
        return self._campaign_row(row) if row else None

    def update_campaign(self, campaign_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        current = self.get_campaign(campaign_id)
        if not current:
            return None
        current.update({key: value for key, value in updates.items() if value is not None})
        current["updated_at"] = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("UPDATE campaigns SET name=?, description=?, status=?, confidence=?, analyst_confirmed=?, updated_at=?, primary_indicators=? WHERE campaign_id=?", (current["name"], current["description"], current["status"], current["confidence"], int(current["analyst_confirmed"]), current["updated_at"], json.dumps(current["primary_indicators"]), campaign_id))
            conn.commit()
        return current

    def add_campaign_email(self, campaign_id: str, email_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("INSERT OR IGNORE INTO campaign_emails (campaign_id, email_id, created_at) VALUES (?, ?, ?)", (campaign_id, email_id, datetime.now(timezone.utc).isoformat()))
            conn.commit()
        return cursor.rowcount > 0

    def get_campaign_emails(self, campaign_id: str) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT email_id FROM campaign_emails WHERE campaign_id = ? ORDER BY created_at ASC", (campaign_id,)).fetchall()
        return [row[0] for row in rows]

    def create_case(self, case: Dict[str, Any]) -> Dict[str, Any]:
        with self._connect() as conn:
            conn.execute("INSERT INTO cases (case_id, title, description, status, severity, priority, analyst, created_at, updated_at, tags_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (case["case_id"], case["title"], case.get("description", ""), case.get("status", "open"), case.get("severity", "medium"), case.get("priority", "normal"), case.get("analyst", "analyst"), case["created_at"], case["updated_at"], json.dumps(case.get("tags", []))))
            conn.commit()
        return case

    def get_case_record(self, case_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT case_id, title, description, status, severity, priority, analyst, created_at, updated_at, tags_json FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if not row:
            return None
        case = {"case_id": row[0], "title": row[1], "description": row[2], "status": row[3], "severity": row[4], "priority": row[5], "analyst": row[6], "created_at": row[7], "updated_at": row[8], "tags": json.loads(row[9])}
        case["email_ids"] = self.get_case_emails(case_id)
        case["campaign_ids"] = self.get_case_campaigns(case_id)
        case["notes"] = self.get_case_notes(case_id)
        return case

    def list_cases(self) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            ids = [row[0] for row in conn.execute("SELECT case_id FROM cases ORDER BY created_at DESC").fetchall()]
        return [self.get_case_record(case_id) for case_id in ids]

    def update_case(self, case_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        case = self.get_case_record(case_id)
        if not case:
            return None
        case.update({key: value for key, value in updates.items() if value is not None})
        case["updated_at"] = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("UPDATE cases SET title=?, description=?, status=?, severity=?, priority=?, analyst=?, updated_at=?, tags_json=? WHERE case_id=?", (case["title"], case["description"], case["status"], case["severity"], case["priority"], case["analyst"], case["updated_at"], json.dumps(case["tags"]), case_id))
            conn.commit()
        return self.get_case_record(case_id)

    def add_case_email(self, case_id: str, email_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("INSERT OR IGNORE INTO case_emails (case_id, email_id, created_at) VALUES (?, ?, ?)", (case_id, email_id, datetime.now(timezone.utc).isoformat()))
            conn.commit()
        return cursor.rowcount > 0

    def remove_case_email(self, case_id: str, email_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM case_emails WHERE case_id = ? AND email_id = ?", (case_id, email_id))
            conn.commit()
        return cursor.rowcount > 0

    def get_case_emails(self, case_id: str) -> list[str]:
        with self._connect() as conn:
            return [row[0] for row in conn.execute("SELECT email_id FROM case_emails WHERE case_id = ? ORDER BY created_at ASC", (case_id,)).fetchall()]

    def add_case_campaign(self, case_id: str, campaign_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("INSERT OR IGNORE INTO case_campaigns (case_id, campaign_id, created_at) VALUES (?, ?, ?)", (case_id, campaign_id, datetime.now(timezone.utc).isoformat()))
            conn.commit()
        return cursor.rowcount > 0

    def get_case_campaigns(self, case_id: str) -> list[str]:
        with self._connect() as conn:
            return [row[0] for row in conn.execute("SELECT campaign_id FROM case_campaigns WHERE case_id = ? ORDER BY created_at ASC", (case_id,)).fetchall()]

    def add_case_note(self, note: Dict[str, Any]) -> Dict[str, Any]:
        with self._connect() as conn:
            conn.execute("INSERT INTO case_notes (note_id, case_id, note, actor, created_at) VALUES (?, ?, ?, ?, ?)", (note["note_id"], note["case_id"], note["note"], note["actor"], note["created_at"]))
            conn.commit()
        return note

    def get_case_notes(self, case_id: str) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT note_id, case_id, note, actor, created_at FROM case_notes WHERE case_id = ? ORDER BY created_at ASC", (case_id,)).fetchall()
        return [{"note_id": row[0], "case_id": row[1], "note": row[2], "actor": row[3], "created_at": row[4]} for row in rows]

    def add_case_timeline(self, event: Dict[str, Any]) -> Dict[str, Any]:
        with self._connect() as conn:
            conn.execute("INSERT INTO case_timeline (event_id, case_id, event_type, description, actor, evidence_refs_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (event["event_id"], event["case_id"], event["event_type"], event["description"], event["actor"], json.dumps(event.get("evidence_refs", [])), event["created_at"]))
            conn.commit()
        return event

    def get_case_timeline(self, case_id: str) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT event_id, case_id, event_type, description, actor, evidence_refs_json, created_at FROM case_timeline WHERE case_id = ? ORDER BY created_at ASC", (case_id,)).fetchall()
        return [{"event_id": row[0], "case_id": row[1], "event_type": row[2], "description": row[3], "actor": row[4], "evidence_refs": json.loads(row[5]), "created_at": row[6]} for row in rows]

    def create_evidence(self, evidence: Dict[str, Any], version: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute("INSERT INTO evidence (evidence_id, email_id, case_id, evidence_type, filename, media_type, size_bytes, sha256, created_at, collected_at, source, storage_reference, integrity_status, preserved, limitations_json, current_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (evidence["evidence_id"], evidence.get("email_id"), evidence.get("case_id"), evidence["evidence_type"], evidence["filename"], evidence["media_type"], evidence["size_bytes"], evidence["sha256"], evidence["created_at"], evidence["collected_at"], evidence["source"], evidence["storage_reference"], evidence["integrity_status"], int(evidence["preserved"]), json.dumps(evidence.get("limitations", [])), evidence.get("current_version", 1)))
            conn.execute("INSERT INTO evidence_versions (version_id, evidence_id, version, sha256, size_bytes, storage_reference, created_at, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (version["version_id"], version["evidence_id"], version["version"], version["sha256"], version["size_bytes"], version["storage_reference"], version["created_at"], version["reason"]))
            conn.commit()

    def find_evidence_by_hash(self, sha256: str, email_id: str | None = None) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT evidence_id FROM evidence WHERE sha256 = ? AND (? IS NULL OR email_id = ?) LIMIT 1", (sha256, email_id, email_id)).fetchone()
        return self.get_evidence(row[0]) if row else None

    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT evidence_id, email_id, case_id, evidence_type, filename, media_type, size_bytes, sha256, created_at, collected_at, source, storage_reference, integrity_status, preserved, limitations_json, current_version FROM evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if not row:
            return None
        return {"evidence_id": row[0], "email_id": row[1], "case_id": row[2], "evidence_type": row[3], "filename": row[4], "media_type": row[5], "size_bytes": row[6], "sha256": row[7], "created_at": row[8], "collected_at": row[9], "source": row[10], "storage_reference": row[11], "integrity_status": row[12], "preserved": bool(row[13]), "limitations": json.loads(row[14]), "current_version": row[15]}

    def update_evidence_integrity(self, evidence_id: str, status: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE evidence SET integrity_status = ? WHERE evidence_id = ?", (status, evidence_id))
            conn.commit()

    def list_evidence_versions(self, evidence_id: str) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT version_id, evidence_id, version, sha256, size_bytes, storage_reference, created_at, reason FROM evidence_versions WHERE evidence_id = ? ORDER BY version ASC", (evidence_id,)).fetchall()
        return [{"version_id": row[0], "evidence_id": row[1], "version": row[2], "sha256": row[3], "size_bytes": row[4], "storage_reference": row[5], "created_at": row[6], "reason": row[7]} for row in rows]

    def create_evidence_version(self, version: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute("INSERT INTO evidence_versions (version_id, evidence_id, version, sha256, size_bytes, storage_reference, created_at, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (version["version_id"], version["evidence_id"], version["version"], version["sha256"], version["size_bytes"], version["storage_reference"], version["created_at"], version["reason"]))
            conn.execute("UPDATE evidence SET current_version = ? WHERE evidence_id = ?", (version["version"], version["evidence_id"]))
            conn.commit()

    def link_evidence_case(self, evidence_id: str, case_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("INSERT OR IGNORE INTO evidence_case_links (evidence_id, case_id, created_at) VALUES (?, ?, ?)", (evidence_id, case_id, datetime.now(timezone.utc).isoformat()))
            conn.execute("UPDATE evidence SET case_id = COALESCE(case_id, ?) WHERE evidence_id = ?", (case_id, evidence_id))
            conn.commit()
        return cursor.rowcount > 0

    def list_evidence_for_case(self, case_id: str) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT evidence_id FROM evidence_case_links WHERE case_id = ? ORDER BY created_at ASC", (case_id,)).fetchall()
        return [self.get_evidence(row[0]) for row in rows]

    def add_custody(self, event: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute("INSERT INTO chain_of_custody (custody_event_id, evidence_id, case_id, event_type, timestamp, actor, description, sha256_before, sha256_after, integrity_verified, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (event["custody_event_id"], event["evidence_id"], event.get("case_id"), event["event_type"], event["timestamp"], event["actor"], event["description"], event.get("sha256_before"), event.get("sha256_after"), int(event.get("integrity_verified", False)), json.dumps(event.get("metadata", {}))))
            conn.commit()

    def get_custody(self, evidence_id: str) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT custody_event_id, evidence_id, case_id, event_type, timestamp, actor, description, sha256_before, sha256_after, integrity_verified, metadata_json FROM chain_of_custody WHERE evidence_id = ? ORDER BY timestamp ASC", (evidence_id,)).fetchall()
        return [{"custody_event_id": row[0], "evidence_id": row[1], "case_id": row[2], "event_type": row[3], "timestamp": row[4], "actor": row[5], "description": row[6], "sha256_before": row[7], "sha256_after": row[8], "integrity_verified": bool(row[9]), "metadata": json.loads(row[10])} for row in rows]

    def create_report(self, report: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute("INSERT INTO reports (report_id, case_id, format, created_at, evidence_count, integrity_verified, download_reference, report_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (report["report_id"], report["case_id"], report["format"], report["created_at"], report["evidence_count"], int(report["integrity_verified"]), report["download_reference"], json.dumps(report, ensure_ascii=False, sort_keys=True)))
            conn.commit()

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT report_json FROM reports WHERE report_id = ?", (report_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_reports(self, case_id: str) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT report_json FROM reports WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    # ============================================================
    # LATEST HASH
    # ============================================================

    def get_latest_hash(self) -> str:

        with self._connect() as conn:

            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT block_hash
                FROM evidence_ledger
                ORDER BY id DESC
                LIMIT 1
                """
            )

            row = cursor.fetchone()

        if row:

            return row[0]

        return GENESIS_HASH

    # ============================================================
    # RECORD EVIDENCE
    # ============================================================

    def record_evidence(
        self,
        case_id: str,
        raw_sha256: str,
        threat_score: int,
        verdict: str,
        forensic_data: Dict[str, Any],
    ) -> str:

        if not case_id:

            raise ValueError(
                "case_id cannot be empty"
            )

        timestamp = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )

        payload_json = json.dumps(
            {**forensic_data, "_ledger_integrity": {"version": 2, "verdict": verdict}},
            sort_keys=True,
            ensure_ascii=False,
        )

        with self._connect() as conn:

            cursor = conn.cursor()
            # Serialize reading the chain head and appending its successor
            # across processes, not just within one Python thread.
            cursor.execute("BEGIN IMMEDIATE")
            row = cursor.execute("SELECT block_hash FROM evidence_ledger ORDER BY id DESC LIMIT 1").fetchone()
            previous_hash = row[0] if row else GENESIS_HASH
            current_hash = hashlib.sha256(
                f"{case_id}{timestamp}{raw_sha256}{int(threat_score)}{payload_json}{previous_hash}".encode("utf-8")
            ).hexdigest()

            cursor.execute(
                """
                INSERT INTO evidence_ledger (
                    case_id,
                    timestamp,
                    raw_sha256,
                    threat_score,
                    verdict,
                    forensic_payload,
                    previous_hash,
                    block_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    timestamp,
                    raw_sha256,
                    int(threat_score),
                    verdict,
                    payload_json,
                    previous_hash,
                    current_hash,
                ),
            )

            conn.commit()

        return current_hash

    # ============================================================
    # GET CASE
    # ============================================================

    def get_case(
        self,
        case_id: str,
    ) -> Optional[Dict[str, Any]]:

        with self._connect() as conn:

            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT
                    id,
                    case_id,
                    timestamp,
                    raw_sha256,
                    threat_score,
                    verdict,
                    forensic_payload,
                    previous_hash,
                    block_hash
                FROM evidence_ledger
                WHERE case_id = ?
                LIMIT 1
                """,
                (
                    case_id,
                ),
            )

            row = cursor.fetchone()

        if not row:

            return None

        (
            record_id,
            stored_case_id,
            timestamp,
            raw_sha256,
            threat_score,
            verdict,
            forensic_payload,
            previous_hash,
            block_hash,
        ) = row

        try:

            payload = json.loads(
                forensic_payload
            )

        except Exception:

            payload = {
                "raw_forensic_payload":
                    forensic_payload
            }

        return {

            "id":
                record_id,

            "case_id":
                stored_case_id,

            "timestamp":
                timestamp,

            "raw_sha256":
                raw_sha256,

            "threat_score":
                threat_score,

            "verdict":
                verdict,

            "forensic_payload":
                payload,

            "previous_hash":
                previous_hash,

            "block_hash":
                block_hash,
        }

    # ============================================================
    # VERIFY CHAIN
    # ============================================================

    def verify_chain_integrity(
        self,
    ) -> Dict[str, Any]:

        with self._connect() as conn:

            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT
                    id,
                    case_id,
                    timestamp,
                    raw_sha256,
                    threat_score,
                    forensic_payload,
                    previous_hash,
                    block_hash,
                    verdict
                FROM evidence_ledger
                ORDER BY id ASC
                """
            )

            records = cursor.fetchall()

        if not records:

            return {

                "status":
                    "EMPTY",

                "valid":
                    True,

                "total_records":
                    0,

                "database":
                    self.db_path,
            }

        expected_previous = GENESIS_HASH

        for row in records:

            (
                record_id,
                case_id,
                timestamp,
                raw_sha256,
                threat_score,
                payload,
                previous_hash,
                stored_hash,
                stored_verdict,
            ) = row

            try:
                seal = json.loads(payload).get("_ledger_integrity", {})
            except (ValueError, AttributeError):
                return {"status": "TAMPERED", "valid": False, "failed_at_id": record_id, "reason": "Invalid ledger payload"}
            if seal.get("version") == 2 and seal.get("verdict") != stored_verdict:
                return {"status": "TAMPERED", "valid": False, "failed_at_id": record_id, "reason": "Verdict modified"}

            if previous_hash != expected_previous:

                return {

                    "status":
                        "TAMPERED",

                    "valid":
                        False,

                    "failed_at_id":
                        record_id,

                    "reason":
                        "Previous hash pointer broken",

                    "database":
                        self.db_path,
                }

            hasher = hashlib.sha256()

            hasher.update(
                (
                    f"{case_id}"
                    f"{timestamp}"
                    f"{raw_sha256}"
                    f"{threat_score}"
                    f"{payload}"
                    f"{previous_hash}"
                ).encode(
                    "utf-8"
                )
            )

            recomputed = (
                hasher.hexdigest()
            )

            if recomputed != stored_hash:

                return {

                    "status":
                        "TAMPERED",

                    "valid":
                        False,

                    "failed_at_id":
                        record_id,

                    "reason":
                        "Payload or metadata modified",

                    "database":
                        self.db_path,
                }

            expected_previous = (
                stored_hash
            )

        return {

            "status":
                "INTEGRAL",

            "valid":
                True,

            "total_records":
                len(records),

            "latest_hash":
                expected_previous,

            "database":
                self.db_path,
        }
