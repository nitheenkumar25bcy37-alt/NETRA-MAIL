from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from backend.audit_context import current_actor
from backend.config import MAX_EVIDENCE_SIZE_BYTES

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
except ImportError:  # pragma: no cover
    canvas = None


class ReportService:
    FORMATS = {"json", "html", "pdf"}

    def __init__(self, db, evidence_service, storage_dir: str):
        self.db = db
        self.evidence = evidence_service
        self.storage_dir = Path(storage_dir).resolve()
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, case_id: str, output_format: str = "json"):
        if output_format not in self.FORMATS:
            raise ValueError("Unsupported report format")
        case = self.db.get_case_record(case_id)
        if not case:
            raise KeyError("Case was not found")
        evidence = self.db.list_evidence_for_case(case_id)
        email_ids = case.get("email_ids", [])
        analyses = [self.db.get_v2_analysis(email_id) for email_id in email_ids]
        analyses = [item for item in analyses if item]
        report_id = "report_" + uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        integrity = [self.evidence.verify(item["evidence_id"]) for item in evidence]
        email_sections = []
        for item in analyses:
            email_sections.append({"email_id": item.get("email_id"), "evidence": item.get("evidence"), "classification": item.get("classification"), "risk_score": item.get("risk_score"), "findings": item.get("findings", []), "parsed": {key: item.get("parsed", {}).get(key) for key in ("metadata", "origin_trace", "ip_intelligence", "domain_intelligence")}})
        relationships = [relationship for email_id in email_ids for relationship in self.db.get_relationships(email_id)]
        custody = [event for item in evidence for event in self.db.get_custody(item["evidence_id"])]
        report = {
            "report_id": report_id,
            "case_id": case_id,
            "format": output_format,
            "created_at": now,
            "evidence_count": len(evidence),
            "integrity_verified": bool(integrity) and all(item["match"] for item in integrity),
            "observed_evidence": {"case": case, "emails": email_sections},
            "campaign_relationships": relationships,
            "evidence_inventory": evidence,
            "chain_of_custody": custody,
            "analyst_notes": case.get("notes", []),
            "timeline": self.db.get_case_timeline(case_id),
            "analytical_findings": [item.get("findings", []) for item in analyses],
            "limitations": ["A hash verifies file integrity, not truthfulness.", "Chain of custody records application-level handling.", "Geolocation and infrastructure evidence do not prove human attribution.", "Reports require analyst review.", "A compromised legitimate account may still send malicious email."],
            "recommended_actions": ["Review high-confidence findings and preserve original evidence.", "Validate affected accounts and authentication activity through independent channels.", "Treat campaign relationships as hypotheses requiring analyst confirmation."],
            "attribution_disclaimer": "Human attribution cannot be established from the available email, infrastructure, or geolocation data.",
        }
        payload = self._render(report, output_format)
        relative = Path("reports") / f"{report_id}.{output_format}"
        destination = self.storage_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.evidence.storage.write(relative, payload)
        report["download_reference"] = str(relative).replace("\\", "/")
        self.db.create_report(report)
        self.db.add_case_timeline({"event_id": "event_" + uuid4().hex[:12], "case_id": case_id, "event_type": "report_generated", "description": f"Report {report_id} was generated.", "actor": current_actor(), "evidence_refs": [item["evidence_id"] for item in evidence], "created_at": now})
        for item in evidence:
            verified = next((check["match"] for check in integrity if check["evidence_id"] == item["evidence_id"]), False)
            self.db.add_custody({"custody_event_id": "custody_" + uuid4().hex[:12], "evidence_id": item["evidence_id"], "case_id": case_id, "event_type": "evidence_reported", "timestamp": now, "actor": current_actor(), "description": f"Evidence was included in report {report_id}.", "sha256_before": item["sha256"], "sha256_after": item["sha256"], "integrity_verified": verified, "metadata": {"report_id": report_id}})
        return report

    @staticmethod
    def _render(report, output_format):
        if output_format == "json":
            return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
        if output_format == "html":
            sections = []
            for title, value in (("Observed Evidence", report["observed_evidence"]), ("Analytical Findings", report["analytical_findings"]), ("Correlation Results", report["campaign_relationships"]), ("Evidence Inventory", report["evidence_inventory"]), ("Chain of Custody", report["chain_of_custody"]), ("Confidence and Limitations", report["limitations"]), ("Recommended Actions", report["recommended_actions"]), ("Attribution Disclaimer", report["attribution_disclaimer"])):
                sections.append(f"<h2>{html.escape(title)}</h2><pre>{html.escape(json.dumps(value, indent=2, ensure_ascii=False, default=str))}</pre>")
            return ("<!doctype html><html><head><meta charset='utf-8'><title>Forensic Report " + html.escape(report["report_id"]) + "</title></head><body><h1>NETRA-Mail Forensic Report</h1>" + "".join(sections) + "</body></html>").encode("utf-8")
        if canvas is None:
            raise RuntimeError("PDF support is unavailable")
        from io import BytesIO
        stream = BytesIO()
        document = canvas.Canvas(stream, pagesize=letter)
        document.setTitle("NETRA-Mail Forensic Report")
        y = 760
        hash_lines = [f"{item.get('evidence_id')}: {item.get('sha256')}" for item in report.get("evidence_inventory", [])]
        for line in (f"NETRA-Mail Forensic Report: {report['report_id']}", f"Case: {report['case_id']}", f"Evidence count: {report['evidence_count']}", f"Integrity verified: {report['integrity_verified']}", "", "Evidence hashes:", *hash_lines, "", "Limitations:", *report["limitations"], "", report["attribution_disclaimer"]):
            for wrapped in [line[index:index + 95] for index in range(0, len(line), 95)] or [""]:
                document.drawString(45, y, wrapped)
                y -= 14
                if y < 45:
                    document.showPage()
                    y = 760
        document.save()
        return stream.getvalue()

    def get(self, report_id: str):
        return self.db.get_report(report_id)

    def download(self, report_id):
        report = self.get(report_id)
        if not report:
            raise KeyError("Report was not found")
        raw = self.evidence.storage.read(report["download_reference"], MAX_EVIDENCE_SIZE_BYTES)
        self.db.add_case_timeline({"event_id": "event_" + uuid4().hex[:12], "case_id": report["case_id"], "event_type": "report_downloaded", "description": f"Report {report_id} was downloaded.", "actor": current_actor(), "evidence_refs": [], "created_at": datetime.now(timezone.utc).isoformat()})
        return raw

    def list_for_case(self, case_id: str):
        return self.db.list_reports(case_id)
