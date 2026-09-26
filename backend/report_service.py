from __future__ import annotations

from backend.presentation import explain_analysis, explanation_lines
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
        # Evidence attached through the dashboard may not be in a legacy case's
        # explicit email list. Include its persisted analysis in the report.
        email_ids = list(dict.fromkeys([*case.get("email_ids", []),
            *[item["email_id"] for item in evidence if item.get("email_id")]]))
        analyses = [self.db.get_v2_analysis(email_id) for email_id in email_ids]
        analyses = [item for item in analyses if item]
        report_id = "report_" + uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        integrity = [self.evidence.verify(item["evidence_id"]) for item in evidence]
        email_sections = []
        for item in analyses:
            email_sections.append({"email_id": item.get("email_id"), "evidence": item.get("evidence"), "classification": item.get("classification"), "risk_score": item.get("risk_score"), "findings": item.get("findings", []), "explanation": explain_analysis(item), "parsed": {key: item.get("parsed", {}).get(key) for key in ("metadata", "origin_trace", "ip_intelligence", "domain_intelligence")}})
        relationships = [relationship for email_id in email_ids for relationship in self.db.get_relationships(email_id)]
        for section in email_sections:
            section["attachment_reviews"] = self.db.list_attachment_reviews(section["email_id"])
            from backend.services.investigation_graph import graph_from_store
            original = next(a for a in analyses if a["email_id"] == section["email_id"])
            section["evidence_graph"] = graph_from_store(original, self.db)
            section["parsed"]["infrastructure_reputation"] = original.get("parsed", {}).get("infrastructure_reputation", {})
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
        lines = [f"Report: {report['report_id']}", f"Case: {report['case_id']}"]
        for email in report["observed_evidence"].get("emails", []):
            lines.append("Email: " + str(email.get("email_id")))
            lines.extend(explanation_lines(email.get("explanation") or explain_analysis(email)))
            graph = email.get("evidence_graph") or {}
            lines.append("Evidence graph analysis: " + str(graph.get("algorithm", "Unavailable")))
            lines.append("Candidate campaign clusters (require review): " + json.dumps(graph.get("candidate_clusters", []), ensure_ascii=False))
            lines.append("Graph observations and sources: " + json.dumps(graph.get("edges", []), ensure_ascii=False))
            for review in email.get("attachment_reviews", []):
                lines.append("Supplemental PDF review: " + review["summary"])
                lines.append("Original attachment SHA-256: " + review["attachment_sha256"])
                lines.extend(review.get("warnings", []))
                for page in review.get("pages", []):
                    lines.append("Page " + str(page["page"]) + ": " + "; ".join(k + " " + v for k, v in page["checks"].items()))
                    lines.extend(page.get("warnings", []))
                    for link in page.get("links", []):
                        lines.append("Link host: " + str(link["host"]) + "; static risk " + str(link["risk_score"]) + "/100")
                    lines.extend(page.get("limitations", []))
                lines.extend(review.get("limitations", []))
        lines.extend(["Evidence integrity:", f"Evidence count: {report['evidence_count']}; integrity verified: {report['integrity_verified']}"])
        lines.extend(f"{item.get('evidence_id')}: {item.get('sha256')}" for item in report.get("evidence_inventory", []))
        lines.extend(["Report limitations:", *report["limitations"], report["attribution_disclaimer"]])
        if output_format == "html":
            narrative = "".join("<p>" + html.escape(str(line)) + "</p>" for line in lines)
            technical = "<details><summary>Technical evidence, custody and analyst records</summary><pre>" + html.escape(json.dumps(report, indent=2, ensure_ascii=False, default=str)) + "</pre></details>"
            return ("<!doctype html><html><head><meta charset='utf-8'><title>NETRA Forensic Report</title><style>body{font:17px Arial;max-width:1000px;margin:40px auto;padding:20px;line-height:1.5}p{overflow-wrap:anywhere}pre{white-space:pre-wrap}</style></head><body><h1>NETRA-Mail Forensic Report</h1>" + narrative + technical + "</body></html>").encode("utf-8")
        if canvas is None:
            raise RuntimeError("PDF support is unavailable")
        from io import BytesIO
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        stream = BytesIO()
        styles = getSampleStyleSheet()
        styles["BodyText"].wordWrap = "CJK"
        story = [Paragraph("NETRA-Mail Forensic Report", styles["Title"])]
        for line in lines:
            story.extend([Paragraph(html.escape(str(line)), styles["BodyText"]), Spacer(1, 6)])
        for title, key in (("Correlation evidence", "campaign_relationships"), ("Chain of custody", "chain_of_custody"), ("Analyst notes", "analyst_notes"), ("Timeline", "timeline")):
            story.append(Paragraph(title, styles["Heading2"]))
            story.append(Paragraph(html.escape(json.dumps(report.get(key, []), ensure_ascii=False, default=str)), styles["BodyText"]))
        SimpleDocTemplate(stream, pagesize=letter, title="NETRA-Mail Forensic Report").build(story)
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
