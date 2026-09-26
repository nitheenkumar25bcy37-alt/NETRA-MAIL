"""Opt-in PDF reviews, separate from the preserved original email assessment."""
import hashlib
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from uuid import uuid4

from backend.inspection_client import inspect_attachment


def original_attachment(result, evidence_service, email_id, digest):
    """Retrieve only an attachment belonging to this exact preserved original."""
    reference = result.get("evidence_reference") or {}
    evidence = evidence_service.get(reference.get("evidence_id", ""))
    if not evidence or evidence.get("email_id") != email_id or evidence.get("evidence_type") != "raw_eml":
        raise ValueError("original_unavailable")
    from backend.config import MAX_EVIDENCE_SIZE_BYTES
    raw = evidence_service.storage.read(evidence["storage_reference"], MAX_EVIDENCE_SIZE_BYTES)
    expected = result.get("evidence", {}).get("sha256")
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("original_integrity_failed")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    for part in message.walk():
        if part.is_multipart():
            continue
        data = part.get_payload(decode=True) or b""
        if data and hashlib.sha256(data).hexdigest() == digest:
            if len(data) > 10 * 1024 * 1024 or not data.startswith(b"%PDF-"):
                raise ValueError("unsupported_attachment")
            return data
    raise ValueError("attachment_not_found")


def review_pdf(data, password, email_id, digest, actor):
    extracted = inspect_attachment(data, "document.pdf", "application/pdf", password=password)
    password = None
    review = {"review_id": "pdf_" + uuid4().hex, "email_id": email_id,
              "attachment_sha256": digest, "created_at": datetime.now(timezone.utc).isoformat(),
              "actor": actor, "consent": True, "analysis_version": "4.6.0",
              "status": "not_inspected", "pages": [], "warnings": [],
              "limitations": ["This supplemental review does not replace the original email assessment.",
                              "Passwords and extracted document text are not retained in this review.",
                              "No antivirus sandbox or guarantee of safety is provided."]}
    if not extracted.get("available"):
        errors = {"incorrect_password": "The password did not unlock this PDF. Try again or skip.",
                  "not_pdf": "Only PDF documents are supported.",
                  "unsupported_or_damaged_pdf": "This PDF is damaged or uses unsupported encryption.",
                  "inspection_capacity_exceeded": "The scanner is busy. Try again shortly."}
        errors.update({
            "portable_inspection_worker_unavailable": "The isolated scanner stopped before PDF extraction finished. This is a scanner resource/runtime failure, not a wrong-password result.",
            "portable_inspection_failed": "The PDF scanner encountered an unsupported document or processing error. Contents remain unverified.",
            "inspection_timeout": "The scan exceeded its time limit. Contents remain unverified.",
            "inspection_output_too_large": "The extracted result exceeded the safe size limit. Contents remain unverified.",
            "pdf_inspection_unavailable": "The PDF inspection service is unavailable. Check the configured inspection runtime.",
        })
        code = extracted.get("error")
        review["error_code"] = code if code in errors else "inspection_unavailable"
        review["summary"] = errors.get(extracted.get("error"), "Inspection could not finish. Contents remain unverified; try again later.")
        return review
    from backend.nlp_engine import NLPEngine
    from backend.multilingual_detector import MultilingualLanguageDetector
    from backend.services.financial_context import request_text, request_evidence
    from backend.ml_classifier import LocalMLClassifier
    from backend.url_analyzer import URLAnalyzer
    from backend.attachment_reputation import apply_reputation

    review["total_pages"] = extracted["total_pages"]
    review["encrypted"] = extracted["encrypted"]
    review["limitations"].extend(extracted["limitations"])
    if extracted["active_content"]:
        review["warnings"].append("PDF contains active actions or embedded content: " + ", ".join(extracted["active_content"]) + ". These were not executed; review is required.")
    reputation = apply_reputation({"sha256": digest}).get("reputation", {})
    review["hash_reputation"] = reputation
    if reputation.get("matched"):
        review["warnings"].append("Original attachment hash matches the configured malware blocklist.")
    incomplete = extracted["total_pages"] > len(extracted["pages"]) or not extracted["pages"]
    for page in extracted["pages"]:
        text = page.pop("text", "")
        warnings, checks, models = [], {}, {}
        lexical, _ = request_text(text)
        try:
            nlp = NLPEngine.analyze_text(lexical)
            multi = MultilingualLanguageDetector.analyze(lexical)
            categories = dict(nlp.get("categories", {}))
            for name, cues in multi.get("multilingual_findings", {}).items():
                categories[name] = list(set(categories.get(name, []) + cues))
            requests = request_evidence(lexical, categories)
            pressured = any(r["categories"].get("urgency") for r in requests)
            checks["text"] = "completed" if text.strip() else "no readable text"
        except Exception:
            requests, pressured = [], False
            checks["text"] = "unavailable"
            incomplete = True
        try:
            prediction = LocalMLClassifier.predict(text) if text.strip() else {}
            models = {k: prediction[k] for k in ("classification", "phishing_probability", "calibration_status") if k in prediction}
            checks["ml"] = "completed" if prediction else "no readable text"
        except Exception:
            checks["ml"] = "unavailable"
            incomplete = True
        links = []
        for url in page.get("urls", [])[:50]:
            try:
                evaluated = URLAnalyzer.analyze_references([{"href": url}])
                for item in evaluated["urls"]:
                    links.append({"host": item.get("hostname", "Unknown"),
                                  "risk_score": item.get("risk_score", 0),
                                  "reasons": [f["title"] for f in evaluated["findings"] if f.get("severity") != "info"]})
            except Exception:
                incomplete = True
                checks["links"] = "partly unavailable"
        checks.setdefault("links", "completed" if links else "no HTTP links extracted")
        suspicious = any(link["risk_score"] >= 35 for link in links)
        if suspicious:
            warnings.append("A link has suspicious structural characteristics; its live destination was not visited.")
        if requests and (pressured or suspicious):
            warnings.append("Document text requests sensitive information or payment with pressure or a suspicious link.")
        checks["ocr"] = "completed" if page["ocr_available"] else "unavailable"
        checks["qr"] = "completed" if page["qr_available"] else "unavailable"
        if not page["ocr_available"] or not page["qr_available"] or not text.strip():
            incomplete = True
        # Language coverage is an enduring limitation, not a parser failure.
        if any("limit" in note or "failed" in note or "could not" in note for note in page["limitations"]):
            incomplete = True
        review["pages"].append({"page": page["page"], "checks": checks, "ml": models,
                                "links": links, "qr_count": page["qr_count"],
                                "warnings": warnings, "limitations": page["limitations"]})
    if any(page["warnings"] for page in review["pages"]) or review["warnings"]:
        review["status"] = "suspicious"
        review["summary"] = "Suspicious content or active document features were found. Review the evidence below before using this attachment."
    elif incomplete:
        review["status"] = "limited"
        review["summary"] = "No warning was found in completed checks, but some content or checks remain unverified."
    else:
        review["status"] = "no_threats_detected"
        review["summary"] = "No threats detected in the completed static checks. This is not a guarantee of safety."
    if any("complexity limit" in note for note in review["limitations"]) and review["status"] == "no_threats_detected":
        review["status"] = "limited"
        review["summary"] = "No warning found, but PDF object inspection reached its limit. Some content remains unverified."
    return review
