import re
from datetime import datetime
from typing import Any, Dict, List
from uuid import uuid4


class HeaderForensicAnalyzer:
    """Structured header, authentication, and relay analysis."""

    BRANDS = {"paypal", "microsoft", "google", "apple", "amazon", "dhl", "fedex", "netflix", "linkedin", "github", "sbi", "hdfc", "icici"}

    @classmethod
    def _finding(cls, rule: str, severity: str, confidence: float, title: str, description: str, evidence: Dict[str, Any], limitations: List[str] | None = None, category: str = "Authentication") -> Dict[str, Any]:
        return {"finding_id": str(uuid4()), "category": category, "rule": rule, "severity": severity, "confidence": confidence, "title": title, "description": description, "evidence": evidence, "limitations": limitations or []}

    @classmethod
    def analyze(cls, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        auth = parsed_email.get("authentication_headers", {}) or {}
        meta = parsed_email.get("metadata", {}) or {}
        chain = parsed_email.get("network_chain", []) or []
        auth_text = " ".join(str(value) for key, values in auth.items() if key in {"authentication_results", "received_spf", "spf", "dmarc"} for value in (values if isinstance(values, list) else [values])).lower()
        statuses = {name: cls._status(name, auth_text) for name in ("spf", "dkim", "dmarc")}
        domains = {name: cls._domain(meta.get(name, "")) for name in ("from", "reply_to", "return_path", "sender")}
        domains["message_id"] = cls._message_id_domain(meta.get("message_id", ""))
        alignment = {"from_domain": domains["from"], "reply_to_domain": domains["reply_to"], "return_path_domain": domains["return_path"], "sender_domain": domains["sender"], "message_id_domain": domains["message_id"], "spf_aligned": cls._aligned(domains["from"], cls._auth_domain(auth_text, "smtp.mailfrom")), "dkim_aligned": cls._aligned(domains["from"], cls._auth_domain(auth_text, "header.d")), "dmarc_aligned": cls._aligned(domains["from"], cls._auth_domain(auth_text, "header.from"))}
        findings: List[Dict[str, Any]] = []

        if domains["from"] and domains["reply_to"] and not cls._aligned(domains["from"], domains["reply_to"]):
            findings.append(cls._finding("from_reply_to_mismatch", "medium", 0.94, "From and Reply-To domains differ", "Replies may be directed to a different domain than the displayed sender.", {"from": domains["from"], "reply_to": domains["reply_to"]}, category="Sender identity"))
        if domains["from"] and domains["return_path"] and not cls._aligned(domains["from"], domains["return_path"]):
            findings.append(cls._finding("from_return_path_mismatch", "medium", 0.92, "From and Return-Path domains differ", "The envelope return path is not aligned with the displayed sender domain.", {"from": domains["from"], "return_path": domains["return_path"]}, category="Sender identity"))
        display_name = cls._display_name(meta.get("from", ""))
        display_brands = [brand for brand in cls.BRANDS if re.search(r"\b" + re.escape(brand) + r"\b", display_name.lower())]
        official = {"paypal": ["paypal.com"], "microsoft": ["microsoft.com", "outlook.com"], "google": ["google.com"], "apple": ["apple.com"], "amazon": ["amazon.com", "amazon.in"], "dhl": ["dhl.com"], "fedex": ["fedex.com"], "netflix": ["netflix.com"], "linkedin": ["linkedin.com"], "github": ["github.com"], "sbi": ["sbi.co.in", "sbi.bank"], "hdfc": ["hdfcbank.com"], "icici": ["icicibank.com"]}
        if display_brands and not any(domains["from"] == domain or domains["from"].endswith("." + domain) for brand in display_brands for domain in official.get(brand, [])):
            findings.append(cls._finding("display_name_impersonation", "high", 0.8, "Display name resembles a known brand", "The display name invokes a known brand while the sender domain does not align with that brand.", {"display_name": display_name, "from_domain": domains["from"]}, category="Sender identity"))
        from backend.domain_confusables import inspect_hostname
        homograph = inspect_hostname(domains["from"], cls.BRANDS)
        if homograph["lookalike"]:
            findings.append(cls._finding("sender_homograph", "high", .9, "Sender domain resembles a protected brand", "Confusable characters can disguise a different sender domain.", homograph, category="Sender identity"))
        for name, status in statuses.items():
            if status == "fail":
                findings.append(cls._finding(f"{name}_failure", "medium", 0.9, f"{name.upper()} authentication failed", "Authentication failure is a risk signal, but authentication success does not prove that the message is safe.", {name: status}))
        if statuses["spf"] == "pass" and alignment["spf_aligned"] is False:
            findings.append(cls._finding("spf_misalignment", "medium", 0.84, "SPF passed but is not aligned", "The authenticated envelope domain differs from the visible From domain.", alignment))
        if statuses["dkim"] == "pass" and alignment["dkim_aligned"] is False:
            findings.append(cls._finding("dkim_misalignment", "medium", 0.84, "DKIM passed but is not aligned", "The signing domain differs from the visible From domain.", alignment))
        if statuses["dmarc"] == "pass" and alignment["dmarc_aligned"] is False:
            findings.append(cls._finding("dmarc_misalignment", "medium", 0.84, "DMARC result is not aligned", "The reported DMARC evidence does not align with the visible From domain.", alignment))
        if domains["message_id"] and domains["from"] and not cls._aligned(domains["message_id"], domains["from"]):
            findings.append(cls._finding("message_id_domain_mismatch", "low", 0.72, "Message-ID domain differs from sender domain", "Message-ID domains can be generated by infrastructure, so this is a review signal rather than proof of abuse.", {"message_id_domain": domains["message_id"], "from_domain": domains["from"]}, ["Message-ID mismatch alone does not establish forgery."]))

        findings.extend(cls._relay_findings(chain))
        risk_score = min(100, sum({"low": 8, "medium": 18, "high": 32, "critical": 45}.get(item["severity"], 0) for item in findings))
        origin_candidates = cls._origin_candidates(chain)
        return {"authentication": statuses, "alignment": alignment, "display_name": display_name, "domains": domains, "relay_chain": chain, "origin_candidates": origin_candidates, "originating_ip": origin_candidates[0]["ip"] if origin_candidates else None, "hop_count": len(chain), "header_risk_score": risk_score, "indicators": [item["title"] for item in findings], "findings": findings, "limitations": ["SPF, DKIM, and DMARC pass results do not prove that a message is safe.", "Relay evidence identifies observed infrastructure, not the human sender."]}

    @classmethod
    def _relay_findings(cls, chain: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for hop in chain:
            if hop.get("malformed"):
                findings.append(cls._finding("malformed_received", "medium", 0.86, "Malformed Received header", "A relay record lacks an expected from/by structure.", {"hop": hop.get("hop_index"), "raw_header": hop.get("raw_header", "")}))
            if hop.get("timestamp_anomaly"):
                findings.append(cls._finding("received_timestamp_anomaly", "low", 0.78, "Received header timestamp is missing or malformed", "The relay timestamp could not be parsed reliably.", {"hop": hop.get("hop_index"), "raw_header": hop.get("raw_header", "")}))
            for ip, classification in zip(hop.get("extracted_ips", []), hop.get("ip_classifications", [])):
                if classification in {"private", "reserved", "loopback"}:
                    findings.append(cls._finding("non_public_origin_ip", "info", 0.9, "Non-public IP appears in relay evidence", "Private, reserved, or loopback addresses cannot establish a public origin.", {"ip": ip, "classification": classification, "hop": hop.get("hop_index")}, ["Private relay addresses are common inside legitimate mail systems."]))
        timestamps = [cls._timestamp(hop.get("timestamp")) for hop in chain]
        valid = [stamp for stamp in timestamps if stamp and stamp.tzinfo is not None]
        if len(valid) > 1 and any(left < right for left, right in zip(valid, valid[1:])):
            findings.append(cls._finding("received_timestamp_order", "medium", 0.78, "Received timestamps are inconsistent", "The observed header order contains timestamps that do not follow normal relay chronology.", {"timestamps": [stamp.isoformat() for stamp in valid]}))
        return findings

    @staticmethod
    def _timestamp(value: Any) -> datetime | None:
        try:
            return datetime.fromisoformat(str(value)) if value else None
        except ValueError:
            return None

    @staticmethod
    def _origin_candidates(chain: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        candidates = []
        for hop in reversed(chain):
            for ip, classification in zip(hop.get("extracted_ips", []), hop.get("ip_classifications", [])):
                if classification == "public":
                    candidates.append({"ip": ip, "position": hop.get("hop_index"), "confidence": 0.65 if not candidates else 0.48, "basis": ["Public IP", "Observed in Received chain", "Oldest observed public candidate" if not candidates else "Additional public relay candidate"]})
        return candidates

    @staticmethod
    def _status(kind: str, text: str) -> str:
        matches = re.findall(rf"\b{re.escape(kind)}\s*[=:]\s*(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)\b", text)
        if not matches:
            return "none"
        value = matches[0]
        # Preserve errors and soft failures: a DNS outage is not proof of forgery.
        return value

    @staticmethod
    def _auth_domain(text: str, key: str) -> str:
        match = re.search(rf"{re.escape(key)}\s*=\s*([^;\s]+)", text)
        return match.group(1).lower().strip(".") if match else ""

    @staticmethod
    def _domain(value: str) -> str:
        match = re.search(r"@([^>\s]+)", str(value))
        return match.group(1).lower().strip(".") if match else ""

    @staticmethod
    def _message_id_domain(value: str) -> str:
        match = re.search(r"@([^>]+)>?", str(value))
        return match.group(1).lower().strip(".") if match else ""

    @staticmethod
    def _display_name(value: str) -> str:
        match = re.match(r"\s*([^<]+?)\s*<", str(value))
        return match.group(1).strip().strip('"') if match else ""

    @staticmethod
    def _aligned(left: str, right: str) -> bool | None:
        if not left or not right:
            return None
        return left == right or left.endswith("." + right) or right.endswith("." + left)
