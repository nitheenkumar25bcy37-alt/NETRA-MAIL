from __future__ import annotations

from typing import Any, Dict, Iterable, List


class RiskEngine:
    """Combines distinct findings without treating one signal as proof."""

    SEVERITY_WEIGHT = {"info": 0, "low": 8, "medium": 18, "high": 32, "critical": 45}

    @classmethod
    def evaluate(cls, findings: Iterable[Dict[str, Any]], nlp: Dict[str, Any] | None = None) -> Dict[str, Any]:
        findings = list(findings)
        seen_rules = set()
        contributions: List[Dict[str, Any]] = []
        score = 0.0
        confidence_values = []

        for finding in findings:
            rule = str(finding.get("rule", "unknown"))
            if rule in seen_rules:
                continue
            seen_rules.add(rule)
            severity = str(finding.get("severity", "info")).lower()
            confidence = max(0.0, min(1.0, float(finding.get("confidence", 0.0))))
            contribution = round(cls.SEVERITY_WEIGHT.get(severity, 0) * confidence, 2)
            score += contribution
            confidence_values.append(confidence)
            if contribution:
                contributions.append({"rule": rule, "points": contribution, "reason": finding.get("title", rule)})

        categories = (nlp or {}).get("categories", {})
        active = {key for key, values in categories.items() if values}
        # Lexical combinations remain useful for unauthenticated messages, but
        # ordinary transactional nouns are only context when the sender is
        # independently authenticated and no structural warning corroborates
        # them.
        if len(active) >= 2 and not (nlp or {}).get("trusted_transactional_context"):
            score += 10
            contributions.append({"rule": "multi_signal_context", "points": 10, "reason": "Multiple social-engineering language categories are present."})

        score = min(100, round(score))
        # Explicit file-handling policy: executable and active-content delivery
        # requires review even without social-engineering text.
        for finding in findings:
            if str(finding.get("rule", "")).startswith("attachment_static_"):
                score = max(score, {"critical": 75, "high": 50, "medium": 25}.get(finding.get("severity"), 0))
        if "calibrated_ml_review" in seen_rules:
            score = max(score, 35)
        escalations = []
        authoritative_failure = seen_rules & {"local_dkim_failure", "verified_dmarc_failure", "trusted_spf_failure"}
        spoof = seen_rules & {"display_name_impersonation", "sender_homograph"}
        if authoritative_failure and spoof:
            score = max(score, 75)
            escalations.append({"rule": "verified_auth_failure_with_spoof", "floor": 75, "reason": "Verified authentication failure accompanies independent sender impersonation evidence.", "evidence_rules": sorted(authoritative_failure | spoof)})
        for finding in findings:
            if finding.get("rule") == "attachment_hash_blocklist" or finding.get("rule") == "attachment_static_critical":
                score = max(score, 75)
                escalations.append({"rule": "dangerous_attachment_escalation", "floor": 75, "reason": "Known blocked hash or executable/critical attachment requires high-risk handling.", "evidence_rule": finding["rule"]})
        direct_deception_rules = {
            str(finding.get("rule", ""))
            for finding in findings
            if str(finding.get("severity", "info")).lower() in {"medium", "high", "critical"}
        } & {"visible_href_mismatch", "idn_or_mixed_script", "ssrf_internal_destination"}
        if direct_deception_rules:
            score = max(score, 50)
            escalations.append({"rule": "direct_url_deception_escalation", "floor": 50,
                                "reason": "A direct link-deception or unsafe-destination rule requires review.",
                                "evidence_rules": sorted(direct_deception_rules)})
        contributions.extend(escalations)
        actionable = [f for f in findings if f.get("severity", "info").lower() != "info"]
        labels = {str(f.get("category", "")).lower() for f in actionable}
        strong = [f for f in actionable if f.get("rule") not in {"calibrated_ml_review"} and f.get("severity", "info").lower() in {"medium", "high", "critical"}]
        strong_labels = {str(f.get("category", "")).lower() for f in strong}
        if any(str(f.get("category", "")).lower() == "attachment" and f.get("severity") in {"high", "critical"} for f in actionable):
            classification = "Malware delivery"
        elif "bec" in strong_labels or {"text", "sender identity"}.issubset(strong_labels) and "financial_fraud" in active:
            classification = "Business Email Compromise"
        elif "url" in strong_labels or "authentication" in strong_labels:
            classification = "Credential phishing" if "credential_harvesting" in active else "Phishing"
        elif score >= 35:
            classification = "Suspicious but inconclusive"
        else:
            classification = "Legitimate or low risk"

        confidence = round(sum(confidence_values) / len(confidence_values), 3) if confidence_values else 0.0
        return {"risk_score": score, "confidence": confidence, "classification": classification, "contributions": contributions, "escalations": escalations}
