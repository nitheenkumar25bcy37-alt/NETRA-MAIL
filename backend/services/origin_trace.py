from __future__ import annotations

from typing import Any, Dict, List
from uuid import uuid4


class OriginTraceService:
    """Reconstruct observed relay evidence without claiming human attribution."""

    LIMITATIONS = [
        "Received headers may be incomplete or modified by upstream systems.",
        "The IP does not identify the human sender.",
        "The oldest observed public hop is a candidate, not a definitive origin.",
    ]

    @classmethod
    def build(cls, parsed: Dict[str, Any], ip_provider: Any | None = None) -> Dict[str, Any]:
        hops = parsed.get("network_chain", []) or []
        candidates: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        lookups = {}
        for hop in reversed(hops):
            for ip, classification in zip(hop.get("extracted_ips", []), hop.get("ip_classifications", [])):
                if classification != "public":
                    continue
                first = not candidates
                candidate = {"ip": ip, "position": hop.get("hop_index"), "confidence": 0.72 if first and not hop.get("malformed") and not hop.get("timestamp_anomaly") else 0.48, "basis": ["Public address", "Observed in Received chain"], "hostname": hop.get("source_hostname"), "timestamp": hop.get("timestamp"), "limitations": list(cls.LIMITATIONS)}
                if first:
                    candidate["basis"].append("Oldest reliable observed hop" if candidate["confidence"] >= 0.7 else "Oldest observed public hop")
                else:
                    candidate["basis"].append("Additional public relay candidate")
                if hop.get("source_hostname"):
                    candidate["basis"].append("Source hostname preserved")
                if ip_provider is not None:
                    if ip not in lookups:
                        lookups[ip] = ip_provider.lookup(ip) if len(lookups) < 4 else {"ip": ip, "available": False, "source": "lookup_budget", "reason": "Per-analysis lookup budget reached; use the dashboard to enrich this relay."}
                    candidate["intelligence"] = lookups[ip]
                    intelligence = candidate["intelligence"]
                    if intelligence.get("cloud_provider") or intelligence.get("hosting_provider"):
                        findings.append({"finding_id": str(uuid4()), "category": "Infrastructure", "rule": "cloud_or_hosting_infrastructure", "severity": "low", "confidence": 0.7, "title": "Cloud or hosting infrastructure observed", "description": "The candidate IP is associated with hosting or cloud infrastructure.", "evidence": {"ip": ip, "cloud_provider": intelligence.get("cloud_provider"), "hosting_provider": intelligence.get("hosting_provider")}, "limitations": ["Cloud hosting is common for legitimate services and is not evidence of maliciousness by itself."]})
                    if intelligence.get("vpn") or intelligence.get("proxy") or intelligence.get("tor"):
                        findings.append({"finding_id": str(uuid4()), "category": "Infrastructure", "rule": "anonymization_indicator", "severity": "medium", "confidence": 0.75, "title": "Anonymization infrastructure indicator observed", "description": "The configured provider reported a VPN, proxy, or Tor indicator for the candidate IP.", "evidence": {"ip": ip, "vpn": intelligence.get("vpn"), "proxy": intelligence.get("proxy"), "tor": intelligence.get("tor")}, "limitations": ["Provider classifications can be incomplete or stale and do not identify the operator."]})
                candidates.append(candidate)
        reliability = [{"hop": hop.get("hop_index"), "reliable": not hop.get("malformed") and not hop.get("timestamp_anomaly"), "reasons": [reason for reason, present in (("Malformed relay syntax", hop.get("malformed")), ("Missing or invalid timestamp", hop.get("timestamp_anomaly"))) if present] or ["Expected relay fields were parsed"]} for hop in hops]
        return {"hops": hops, "hop_reliability": reliability, "origin_candidates": candidates, "findings": findings, "conclusion": "This is the probable earliest observed sending infrastructure." if candidates else "No reliable public origin candidate was observed.", "limitations": list(cls.LIMITATIONS)}
