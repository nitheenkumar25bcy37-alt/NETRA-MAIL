"""One human-readable evidence view shared by API, dashboard and exports."""
import json


def infrastructure_view(parsed):
    registrations = [item.get("registration") for item in (parsed.get("domain_intelligence") or {}).get("domains", []) if item.get("registration")]
    networks = parsed.get("ip_intelligence") or []
    reputation = parsed.get("infrastructure_reputation") or {}
    lines = ["Infrastructure observations do not establish the sender's identity or physical location."]
    for item in registrations:
        lines.append(f"Registration for {item.get('domain')}: {item.get('status')}; registrar: {item.get('registrar') or 'Unknown'}; registered: {item.get('registered_at') or 'Unknown'}; expires: {item.get('expires_at') or 'Unknown'}; age in days: {item.get('domain_age_days') if item.get('domain_age_days') is not None else 'Unknown'}.")
        lines.append(f"Registration source: {item.get('source')}; lookup: {item.get('looked_up_at')}; status codes: {item.get('domain_status')}; registration nameservers: {item.get('nameservers')}; redaction: {item.get('redacted')}. These are registration records, separate from live DNS.")
    for item in networks:
        lines.append("Observed server " + str(item.get("ip")) + ": " + "; ".join(f"{field.replace('_', ' ')}: {item.get(field) if item.get(field) is not None else 'Unknown'}" for field in ("country", "region", "city", "asn", "isp", "organization", "hosting_provider", "vpn", "proxy", "tor")))
        lines.append("Field sources and conflicts: " + json.dumps({"fields": item.get("field_provenance"), "network_lookup": item.get("network_enrichment")}, ensure_ascii=False))
    for item in reputation.get("observations", []):
        lines.append(f"Review observation: {item.get('kind')} for {item.get('indicator')} from {item.get('source')}; observed {item.get('observed_at')}; expires {item.get('expires_at')}; {item.get('freshness')}; email-time overlap: {item.get('email_time_within_observation_window')}. Evidence: {json.dumps(item.get('evidence'), ensure_ascii=False)}")
    for lookup in reputation.get("lookups", []):
        lines.append(f"Intelligence service {lookup.get('source')}: {lookup.get('status')}. Absence from a feed does not mean safe.")
    return {"registrations": registrations, "networks": networks, "reputation": reputation, "lines": lines}
