"""Timestamped observations, never behavioural botnet detection or attribution."""
import os
import re
import time
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit
from backend.intelligence.registration import instant, enabled, registration_domain
from backend.intelligence.transport import transport, LookupError
from backend.intelligence.ip_provider import IPIntelligenceProvider


class InfrastructureReputation:
    def __init__(self, client=None):
        self.client = client or transport

    def lookup(self, parsed):
        now = datetime.now(timezone.utc)
        result = {"checked_at": now.isoformat(), "observations": [], "lookups": [],
            "limitations": ["No match means unknown, not safe. Feed matches require review and are not behavioural botnet detection.",
                "VPN/Tor use, geography and shared infrastructure do not identify an attacker.",
                "Email Date headers are sender-supplied; temporal comparisons are context, not proof."]}
        email_time = instant((parsed.get("metadata") or {}).get("date"))
        if email_time is None:
            try:
                email_time = parsedate_to_datetime((parsed.get("metadata") or {}).get("date", ""))
                if email_time.tzinfo is None:
                    email_time = email_time.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError, IndexError):
                pass
        def observation(indicator, kind, source, evidence, observed, expires):
            fresh = bool(observed and expires and observed <= now <= expires)
            result["observations"].append({"indicator": indicator, "kind": kind, "source": source,
                "retrieved_at": now.isoformat(), "observed_at": observed.isoformat() if observed else None,
                "expires_at": expires.isoformat() if expires else None, "freshness": "fresh" if fresh else "expired_or_unknown",
                "email_time": email_time.isoformat() if email_time else None,
                "email_time_within_observation_window": bool(email_time and observed and expires and observed <= email_time <= expires),
                "review_status": "needs_review", "evidence": evidence})
        ips = sorted({x.get("ip") for x in parsed.get("ip_intelligence", []) if IPIntelligenceProvider._classify(str(x.get("ip", ""))) == "public"})[:4]
        for item in parsed.get("ip_intelligence", [])[:4]:
            for flag in ("vpn", "proxy", "tor"):
                if item.get(flag) is True and item.get("ip") in ips:
                    observed = instant(item.get("looked_up_at"))
                    observation(item["ip"], flag, item.get("source"), {"provider_classification": True}, observed, observed + timedelta(hours=1) if observed else None)
        if enabled("NETRA_TOR_ENABLED"):
            state = {"source": "Tor Project exit-addresses", "status": "unavailable"}
            try:
                data = self.client.get("https://check.torproject.org/exit-addresses", text=True, ttl=900)
                valid_rows = 0
                for line in data.splitlines():
                    parts = line.split()
                    if len(parts) == 4 and parts[0] == "ExitAddress":
                        observed = instant(parts[2] + "T" + parts[3] + "+00:00")
                        if observed and IPIntelligenceProvider._classify(parts[1]) == "public":
                            valid_rows += 1
                            if parts[1] in ips:
                                observation(parts[1], "tor_exit_observation", state["source"], {"exit_address": parts[1]}, observed, observed + timedelta(hours=24))
                state["status"] = "ok" if valid_rows else "malformed_response"
            except (LookupError, AttributeError, TypeError) as exc:
                state["status"] = str(exc) if isinstance(exc, LookupError) else "malformed_response"
            result["lookups"].append(state)
        else:
            result["lookups"].append({"source": "Tor Project", "status": "disabled"})
        key = os.getenv("NETRA_THREATFOX_AUTH_KEY", "")
        if not enabled("NETRA_THREATFOX_ENABLED") or not key:
            result["lookups"].append({"source": "ThreatFox", "status": "credential_required" if enabled("NETRA_THREATFOX_ENABLED") else "disabled"})
            return result
        domains = []
        for item in (parsed.get("domain_intelligence") or {}).get("domains", []):
            domain = item.get("domain", "").lower()
            if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", domain) and registration_domain(domain):
                domains.append(domain)
        # Disclose only public IPs and bare public domains, never URL tokens or mail content.
        deadline = time.monotonic() + 12
        for indicator in list(dict.fromkeys(ips + domains))[:6]:
            state = {"source": "ThreatFox", "indicator": indicator, "status": "budget_exhausted"}
            result["lookups"].append(state)
            if time.monotonic() >= deadline:
                continue
            try:
                data = self.client.get("https://threatfox-api.abuse.ch/api/v1/", payload={"query": "search_ioc", "search_term": indicator, "exact_match": True}, headers={"Auth-Key": key}, ttl=900)
                state["status"] = data.get("query_status", "malformed_response")
                if state["status"] != "ok":
                    continue
                rows = data.get("data")
                if not isinstance(rows, list):
                    raise LookupError("malformed_response")
                for row in rows[:50]:
                    ioc = str(row.get("ioc", ""))
                    kind = row.get("ioc_type")
                    host = ioc
                    if kind == "ip:port":
                        host = urlsplit("//" + ioc).hostname
                    if kind not in {"ip:port", "domain"} or host != indicator:
                        continue
                    observed = instant(row.get("last_seen") or row.get("first_seen"))
                    observation(indicator, "malware_infrastructure_reputation", "ThreatFox", {"ioc": ioc, "ioc_type": kind, "threat_type": row.get("threat_type"), "malware": row.get("malware"), "reference": row.get("reference"), "first_seen": row.get("first_seen")}, observed, observed + timedelta(days=30) if observed else None)
            except (LookupError, ValueError, TypeError, AttributeError) as exc:
                state["status"] = str(exc) if isinstance(exc, LookupError) else "malformed_response"
        return result
