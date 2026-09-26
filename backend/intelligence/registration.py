"""Registration records are distinct from DNS and public-suffix parsing."""
import os
import re
from datetime import datetime, timezone
from backend.domain_intel import DomainForensics
from backend.domain_identity import canonical_host
import tldextract
from backend.intelligence.transport import transport, LookupError

_registry_suffixes = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=False)


def registration_domain(domain):
    host = canonical_host(DomainForensics._normalize_domain(domain))
    parsed = _registry_suffixes(host)
    return parsed.top_domain_under_public_suffix if parsed.suffix else ""


def instant(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace(" UTC", "+00:00").replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def enabled(name):
    return os.getenv(name, "false").lower() in {"1", "true", "yes"}


class RegistrationProvider:
    def __init__(self, client=None):
        self.client = client or transport

    def lookup(self, domain):
        now = datetime.now(timezone.utc)
        result = {"domain": domain, "status": "disabled", "source": "IANA RDAP bootstrap",
            "looked_up_at": now.isoformat(), "registrar": None, "registered_at": None,
            "expires_at": None, "domain_age_days": None, "domain_status": [], "nameservers": [],
            "redacted": False, "attempts": [], "limitations": ["Registration does not establish sender identity or safe intent. Missing fields remain unknown."]}
        if not enabled("NETRA_REGISTRATION_ENABLED"):
            return result
        domain = registration_domain(domain)
        if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9-]+(?:\.[a-z0-9-]+)+", domain or ""):
            result["status"] = "unsupported_domain"
            return result
        result["domain"] = domain
        try:
            bootstrap = self.client.get("https://data.iana.org/rdap/dns.json", ttl=86400)
            bases = [url for suffixes, urls in bootstrap.get("services", []) if domain.rsplit(".", 1)[1] in suffixes for url in urls if url.startswith("https://")]
            if not bases:
                raise LookupError("unsupported_domain")
            endpoint = bases[0].rstrip("/") + "/domain/" + domain
            result["source"] = endpoint
            data = self.client.get(endpoint)
            result["retrieved_at"] = data.get("_netra_retrieved_at", result["looked_up_at"])
            if str(data.get("ldhName", "")).lower().rstrip(".") != domain:
                raise LookupError("malformed_response")
            for entity in data.get("entities", [])[:50]:
                if "registrar" in entity.get("roles", []):
                    card = entity.get("vcardArray", [None, []])
                    for row in card[1]:
                        if row[0] == "fn" and isinstance(row[3], str):
                            result["registrar"] = row[3][:300]
            for event in data.get("events", [])[:50]:
                key = {"registration": "registered_at", "expiration": "expires_at"}.get(event.get("eventAction"))
                date = instant(event.get("eventDate"))
                if key and date:
                    result[key] = date.isoformat()
            result["domain_status"] = [str(v)[:100] for v in data.get("status", [])[:30]]
            result["nameservers"] = [v["ldhName"].lower().rstrip(".") for v in data.get("nameservers", [])[:30] if isinstance(v.get("ldhName"), str)]
            result["redacted"] = bool(data.get("redacted")) or "redact" in str(data.get("notices", [])).lower()
            result["status"] = "redacted" if result["redacted"] else "ok"
        except (LookupError, ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
            result["status"] = str(exc) if isinstance(exc, LookupError) else "malformed_response"
        result["attempts"].append({"source": result["source"], "status": result["status"]})
        # Optional licensed HTTPS WHOIS service, never raw port-43 referrals.
        key = os.getenv("NETRA_WHOISXML_API_KEY", "")
        if result["status"] in {"unsupported_domain", "not_found"} and key:
            result["source"] = "WhoisXML API"
            try:
                data = self.client.get("https://www.whoisxmlapi.com/whoisserver/WhoisService", params={"apiKey": key, "domainName": domain, "outputFormat": "JSON"})
                result["retrieved_at"] = data.get("_netra_retrieved_at", result["looked_up_at"])
                record = data.get("WhoisRecord")
                if not isinstance(record, dict) or record.get("domainName", "").lower() != domain:
                    raise LookupError("malformed_response")
                registry = record.get("registryData") or {}
                result["registrar"] = record.get("registrarName")
                for field, source in (("registered_at", "createdDateNormalized"), ("expires_at", "expiresDateNormalized")):
                    date = instant(record.get(source) or registry.get(source))
                    result[field] = date.isoformat() if date else None
                result["nameservers"] = (record.get("nameServers") or registry.get("nameServers") or {}).get("hostNames", [])[:30]
                result["domain_status"] = [str(record.get("status") or registry.get("status"))] if record.get("status") or registry.get("status") else []
                result["status"] = "partial" if not result["registered_at"] else "ok"
            except (LookupError, ValueError, TypeError, AttributeError) as exc:
                result["status"] = str(exc) if isinstance(exc, LookupError) else "malformed_response"
            result["attempts"].append({"source": result["source"], "status": result["status"]})
        registered = instant(result["registered_at"])
        if registered and registered <= now:
            result["domain_age_days"] = (now - registered).days
        elif registered:
            result["registered_at"] = None
            result["status"] = "invalid_registration_date"
        return result
