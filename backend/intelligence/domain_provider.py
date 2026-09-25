from __future__ import annotations

import ipaddress
import os
import re
import time
import copy
from datetime import datetime, timezone
from typing import Any, Dict, List

try:
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None

from backend.domain_intel import DomainForensics


class DomainIntelligenceProvider:
    """Best-effort DNS enrichment with bounded resolver timeouts."""

    RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")

    def __init__(self, timeout: float | None = None, resolver: Any | None = None):
        self.timeout = timeout or float(os.getenv("NETRA_DNS_TIMEOUT_SECONDS", "2"))
        self.resolver = resolver
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_times: Dict[str, float] = {}

    @staticmethod
    def _registered(domain: str) -> str:
        return DomainForensics._registered_domain(domain)

    @staticmethod
    def _mixed_script(domain: str) -> bool:
        scripts = {"ascii" if all(ord(char) < 128 for char in label) else "non_ascii" for label in domain.split(".") if label}
        return len(scripts) > 1

    def inspect(self, domain: str, source: str = "unknown", related_ips: List[str] | None = None) -> Dict[str, Any]:
        normalized = DomainForensics._normalize_domain(domain)
        if not normalized:
            return {"domain": "", "valid": False, "source": source, "records": {}, "findings": [], "limitations": ["No valid domain was provided."]}
        # Source and related IPs affect findings and must be part of the key.
        cache_key = (normalized, source, tuple(sorted(related_ips or [])))
        if cache_key in self.cache and time.monotonic() - self.cache_times.get(cache_key, 0) < 300:
            return copy.deepcopy(self.cache[cache_key])
        is_punycode = "xn--" in normalized or any(ord(char) > 127 for char in normalized)
        brands = DomainForensics.detect_brand_impersonation(normalized)
        typosquatting = DomainForensics.detect_typosquatting(normalized)
        base = {"domain": normalized, "source": source, "valid": True, "registered_domain": self._registered(normalized), "is_punycode": is_punycode, "has_suspicious_tld": any(normalized.endswith(tld) for tld in DomainForensics.SUSPICIOUS_TLDS), "impersonated_brands": brands, "typosquatting": typosquatting, "resolves": False, "resolved_ip": None, "risk_score": 0, "risk_level": "LOW", "reasons": []}
        result = {**base, "subdomain": normalized[:-len(base["registered_domain"])].rstrip("."), "records": {record: [] for record in self.RECORD_TYPES}, "resolved_ips": [], "lookup_source": "local_dns", "lookup_timestamp": datetime.now(timezone.utc).isoformat(), "lookup_available": False, "findings": [], "limitations": ["DNS data is time-dependent and does not prove ownership or malicious intent."]}
        resolver = self.resolver
        deadline = time.monotonic() + min(max(self.timeout, 0.1), 3.0)
        if resolver is None and dns is not None:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
        if resolver is not None:
            for record_type in self.RECORD_TYPES:
                try:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("DNS budget exhausted")
                    if self.resolver is None:
                        answers = resolver.resolve(normalized, record_type, lifetime=remaining)
                    else:
                        answers = resolver.resolve(normalized, record_type)
                    values = [
                        (b"".join(answer.strings).decode("utf-8", errors="replace") if record_type == "TXT" and hasattr(answer, "strings") else str(answer).rstrip("."))
                        for answer in list(answers)[:100]
                    ]
                    result["records"][record_type] = values
                    result["lookup_available"] = True
                except Exception:
                    result["records"][record_type] = []
        result["resolved_ips"] = result["records"]["A"] + result["records"]["AAAA"]
        result["spf"] = [value for value in result["records"]["TXT"] if value.lower().startswith("v=spf1")]
        result["records"]["SPF"] = result["spf"]
        dmarc = []
        if resolver is not None:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("DNS budget exhausted")
                answers = resolver.resolve("_dmarc." + normalized, "TXT", lifetime=remaining) if self.resolver is None else resolver.resolve("_dmarc." + normalized, "TXT")
                dmarc = [b"".join(answer.strings).decode("utf-8", errors="replace") if hasattr(answer, "strings") else str(answer).rstrip(".") for answer in list(answers)[:100]]
            except Exception:
                dmarc = []
        result["dmarc"] = dmarc
        if "xn--" in normalized or any(ord(char) > 127 for char in normalized):
            result["findings"].append({"category": "Infrastructure", "rule": "punycode_domain", "severity": "medium", "confidence": 0.9, "title": "Punycode or internationalized domain detected", "description": "The domain uses IDN encoding that can support lookalike presentation.", "evidence": {"domain": normalized}, "limitations": ["Internationalized domains can be legitimate."]})
        if self._mixed_script(normalized):
            result["findings"].append({"category": "Infrastructure", "rule": "mixed_script_domain", "severity": "medium", "confidence": 0.86, "title": "Mixed-script domain detected", "description": "The domain contains ASCII and non-ASCII labels.", "evidence": {"domain": normalized}, "limitations": ["Mixed scripts are not by themselves proof of abuse."]})
        if not result["records"]["MX"]:
            result["findings"].append({"category": "Infrastructure", "rule": "missing_mx", "severity": "info", "confidence": 0.72, "title": "Domain has no observed MX record", "description": "No MX record was observed during the bounded lookup.", "evidence": {"domain": normalized}, "limitations": ["DNS failures, split-horizon DNS, or non-mail domains can explain a missing MX record."]})
        if related_ips:
            observed = {str(value) for value in result["resolved_ips"]}
            unrelated = [value for value in related_ips if value and value not in observed]
            if observed and unrelated:
                result["findings"].append({"category": "Infrastructure", "rule": "ip_domain_inconsistency", "severity": "info", "confidence": 0.7, "title": "Mail delivery and website use different infrastructure", "description": "Mail servers and website servers often have different IP addresses. This comparison does not establish a threat and adds no risk points.", "evidence": {"domain_ips": sorted(observed), "observed_ips": unrelated}, "limitations": ["Mail providers, proxies, CDNs, and changing DNS can make this relationship legitimate."]})
        if len(self.cache) >= 1024:
            self.cache.clear()
            self.cache_times.clear()
        self.cache[cache_key] = copy.deepcopy(result)
        self.cache_times[cache_key] = time.monotonic()
        return result
