from __future__ import annotations

import ipaddress
import json
import hashlib
import math
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import requests


class IPIntelligenceProvider:
    """Optional IP intelligence provider with safe unavailable behavior."""

    def __init__(self, endpoint: str | None = None, timeout: float | None = None, cache_dir: str | None = None):
        self.api_key = os.getenv("NETRA_IPSTACK_API_KEY", "").strip()
        self.ipstack = endpoint is None and bool(self.api_key)
        self.endpoint = (endpoint if endpoint is not None else os.getenv("NETRA_IP_INTEL_URL", "https://ipwho.is")).strip()
        if self.ipstack:
            self.endpoint = "https://api.ipstack.com"
        self.timeout = timeout or float(os.getenv("NETRA_INTEL_TIMEOUT_SECONDS", "3"))
        self.cache_dir = Path(cache_dir or os.getenv("NETRA_INTEL_CACHE_DIR", "data/intelligence_cache"))
        self.cache_dir = self.cache_dir / hashlib.sha256(self.endpoint.encode()).hexdigest()[:16]
        self.cache: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _fresh(result):
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(result["looked_up_at"])).total_seconds()
            return 0 <= age < (3600 if result.get("available") else 30)
        except (KeyError, TypeError, ValueError):
            return False

    @staticmethod
    def _base(ip: str) -> Dict[str, Any]:
        return {"ip": ip, "available": False, "source": "unconfigured", "confidence": 0.0, "looked_up_at": datetime.now(timezone.utc).isoformat(), "country": None, "region": None, "city": None, "latitude": None, "longitude": None, "asn": None, "isp": None, "organization": None, "hosting_provider": None, "cloud_provider": None, "vpn": None, "proxy": None, "tor": None, "limitation": "The location represents the registered or inferred network location of the IP address. It does not prove the physical location of the sender."}

    @classmethod
    def _classify(cls, ip: str) -> str:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return "invalid"
        if address.is_loopback:
            return "loopback"
        if address in ipaddress.ip_network("192.0.2.0/24") or address in ipaddress.ip_network("198.51.100.0/24") or address in ipaddress.ip_network("203.0.113.0/24") or address in ipaddress.ip_network("2001:db8::/32"):
            return "documentation"
        if address.is_private:
            return "private"
        if address.is_reserved:
            return "reserved"
        if getattr(address, "is_link_local", False):
            return "link_local"
        if not address.is_global:
            return "special"
        return "public"

    def lookup(self, ip: str) -> Dict[str, Any]:
        result = self._base(str(ip).strip())
        classification = self._classify(result["ip"])
        result["ip_classification"] = classification
        if classification != "public":
            result["source"] = "local_validation"
            result["limitation"] = "Private, reserved, loopback, or special-use addresses are not geolocated. Network location does not prove the sender's physical location."
            return result
        if result["ip"] in self.cache and self._fresh(self.cache[result["ip"]]):
            return dict(self.cache[result["ip"]])
        if len(self.cache) >= 2048:
            self.cache.clear()
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            cache_path = self.cache_dir / f"{result['ip'].replace(':', '_')}.json"
            if cache_path.exists() and cache_path.stat().st_size <= 65536:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                if isinstance(cached, dict) and cached.get("ip") == result["ip"] and self._fresh(cached):
                    self.cache[result["ip"]] = cached
                    return dict(cached)
        except Exception:
            cache_path = None
        if not self.endpoint:
            result["reason"] = "IP lookup service disabled by configuration."
            self.cache[result["ip"]] = result
            return result
        try:
            options = {"timeout": self.timeout, "allow_redirects": False}
            if self.ipstack:
                options["params"] = {"access_key": self.api_key}
            response = requests.get(self.endpoint.rstrip("/") + "/" + result["ip"], **options)
            if 300 <= response.status_code < 400:
                raise ValueError("Provider redirects are not permitted")
            if response.status_code == 429:
                result["source"] = "provider_rate_limited"
                result["reason"] = "IP lookup provider rate limit reached. Retry later or configure your own provider."
                self.cache[result["ip"]] = result
                return result
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Provider response must be an object")
            if data.get("success") is False:
                if self.ipstack:
                    error = data.get("error")
                    code = error.get("code") if isinstance(error, dict) else None
                    result["source"] = "provider_rate_limited" if code == 104 else "provider_configuration_error"
                    result["provider"] = "ipstack"
                    result["reason"] = {101: "The ipstack API key is invalid or inactive.", 104: "The ipstack monthly lookup allowance has been reached.", 105: "The requested feature is unavailable on this ipstack plan.", 103: "This ipstack request is not supported by the account."}.get(code, "ipstack rejected the lookup. Check the account configuration.")
                    self.cache[result["ip"]] = result
                    return result
                raise ValueError(str(data.get("message") or "Provider could not locate this IP")[:200])
            if data.get("ip") and ipaddress.ip_address(str(data["ip"])) != ipaddress.ip_address(result["ip"]):
                raise ValueError("Provider returned a different IP")
            connection = data.get("connection") or {}
            if self.ipstack:
                security = data.get("security") or {}
                if not isinstance(security, dict) or not isinstance(connection, dict):
                    raise ValueError("Malformed ipstack modules")
                data = {**data, "country": data.get("country_name"), "region": data.get("region_name"),
                        "vpn": security.get("is_vpn"), "proxy": security.get("is_proxy"), "tor": security.get("is_tor")}
                result["provider"] = "ipstack"
                result["network_details_available"] = bool(connection)
                result["security_details_available"] = bool(security)
                result["plan_note"] = "Network and VPN/proxy details were not returned by this provider response; missing fields mean unknown." if not connection or not security else ""
            if isinstance(connection, dict):
                data = {**data, "asn": data.get("asn", connection.get("asn")), "isp": data.get("isp", connection.get("isp")), "organization": data.get("organization", connection.get("org"))}
            result.update({key: data.get(key) for key in ("country", "region", "city", "latitude", "longitude", "asn", "isp", "organization", "hosting_provider", "cloud_provider", "vpn", "proxy", "tor") if key in data})
            for field, limit in (("latitude", 90), ("longitude", 180)):
                value = result.get(field)
                try:
                    number = float(value)
                    result[field] = number if not isinstance(value, bool) and math.isfinite(number) and abs(number) <= limit else None
                except (ValueError, TypeError):
                    result[field] = None
            result["location_available"] = result.get("latitude") is not None and result.get("longitude") is not None
            for flag in ("vpn", "proxy", "tor"):
                result[flag] = data.get(flag) if isinstance(data.get(flag), bool) else None
            result["available"] = any(result.get(key) is not None for key in ("country", "asn", "isp", "organization", "latitude"))
            result["source"] = os.getenv("NETRA_IP_INTEL_SOURCE", "ipwho.is" if self.endpoint.rstrip("/") == "https://ipwho.is" else "configured_provider")
            if self.ipstack:
                result["source"] = "ipstack"
            result["confidence"] = float(data.get("confidence", 0.5))
            result["confidence"] = max(0.0, min(1.0, result["confidence"])) if math.isfinite(result["confidence"]) else 0.0
            result["looked_up_at"] = datetime.now(timezone.utc).isoformat()
            if cache_path:
                try:
                    cache_path.write_text(json.dumps(result), encoding="utf-8")
                except OSError:
                    pass
        except (requests.RequestException, TimeoutError, ValueError, TypeError):
            result.update(available=False, location_available=False, latitude=None, longitude=None)
            result["source"] = "provider_unavailable"
            result["reason"] = "The lookup provider could not return usable data (network, response or service error)."
        self.cache[result["ip"]] = result
        return result
