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
        self.endpoint = (endpoint or os.getenv("NETRA_IP_INTEL_URL", "")).strip()
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
            self.cache[result["ip"]] = result
            return result
        try:
            response = requests.get(self.endpoint.rstrip("/") + "/" + result["ip"], timeout=self.timeout, allow_redirects=False)
            if 300 <= response.status_code < 400:
                raise ValueError("Provider redirects are not permitted")
            if response.status_code == 429:
                result["source"] = "provider_rate_limited"
                self.cache[result["ip"]] = result
                return result
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Provider response must be an object")
            result.update({key: data.get(key) for key in ("country", "region", "city", "latitude", "longitude", "asn", "isp", "organization", "hosting_provider", "cloud_provider", "vpn", "proxy", "tor") if key in data})
            for flag in ("vpn", "proxy", "tor"):
                result[flag] = data.get(flag) if isinstance(data.get(flag), bool) else None
            result["available"] = any(result.get(key) is not None for key in ("country", "asn", "isp", "organization", "latitude"))
            result["source"] = os.getenv("NETRA_IP_INTEL_SOURCE", "configured_provider")
            result["confidence"] = float(data.get("confidence", 0.5))
            result["confidence"] = max(0.0, min(1.0, result["confidence"])) if math.isfinite(result["confidence"]) else 0.0
            result["looked_up_at"] = datetime.now(timezone.utc).isoformat()
            if cache_path:
                cache_path.write_text(json.dumps(result), encoding="utf-8")
        except (requests.RequestException, TimeoutError, ValueError, TypeError):
            result["source"] = "provider_unavailable"
        self.cache[result["ip"]] = result
        return result
