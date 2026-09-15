"""Bounded, opt-in URL reputation using fixed maintained-provider endpoints."""
from datetime import datetime, timezone
import os
import time
from urllib.parse import urlsplit

import requests


class URLReputationProvider:
    def __init__(self, session=None, enabled=None, google_key=None, urlhaus_key=None):
        self.session = session or requests.Session()
        self.session.trust_env = False
        self.enabled = enabled if enabled is not None else os.getenv("NETRA_URL_REPUTATION_ENABLED", "false").lower() in {"1", "true", "yes"}
        self.google_key = google_key if google_key is not None else os.getenv("NETRA_GOOGLE_SAFE_BROWSING_KEY", "")
        self.urlhaus_key = urlhaus_key if urlhaus_key is not None else os.getenv("NETRA_URLHAUS_AUTH_KEY", "")
        self.cache = {}

    @staticmethod
    def _valid(url):
        try:
            parsed = urlsplit(url)
            return parsed.scheme in {"http", "https"} and bool(parsed.hostname) and not parsed.username and not parsed.password and len(url) <= 2048
        except ValueError:
            return False

    @staticmethod
    def _json(response, limit=262144):
        import json
        try:
            if 300 <= response.status_code < 400: raise ValueError("Redirect rejected")
            response.raise_for_status()
            raw = bytearray()
            deadline = time.monotonic() + 6
            for chunk in response.iter_content(16384):
                raw.extend(chunk)
                if len(raw) > limit or time.monotonic() > deadline:
                    raise ValueError("Provider response exceeded budget")
            value = json.loads(raw)
        finally:
            response.close()
        if not isinstance(value, dict): raise ValueError("Provider response invalid")
        return value

    def lookup(self, urls):
        urls = list(dict.fromkeys(url for url in urls if self._valid(url)))[:20]
        result = {"enabled": self.enabled, "checked_at": datetime.now(timezone.utc).isoformat(), "results": [],
            "limitations": ["URLs are disclosed to enabled reputation providers. Provider silence does not prove safety."]}
        if not self.enabled: return result
        deadline = time.monotonic() + 20
        pending = [url for url in urls if url not in self.cache or time.monotonic() - self.cache[url][0] > 900]
        verdicts = {url: {"url": url, "malicious": False, "providers": [], "available": False} for url in urls}
        if pending and self.google_key:
            try:
                data = self._json(self.session.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                    params={"key": self.google_key}, json={"client": {"clientId": "netra-mail", "clientVersion": "4.4.0"},
                    "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url} for url in pending]}},
                    timeout=(3, 6), allow_redirects=False, stream=True))
                for url in pending: verdicts[url]["available"] = True
                for match in data.get("matches", [])[:100]:
                    url = (match.get("threat", {}) or {}).get("url")
                    if url in verdicts:
                        verdicts[url].update(malicious=True)
                        verdicts[url]["providers"].append({"provider": "Google Safe Browsing", "threat_type": match.get("threatType")})
            except (requests.RequestException, ValueError, TypeError): pass
        for url in pending:
            if not self.urlhaus_key or time.monotonic() >= deadline:
                self.cache[url] = (time.monotonic(), verdicts[url])
                continue
            try:
                data = self._json(self.session.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                    headers={"Auth-Key": self.urlhaus_key}, timeout=(3, 6), allow_redirects=False, stream=True))
                if data.get("query_status") in {"ok", "no_results"}:
                    verdicts[url]["available"] = True
                if data.get("query_status") == "ok":
                    verdicts[url]["malicious"] = True
                    verdicts[url]["providers"].append({"provider": "URLhaus", "status": data.get("url_status")})
            except (requests.RequestException, ValueError, TypeError): pass
            self.cache[url] = (time.monotonic(), verdicts[url])
        for url in urls:
            if url in self.cache and url not in pending: verdicts[url] = dict(self.cache[url][1])
        result["results"] = list(verdicts.values())
        result["findings"] = [{"category": "URL", "rule": "maintained_reputation_match", "severity": "critical", "confidence": 0.98,
            "title": "URL is listed by a maintained threat-intelligence provider", "description": "A configured reputation provider identified this exact URL.",
            "evidence": item, "limitations": result["limitations"]} for item in result["results"] if item["malicious"]]
        return result
