"""Bounded HTTPS transport for explicitly enabled intelligence services."""
import copy
import ipaddress
import json
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
import requests


class LookupError(Exception):
    pass


class Transport:
    def __init__(self):
        self.session = requests.Session()
        self.session.trust_env = False
        self.cache = {}

    def get(self, url, *, params=None, payload=None, headers=None, text=False, ttl=3600):
        # Destinations come only from fixed provider URLs or the IANA bootstrap.
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.port not in (None, 443):
            raise LookupError("invalid_endpoint")
        key = (url, repr(params), repr(payload), repr(headers), text)
        cached = self.cache.get(key)
        if cached and time.monotonic() < cached[0]:
            if cached[1] != "ok":
                raise LookupError(cached[1])
            return copy.deepcopy(cached[2])
        response = None
        if len(self.cache) >= 512:
            self.cache.clear()
        try:
            addresses = socket.getaddrinfo(parts.hostname, 443, type=socket.SOCK_STREAM)
            if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
                raise LookupError("invalid_endpoint")
            response = self.session.request("POST" if payload is not None else "GET", url,
                params=params, json=payload, headers=headers, timeout=(2, 4), stream=True, allow_redirects=False)
            if response.status_code == 429:
                raise LookupError("rate_limited")
            if response.status_code in (401, 403):
                raise LookupError("credential_or_permission_required")
            if response.status_code == 404:
                raise LookupError("not_found")
            if response.status_code != 200:
                raise LookupError("provider_unavailable")
            raw = bytearray()
            deadline = time.monotonic() + 5
            for chunk in response.iter_content(16384):
                raw.extend(chunk)
                if len(raw) > 2 * 1024 * 1024 or time.monotonic() > deadline:
                    raise LookupError("response_budget_exceeded")
            value = raw.decode("utf-8") if text else json.loads(raw)
            if not text and not isinstance(value, dict):
                raise LookupError("malformed_response")
            if isinstance(value, dict):
                value["_netra_retrieved_at"] = datetime.now(timezone.utc).isoformat()
            if len(self.cache) >= 512:
                self.cache.clear()
            self.cache[key] = (time.monotonic() + ttl, "ok", value)
            return copy.deepcopy(value)
        except LookupError as exc:
            self.cache[key] = (time.monotonic() + 60, str(exc), None)
            raise
        except (requests.RequestException, OSError, ValueError, TypeError):
            self.cache[key] = (time.monotonic() + 60, "provider_unavailable", None)
            raise LookupError("provider_unavailable") from None
        finally:
            if response is not None:
                response.close()


transport = Transport()
