from __future__ import annotations

import re
import secrets
import time
from collections import OrderedDict, deque
from threading import Lock
from typing import Deque


class RequestRateLimiter:
    """
    Small process-local sliding-window rate limiter.

    This is suitable for a single local/demo process.

    Production deployment should use a gateway or distributed
    rate limiter such as Redis-backed limiting.
    """

    def __init__(
        self,
        limit: int = 60,
        window_seconds: int = 60,
        max_keys: int = 10_000,
    ):
        self.limit = max(1, int(limit))
        self.window_seconds = max(1, int(window_seconds))
        self.max_keys = max(100, int(max_keys))

        # OrderedDict allows old client keys to be evicted when
        # the in-memory key limit is reached.
        self._events: OrderedDict[str, Deque[float]] = OrderedDict()

        self._lock = Lock()

    def allow(self, key: str) -> bool:
        """
        Return True if the request is allowed.

        Requests are counted using a sliding time window.
        """

        key = str(key or "").strip()

        if not key:
            key = "anonymous"

        now = time.monotonic()

        with self._lock:
            events = self._events.get(key)

            if events is None:
                events = deque()
                self._events[key] = events
            else:
                # Mark recently used keys as most-recently-used.
                self._events.move_to_end(key)

            # Remove expired events.
            cutoff = now - self.window_seconds

            while events and events[0] <= cutoff:
                events.popleft()

            # Reject once the current window is full.
            if len(events) >= self.limit:
                return False

            events.append(now)

            # Bound memory usage when many unique client keys appear.
            self._evict_if_needed()

            return True

    def _evict_if_needed(self) -> None:
        """
        Evict the least-recently-used keys until the configured
        key limit is satisfied.
        """

        while len(self._events) > self.max_keys:
            self._events.popitem(last=False)

    def reset(self) -> None:
        """
        Clear all limiter state.

        Useful for tests and controlled application resets.
        """

        with self._lock:
            self._events.clear()

    def key_count(self) -> int:
        """
        Return the number of tracked keys.

        Primarily useful for diagnostics/tests.
        """

        with self._lock:
            return len(self._events)


# ---------------------------------------------------------------------------
# Identifier validation
# ---------------------------------------------------------------------------

ID_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{1,100}$"
)


def validate_identifier(
    value: str,
    name: str = "identifier",
) -> str:
    """
    Validate identifiers used in API paths.

    Allowed:
        letters
        numbers
        underscore
        hyphen

    Maximum length:
        100 characters
    """

    if not isinstance(value, str):
        raise ValueError(f"Invalid {name}")

    value = value.strip()

    if not ID_PATTERN.fullmatch(value):
        raise ValueError(f"Invalid {name}")

    return value


def valid_api_key(candidate: str | None, expected: str | None) -> bool:
    """Compare a deployment access key in constant time."""
    return bool(candidate and expected and secrets.compare_digest(candidate, expected))


# ---------------------------------------------------------------------------
# Privacy helpers
# ---------------------------------------------------------------------------

def mask_email_address(value: str) -> str:
    """
    Mask the local part of an email address for safe logging.

    Example:
        alice@example.com
        becomes
        a***@example.com
    """

    value = str(value or "")

    if "@" not in value:
        return value

    local, domain = value.split("@", 1)

    if not local:
        return f"***@{domain}"

    return f"{local[:1]}***@{domain}"
