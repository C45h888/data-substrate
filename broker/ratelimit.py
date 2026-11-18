"""Exchange rate limiting. In-memory per replica by design.

The broker runs as a single replica behind WireGuard; Nginx remains the
perimeter rate limiter. If a second replica is ever added, these caps must
move to a shared store (see PostgresDecisionAudit-style sink) because
in-memory counters do not coordinate across processes.
"""
from __future__ import annotations

import threading
import time

# Per-credential exchange caps (per minute), on top of the per-IP limiter.
PUBLIC_KEY_RATE_LIMIT = 30
SERVICE_KEY_RATE_LIMIT = 10

# Per-IP exchange caps (per minute).
PUBLIC_IP_RATE_LIMIT = 60
SERVICE_IP_RATE_LIMIT = 10


class IpRateLimit:
    """Single-process guardrail; Nginx remains the perimeter rate limiter."""

    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self.hits: dict[tuple[str, int], int] = {}
        self.lock = threading.Lock()

    def allow(self, ip: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        bucket = int(now // self.window_seconds)
        key = (ip, bucket)
        with self.lock:
            count = self.hits.get(key, 0) + 1
            self.hits[key] = count
            # Bound memory while removing expired windows.
            for old in [item for item in self.hits if item[1] < bucket - 1]:
                self.hits.pop(old, None)
            return count <= self.limit


class DenyCounter:
    """In-memory counters for rate-limit denials (leak/spike signal).

    The decision audit table remains the durable trail; these counters give
    operators a cheap spike signal without a metrics endpoint.
    """

    def __init__(self):
        self.counts: dict[str, int] = {}
        self.lock = threading.Lock()

    def inc(self, detail: str) -> int:
        with self.lock:
            self.counts[detail] = self.counts.get(detail, 0) + 1
            return self.counts[detail]

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return dict(self.counts)


class ExchangeLimiters:
    """The four exchange limiters. Call check() before any credential lookup."""

    def __init__(self):
        self.public_ip = IpRateLimit(PUBLIC_IP_RATE_LIMIT)
        self.service_ip = IpRateLimit(SERVICE_IP_RATE_LIMIT)
        self.public_key = IpRateLimit(PUBLIC_KEY_RATE_LIMIT)
        self.service_key = IpRateLimit(SERVICE_KEY_RATE_LIMIT)
        self.deny_counter = DenyCounter()

    def check(self, kind: str, ip: str, key_id: str) -> str | None:
        """Return the denial detail when a cap trips, else None."""
        limiter = self.public_ip if kind == "public" else self.service_ip
        if not limiter.allow(ip):
            return "rate_limit_ip"
        key_limiter = self.public_key if kind == "public" else self.service_key
        if not key_limiter.allow(key_id):
            return "rate_limit_credential"
        return None
