"""Prometheus metrics for Agent Guard."""

from __future__ import annotations

from prometheus_client import Counter, Histogram, generate_latest

REQUESTS_TOTAL = Counter(
    "agent_guard_requests_total",
    "Total proxied requests",
    ["provider", "path"],
)

DECISIONS_TOTAL = Counter(
    "agent_guard_decisions_total",
    "Policy decisions by action",
    ["action", "rule_id"],
)

REQUEST_LATENCY = Histogram(
    "agent_guard_request_duration_seconds",
    "End-to-end request latency in seconds",
    ["provider"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

BLOCKED_TOTAL = Counter(
    "agent_guard_blocked_total",
    "Requests blocked by policy",
    ["rule_id"],
)


def get_metrics_text() -> bytes:
    """Return the current Prometheus metrics as bytes (text/plain)."""
    return generate_latest()
