"""Domain normalization."""

from __future__ import annotations

from urllib.parse import urlparse


def normalize_domain(value: str) -> str:
    """Normalize a domain or host string."""
    candidate = value.strip().lower()
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or candidate
    candidate = candidate.strip(" .")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if "/" in candidate:
        candidate = candidate.split("/", 1)[0]
    if ":" in candidate and not candidate.count(":") > 1:
        candidate = candidate.split(":", 1)[0]
    return candidate.rstrip(".")
