"""Host and URL normalization."""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse


def normalize_url(value: str) -> str:
    """Normalize URL scheme and host while preserving path."""
    candidate = value.strip()
    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    scheme = parsed.scheme.lower() or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    return urlunparse((scheme, netloc, path, "", "", ""))
