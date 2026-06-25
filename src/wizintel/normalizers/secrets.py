"""Secret finding normalization."""

from __future__ import annotations

import hashlib
from typing import Any

from wizintel.redaction import redact_secret


def fingerprint_secret(value: str) -> str:
    """Create a non-reversible short fingerprint for a secret."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


def normalize_secret_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract safe secret metadata from raw tool output."""
    secret = str(raw.get("Raw") or raw.get("RawV2") or raw.get("Secret") or "")
    detector = str(raw.get("DetectorName") or raw.get("detector") or "unknown")
    verified = bool(raw.get("Verified") or raw.get("verified") or False)
    fingerprint = fingerprint_secret(secret) if secret else ""
    return {
        "secret_type": detector,
        "verified": verified,
        "redacted_secret": redact_secret(secret) if secret else "",
        "fingerprint": fingerprint,
    }
