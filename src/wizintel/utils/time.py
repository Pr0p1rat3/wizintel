"""Time helpers."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def utc_timestamp_slug() -> str:
    """Return a compact timestamp suitable for case IDs."""
    return utc_now().strftime("%Y%m%d_%H%M%S")
