"""Email normalization."""

from __future__ import annotations


def normalize_email(value: str) -> str:
    """Normalize an email address for deduplication."""
    return value.strip().lower()
