"""Username normalization."""

from __future__ import annotations


def normalize_username(value: str) -> str:
    """Normalize a username handle."""
    return value.strip().lstrip("@").lower()
