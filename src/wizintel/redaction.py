"""Redaction helpers."""

from __future__ import annotations

import math
import re

ASSIGNMENT_TOKEN_RE = re.compile(
    r"(?P<prefix>\b[A-Za-z0-9_.-]*(?:token|secret|api[_-]?key|key|password|pass|auth)"
    r"[A-Za-z0-9_.-]*\s*=\s*)"
    r"(?P<token>[A-Za-z0-9][A-Za-z0-9_.-]{19,})",
    re.IGNORECASE,
)
TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_.=-])([A-Za-z0-9][A-Za-z0-9_.=-]{19,})(?![A-Za-z0-9_.=-])"
)


def redact_email(email: str, *, mask_local: bool = True) -> str:
    """Redact an email local-part when requested."""
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if not mask_local:
        return f"{local}@{domain.lower()}"
    if not local:
        return f"***@{domain.lower()}"
    return f"{local[0]}***@{domain.lower()}"


def redact_secret(secret: str) -> str:
    """Redact a secret, preserving only first and last 4 characters when length allows."""
    cleaned = secret.strip()
    if len(cleaned) >= 12:
        return f"{cleaned[:4]}...{cleaned[-4:]}"
    if cleaned:
        return "[redacted]"
    return ""


def redact_token_like_strings(text: str) -> str:
    """Redact long high-entropy token-like strings in text."""

    def replace_assignment(match: re.Match[str]) -> str:
        candidate = match.group("token")
        if _shannon_entropy(candidate) >= 3.5:
            return f"{match.group('prefix')}{redact_secret(candidate)}"
        return match.group(0)

    def replace_bare(match: re.Match[str]) -> str:
        candidate = match.group(1)
        if _shannon_entropy(candidate) >= 3.5:
            return redact_secret(candidate)
        return candidate

    redacted = ASSIGNMENT_TOKEN_RE.sub(replace_assignment, text)
    return TOKEN_RE.sub(replace_bare, redacted)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())
