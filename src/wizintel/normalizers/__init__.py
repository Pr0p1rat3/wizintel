"""Normalization helpers."""

from __future__ import annotations

from collections.abc import Iterable

from wizintel.normalizers.domains import normalize_domain
from wizintel.normalizers.emails import normalize_email
from wizintel.normalizers.hosts import normalize_url
from wizintel.normalizers.secrets import normalize_secret_finding
from wizintel.normalizers.usernames import normalize_username
from wizintel.schemas.finding import Finding

__all__ = [
    "deduplicate_findings",
    "normalize_domain",
    "normalize_email",
    "normalize_secret_finding",
    "normalize_url",
    "normalize_username",
]


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Deduplicate findings using normalized values and source where appropriate."""
    seen: set[tuple[str, str, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        normalized_value = _normalized_value(finding)
        source = (
            finding.source
            if finding.finding_type in {"secret_exposure", "username_profile"}
            else ""
        )
        key = (finding.finding_type, normalized_value, source)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _normalized_value(finding: Finding) -> str:
    if finding.finding_type in {"domain", "subdomain", "host"}:
        return normalize_domain(finding.value)
    if finding.finding_type == "email":
        return normalize_email(finding.value)
    if finding.finding_type == "username_profile":
        return normalize_url(finding.value)
    if finding.finding_type == "secret_exposure":
        return str(finding.evidence.get("fingerprint") or finding.redacted_value or finding.value)
    return finding.value.strip().lower()
