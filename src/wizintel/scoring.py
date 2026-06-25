"""Deterministic risk scoring."""

from __future__ import annotations

import re

from wizintel.schemas.finding import Finding, Severity

INTERESTING_DEFAULTS = {
    "admin",
    "vpn",
    "portal",
    "dev",
    "test",
    "staging",
    "backup",
    "sso",
    "auth",
    "git",
    "ci",
    "jenkins",
    "grafana",
    "kibana",
}
SENSITIVE_INTERNAL_PATTERN = re.compile(r"(internal|private|corp|credential|secret|prod-admin)")


def score_finding(
    finding: Finding, *, interesting_keywords: list[str] | None = None
) -> Finding:
    """Apply deterministic v1 severity rules."""
    keywords = set(interesting_keywords or INTERESTING_DEFAULTS)
    severity: Severity = "info"

    if finding.finding_type == "metadata":
        severity = "info"
    elif finding.finding_type == "username_profile":
        severity = "info" if "unverified" in finding.tags else "low"
    elif finding.finding_type == "email":
        severity = "low"
    elif finding.finding_type in {"domain", "subdomain", "host"}:
        severity = "medium" if _contains_keyword(finding.value, keywords) else "low"
        if SENSITIVE_INTERNAL_PATTERN.search(finding.value.lower()):
            severity = "high"
    elif finding.finding_type == "ip":
        severity = "low"
    elif finding.finding_type == "secret_exposure":
        verified = bool(finding.evidence.get("verified"))
        severity = "high" if verified else "medium"
        if "credential-indicator" in finding.tags:
            severity = "high"

    # TODO: Add future analyst override and multi-indicator critical assignment.
    return finding.model_copy(update={"severity": severity})


def score_findings(
    findings: list[Finding], *, interesting_keywords: list[str] | None = None
) -> list[Finding]:
    """Score a list of findings."""
    return [
        score_finding(finding, interesting_keywords=interesting_keywords) for finding in findings
    ]


def _contains_keyword(value: str, keywords: set[str]) -> bool:
    labels = re.split(r"[^a-z0-9]+", value.lower())
    return any(label in keywords for label in labels)
