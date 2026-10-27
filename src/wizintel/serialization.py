"""Privacy policy for exported data; storage models retain their original values."""

from __future__ import annotations

from typing import Any

from wizintel.redaction import redact_email, redact_emails_in_text
from wizintel.schemas.finding import Finding
from wizintel.schemas.scan import Scan


def serialize_scan(scan: Scan, *, include_sensitive: bool = False) -> dict[str, Any]:
    """Copy a scan for export, masking email targets and incidental email text by default."""
    data = scan.model_dump(mode="json")
    if include_sensitive:
        return data
    if scan.target.type == "email":
        data["target"]["value"] = redact_email(scan.target.value)
    return _redact_mapping(data)


def serialize_finding(finding: Finding, *, include_sensitive: bool = False) -> dict[str, Any]:
    """Copy a finding for export without trusting a collector to have masked emails."""
    data = finding.model_dump(mode="json")
    if include_sensitive:
        return data
    value = finding.redacted_value
    if value is None:
        value = finding.value
    if finding.finding_type == "email":
        value = redact_email(value)
    # Keep the existing JSON shape, but never include an alternate raw value by default.
    data["value"] = data["redacted_value"] = value
    return _redact_mapping(data)


def _redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    next_suffix: dict[str, int] = {}
    for key, value in data.items():
        safe_key = redact_emails_in_text(key)
        # Masked evidence keys can collide. Preserve every entry without leaking the key.
        unique_key = safe_key
        suffix = next_suffix.get(safe_key, 2)
        while unique_key in result:
            unique_key = f"{safe_key}#{suffix}"
            suffix += 1
        next_suffix[safe_key] = suffix
        result[unique_key] = _redact_value(value)
    return result


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_emails_in_text(value)
    if isinstance(value, dict):
        return _redact_mapping(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value
