"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wizintel.constants import APP_NAME, VERSION
from wizintel.schemas.finding import Finding
from wizintel.schemas.scan import Scan
from wizintel.serialization import serialize_finding, serialize_scan


def build_json_report(
    scan: Scan, findings: list[Finding], *, include_sensitive: bool = False
) -> dict[str, Any]:
    """Build structured JSON report."""
    return {
        "metadata": {
            "project": APP_NAME,
            "version": VERSION,
            "redaction_mode": "full-fidelity" if include_sensitive else "redacted",
            "redaction": (
                "Full-fidelity export of stored values, including original email addresses."
                if include_sensitive
                else "Email addresses are masked; finding values use redacted_value."
            ),
        },
        "scan": serialize_scan(scan, include_sensitive=include_sensitive),
        "findings": [
            serialize_finding(finding, include_sensitive=include_sensitive) for finding in findings
        ],
    }


def write_json_report(
    scan: Scan, findings: list[Finding], output_path: Path, *, include_sensitive: bool = False
) -> Path:
    """Write structured JSON report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            build_json_report(scan, findings, include_sensitive=include_sensitive),
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return output_path
