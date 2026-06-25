"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wizintel.constants import APP_NAME, VERSION
from wizintel.schemas.finding import Finding
from wizintel.schemas.scan import Scan


def build_json_report(scan: Scan, findings: list[Finding]) -> dict[str, Any]:
    """Build structured JSON report."""
    return {
        "metadata": {
            "project": APP_NAME,
            "version": VERSION,
            "redaction": (
                "Reports use redacted values by default; secret raw values are not stored."
            ),
        },
        "scan": scan.model_dump(mode="json"),
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }


def write_json_report(scan: Scan, findings: list[Finding], output_path: Path) -> Path:
    """Write structured JSON report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(build_json_report(scan, findings), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return output_path
