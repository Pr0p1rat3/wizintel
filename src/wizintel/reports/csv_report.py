"""CSV report writer."""

from __future__ import annotations

import csv
from pathlib import Path

from wizintel.schemas.finding import Finding

CSV_COLUMNS = [
    "severity",
    "confidence",
    "finding_type",
    "redacted_value",
    "collector",
    "source",
    "tags",
]


def write_csv_report(findings: list[Finding], output_path: Path) -> Path:
    """Write findings CSV using redacted values."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for finding in findings:
            writer.writerow(
                {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "finding_type": finding.finding_type,
                    "redacted_value": finding.redacted_value or finding.value,
                    "collector": finding.collector,
                    "source": finding.source,
                    "tags": ",".join(finding.tags),
                }
            )
    return output_path
