"""CSV report writer."""

from __future__ import annotations

import csv
from pathlib import Path

from wizintel.schemas.finding import Finding
from wizintel.serialization import serialize_finding

CSV_COLUMNS = [
    "severity",
    "confidence",
    "finding_type",
    "redacted_value",
    "collector",
    "source",
    "tags",
]


def write_csv_report(
    findings: list[Finding], output_path: Path, *, include_sensitive: bool = False
) -> Path:
    """Write findings CSV using redacted values."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        columns = [*CSV_COLUMNS, "value"] if include_sensitive else CSV_COLUMNS
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for finding in findings:
            exported = serialize_finding(finding, include_sensitive=include_sensitive)
            row = {column: exported[column] for column in columns}
            row["tags"] = ",".join(exported["tags"])
            writer.writerow(row)
    return output_path
