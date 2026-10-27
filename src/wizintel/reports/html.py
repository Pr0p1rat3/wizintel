"""HTML report generation."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from wizintel.constants import APP_NAME
from wizintel.schemas.finding import Finding
from wizintel.schemas.scan import Scan
from wizintel.serialization import serialize_finding, serialize_scan


def write_html_report(
    scan: Scan, findings: list[Finding], output_path: Path, *, include_sensitive: bool = False
) -> Path:
    """Render the HTML report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )
    template = env.get_template("report.html.j2")
    rendered = template.render(
        project_name=APP_NAME,
        scan=serialize_scan(scan, include_sensitive=include_sensitive),
        findings=[
            serialize_finding(finding, include_sensitive=include_sensitive) for finding in findings
        ],
        include_sensitive=include_sensitive,
        severity_counts=dict(Counter(finding.severity for finding in findings)),
        type_counts=dict(Counter(finding.finding_type for finding in findings)),
        risk_notes=_risk_notes(findings),
    )
    output_path.write_text(rendered, encoding="utf-8")
    return output_path


def _risk_notes(findings: list[Finding]) -> list[str]:
    notes: list[str] = []
    if any(finding.severity == "high" for finding in findings):
        notes.append("High severity exposure indicators require analyst validation and triage.")
    if any(finding.finding_type == "username_profile" for finding in findings):
        notes.append(
            "Username profile matches are unverified public matches unless evidence says otherwise."
        )
    if any(finding.finding_type == "secret_exposure" for finding in findings):
        notes.append(
            "Secret findings are redacted by default and should be validated "
            "in a controlled workflow."
        )
    if not notes:
        notes.append("No high-risk findings were identified by the enabled passive collectors.")
    return notes
