"""TruffleHog public repository secret exposure collector."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from wizintel.collectors.base import BaseCollector, make_finding
from wizintel.normalizers.secrets import fingerprint_secret, normalize_secret_finding
from wizintel.redaction import redact_secret
from wizintel.schemas.collector import CollectorContext
from wizintel.schemas.finding import Finding
from wizintel.schemas.target import Target, TargetType


class TruffleHogCollector(BaseCollector):
    """Wrap TruffleHog in JSON mode for public GitHub repository checks."""

    name: ClassVar[str] = "trufflehog"
    description: ClassVar[str] = "Public repository secret exposure checks."
    supported_target_types: ClassVar[set[TargetType]] = {"github_repo"}
    passive_only: ClassVar[bool] = True
    requires_binary: ClassVar[bool] = True
    binary_name: ClassVar[str | None] = "trufflehog"

    def build_command(self, target: Target, _config: CollectorContext) -> list[str]:
        return ["trufflehog", "github", "--repo", target.value, "--json"]

    def parse_output(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            safe_secret = normalize_secret_finding(item)
            fingerprint = safe_secret["fingerprint"] or fingerprint_secret(
                json.dumps(item, sort_keys=True)
            )
            file_path, line_number = _extract_source_location(item)
            verified = bool(safe_secret["verified"])
            redacted_fingerprint = redact_secret(str(fingerprint))
            findings.append(
                make_finding(
                    collector=self.name,
                    finding_type="secret_exposure",
                    value=redacted_fingerprint,
                    redacted_value=safe_secret["redacted_secret"] or redacted_fingerprint,
                    source=file_path,
                    confidence="high" if verified else "medium",
                    severity="high" if verified else "medium",
                    tags=["passive", "secret", "credential-indicator"],
                    evidence={
                        "secret_type": safe_secret["secret_type"],
                        "file": file_path,
                        "line": line_number,
                        "verified": verified,
                        "fingerprint": fingerprint,
                        "stored_secret_value": False,
                    },
                )
            )
        return findings


def _extract_source_location(item: dict[str, Any]) -> tuple[str, int | None]:
    source_metadata = item.get("SourceMetadata")
    if isinstance(source_metadata, dict):
        data = source_metadata.get("Data")
        if isinstance(data, dict):
            github = data.get("Github") or data.get("Git")
            if isinstance(github, dict):
                file_path = str(github.get("file") or github.get("path") or "")
                line_value = github.get("line") or github.get("start_line")
                return file_path, _parse_line_number(line_value)
    file_path = str(item.get("SourceName") or item.get("file") or "")
    line_value = item.get("line") or item.get("Line")
    return file_path, _parse_line_number(line_value)


def _parse_line_number(value: Any) -> int | None:
    value_str = str(value)
    return int(value_str) if value_str.isdigit() else None
