"""theHarvester collector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from wizintel.collectors.base import BaseCollector, make_finding
from wizintel.normalizers.domains import normalize_domain
from wizintel.normalizers.emails import normalize_email
from wizintel.redaction import redact_email
from wizintel.schemas.collector import CollectorContext
from wizintel.schemas.finding import Finding
from wizintel.schemas.target import Target, TargetType
from wizintel.utils.subprocess_runner import SubprocessResult


class TheHarvesterCollector(BaseCollector):
    """Wrap theHarvester and parse supported JSON output."""

    name: ClassVar[str] = "theharvester"
    description: ClassVar[str] = "Emails, names, hosts, and subdomains from passive sources."
    supported_target_types: ClassVar[set[TargetType]] = {"domain", "email"}
    passive_only: ClassVar[bool] = True
    requires_binary: ClassVar[bool] = True
    binary_name: ClassVar[str | None] = "theHarvester"

    def build_command(self, target: Target, config: CollectorContext) -> list[str]:
        query = (
            target.value.split("@", 1)[1]
            if target.type == "email" and "@" in target.value
            else target.value
        )
        output_base = self._output_base(config)
        source = str(config.settings.get("source") or "all")
        return ["theHarvester", "-d", query, "-b", source, "-f", str(output_base)]

    def collect_raw_output(
        self, subprocess_result: SubprocessResult, context: CollectorContext
    ) -> str:
        json_file = self._output_base(context).with_suffix(".json")
        if json_file.exists():
            return json_file.read_text(encoding="utf-8", errors="replace")
        return subprocess_result.stdout

    def parse_output(self, raw_output: str) -> list[Finding]:
        if not raw_output.strip():
            return []
        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            return self._parse_text(raw_output)
        objects = parsed if isinstance(parsed, list) else [parsed]
        findings: list[Finding] = []
        for item in objects:
            if isinstance(item, dict):
                findings.extend(self._findings_from_json(item))
        return findings

    def _findings_from_json(self, item: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for email in _as_list(item.get("emails") or item.get("email")):
            normalized = normalize_email(str(email))
            findings.append(
                make_finding(
                    collector=self.name,
                    finding_type="email",
                    value=normalized,
                    redacted_value=redact_email(normalized),
                    source="theharvester",
                    confidence="medium",
                    tags=["passive", "email"],
                )
            )
        for host in _as_list(item.get("hosts") or item.get("host") or item.get("subdomains")):
            normalized_host = normalize_domain(str(host))
            if normalized_host:
                findings.append(
                    make_finding(
                        collector=self.name,
                        finding_type="subdomain",
                        value=normalized_host,
                        source="theharvester",
                        confidence="medium",
                        tags=["passive", "host"],
                    )
                )
        for ip_value in _as_list(item.get("ips") or item.get("ip")):
            findings.append(
                make_finding(
                    collector=self.name,
                    finding_type="ip",
                    value=str(ip_value),
                    source="theharvester",
                    confidence="low",
                    tags=["passive", "ip"],
                )
            )
        for name in _as_list(item.get("people") or item.get("names")):
            findings.append(
                make_finding(
                    collector=self.name,
                    finding_type="metadata",
                    value=str(name),
                    source="theharvester",
                    confidence="low",
                    tags=["passive", "person-name"],
                )
            )
        return findings

    def _parse_text(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw_output.splitlines():
            value = line.strip()
            if "@" in value and "." in value:
                normalized = normalize_email(value)
                findings.append(
                    make_finding(
                        collector=self.name,
                        finding_type="email",
                        value=normalized,
                        redacted_value=redact_email(normalized),
                        source="theharvester",
                        confidence="low",
                        tags=["passive", "email"],
                    )
                )
        return findings

    def _output_base(self, context: CollectorContext) -> Path:
        return context.output_dir / "theharvester"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
