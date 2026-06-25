"""Amass passive asset collector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from wizintel.collectors.base import BaseCollector, make_finding
from wizintel.normalizers.domains import normalize_domain
from wizintel.schemas.collector import CollectorContext
from wizintel.schemas.finding import Finding
from wizintel.schemas.target import Target, TargetType
from wizintel.utils.subprocess_runner import SubprocessResult


class AmassCollector(BaseCollector):
    """Wrap Amass passive enum mode."""

    name: ClassVar[str] = "amass"
    description: ClassVar[str] = "Passive external asset discovery."
    supported_target_types: ClassVar[set[TargetType]] = {"domain"}
    passive_only: ClassVar[bool] = True
    requires_binary: ClassVar[bool] = True
    binary_name: ClassVar[str | None] = "amass"

    def build_command(self, target: Target, config: CollectorContext) -> list[str]:
        output_file = self._output_file(config)
        return ["amass", "enum", "-passive", "-d", target.value, "-json", str(output_file)]

    def collect_raw_output(
        self, subprocess_result: SubprocessResult, context: CollectorContext
    ) -> str:
        output_file = self._output_file(context)
        if output_file.exists():
            return output_file.read_text(encoding="utf-8", errors="replace")
        return subprocess_result.stdout

    def parse_output(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                item = {"name": line}
            if not isinstance(item, dict):
                continue
            host = normalize_domain(str(item.get("name") or item.get("domain") or ""))
            if host:
                findings.append(
                    make_finding(
                        collector=self.name,
                        finding_type="subdomain",
                        value=host,
                        source="amass",
                        confidence="medium",
                        tags=["passive", "asset"],
                        evidence={"sources": item.get("sources") or item.get("tag")},
                    )
                )
            for ip_value in _extract_ips(item):
                findings.append(
                    make_finding(
                        collector=self.name,
                        finding_type="ip",
                        value=ip_value,
                        source="amass",
                        confidence="low",
                        tags=["passive", "ip"],
                    )
                )
        return findings

    def _output_file(self, context: CollectorContext) -> Path:
        return context.output_dir / "amass.json"


def _extract_ips(item: dict[str, Any]) -> list[str]:
    ips: list[str] = []
    for address in item.get("addresses") or []:
        if isinstance(address, dict) and address.get("ip"):
            ips.append(str(address["ip"]))
    if item.get("ip"):
        ips.append(str(item["ip"]))
    return ips
