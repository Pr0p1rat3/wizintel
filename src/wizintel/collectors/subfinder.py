"""subfinder passive subdomain collector."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from wizintel.collectors.base import BaseCollector, make_finding
from wizintel.normalizers.domains import normalize_domain
from wizintel.schemas.collector import CollectorContext
from wizintel.schemas.finding import Finding
from wizintel.schemas.target import Target, TargetType


class SubfinderCollector(BaseCollector):
    """Wrap ProjectDiscovery subfinder in passive JSON mode."""

    name: ClassVar[str] = "subfinder"
    description: ClassVar[str] = "Passive subdomain discovery."
    supported_target_types: ClassVar[set[TargetType]] = {"domain"}
    passive_only: ClassVar[bool] = True
    requires_binary: ClassVar[bool] = True
    binary_name: ClassVar[str | None] = "subfinder"

    def build_command(self, target: Target, _config: CollectorContext) -> list[str]:
        return ["subfinder", "-silent", "-d", target.value, "-json"]

    def parse_output(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            item: dict[str, Any] | None = None
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    item = parsed
            except json.JSONDecodeError:
                item = {"host": line}
            if item is None:
                continue
            host = normalize_domain(
                str(item.get("host") or item.get("name") or item.get("domain") or "")
            )
            if host:
                findings.append(
                    make_finding(
                        collector=self.name,
                        finding_type="subdomain",
                        value=host,
                        source="subfinder",
                        confidence="medium",
                        tags=["passive", "subdomain"],
                        evidence={"raw_source": item.get("source") or item.get("sources")},
                    )
                )
            ip_value = item.get("ip") or item.get("address")
            if ip_value:
                findings.append(
                    make_finding(
                        collector=self.name,
                        finding_type="ip",
                        value=str(ip_value),
                        source="subfinder",
                        confidence="low",
                        tags=["passive", "ip"],
                    )
                )
        return findings
