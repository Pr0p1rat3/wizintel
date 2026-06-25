"""SpiderFoot placeholder collector."""

from __future__ import annotations

from typing import ClassVar

from wizintel.collectors.base import BaseCollector
from wizintel.schemas.collector import CollectorContext
from wizintel.schemas.finding import Finding
from wizintel.schemas.target import Target, TargetType


class SpiderFootCollector(BaseCollector):
    """Disabled-by-default placeholder for future SpiderFoot integration."""

    name: ClassVar[str] = "spiderfoot"
    description: ClassVar[str] = "Optional broader OSINT automation connector."
    supported_target_types: ClassVar[set[TargetType]] = {
        "domain",
        "email",
        "username",
        "github_repo",
    }
    passive_only: ClassVar[bool] = True
    requires_binary: ClassVar[bool] = True
    binary_name: ClassVar[str | None] = "spiderfoot"

    def build_command(self, target: Target, _config: CollectorContext) -> list[str]:
        # TODO: Implement a strictly passive SpiderFoot connector in v2.
        return ["spiderfoot", "-s", target.value]

    def parse_output(self, _raw_output: str) -> list[Finding]:
        return []
