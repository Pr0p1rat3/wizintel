from __future__ import annotations

import sys
from pathlib import Path
from typing import ClassVar

from wizintel.collectors.base import BaseCollector, make_finding
from wizintel.config import WizIntelConfig
from wizintel.orchestrator import run_scan
from wizintel.schemas.collector import CollectorContext
from wizintel.schemas.finding import Finding
from wizintel.schemas.target import Target, TargetType


class FixtureCollector(BaseCollector):
    name: ClassVar[str] = "fixture"
    description: ClassVar[str] = "Test collector"
    supported_target_types: ClassVar[set[TargetType]] = {"domain"}
    passive_only: ClassVar[bool] = True
    requires_binary: ClassVar[bool] = False
    binary_name: ClassVar[str | None] = None

    def build_command(self, target: Target, _config: CollectorContext) -> list[str]:
        return [sys.executable, "-c", "print('admin.example.com')"]

    def parse_output(self, raw_output: str) -> list[Finding]:
        return [
            make_finding(
                collector=self.name,
                finding_type="subdomain",
                value=raw_output.strip(),
                source="fixture",
                confidence="medium",
            )
        ]


def test_mocked_scan_produces_artifacts(tmp_path: Path) -> None:
    config = WizIntelConfig.model_validate(
        {
            "app": {"data_dir": str(tmp_path), "timeout_seconds": 20},
            "collectors": {"fixture": {"enabled": True, "timeout_seconds": 20}},
        }
    )
    target = Target(type="domain", value="example.com", authorized=True, passive=True)
    execution = run_scan(target, config, collectors=[FixtureCollector()])
    assert execution.scan.findings_count == 1
    assert (execution.output_dir / "findings.json").exists()
    assert (execution.output_dir / "findings.csv").exists()
    assert (execution.output_dir / "report.html").exists()
