"""Collector abstraction."""

from __future__ import annotations

import logging
import shutil
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import ClassVar, cast

from wizintel.config import WizIntelConfig
from wizintel.schemas.collector import CollectorContext, CollectorResult
from wizintel.schemas.finding import Confidence, Finding, FindingType, Severity
from wizintel.schemas.target import Target, TargetType
from wizintel.utils.filesystem import ensure_dir
from wizintel.utils.subprocess_runner import SubprocessResult, run_command


class BaseCollector(ABC):
    """Base class for safe, passive-first collector wrappers."""

    name: ClassVar[str]
    description: ClassVar[str]
    supported_target_types: ClassVar[set[TargetType]]
    passive_only: ClassVar[bool] = True
    requires_binary: ClassVar[bool] = True
    binary_name: ClassVar[str | None] = None

    def is_available(self) -> bool:
        """Return whether this collector can run in the current environment."""
        if not self.requires_binary:
            return True
        if self.binary_name is None:
            return False
        return shutil.which(self.binary_name) is not None

    @abstractmethod
    def build_command(self, target: Target, config: CollectorContext) -> list[str]:
        """Build a safe list-argument command."""

    @abstractmethod
    def parse_output(self, raw_output: str) -> list[Finding]:
        """Parse raw collector output into findings."""

    def run(
        self,
        target: Target,
        app_config: WizIntelConfig,
        context: CollectorContext,
        *,
        logger: logging.Logger | None = None,
        runner: Callable[..., SubprocessResult] = run_command,
    ) -> CollectorResult:
        """Run a collector and return structured findings without crashing the scan."""
        result = CollectorResult(collector=self.name)
        if target.type not in self.supported_target_types:
            result.warnings.append(f"{self.name} does not support target type {target.type}.")
            return result
        if self.passive_only and not target.passive:
            result.errors.append(f"{self.name} is passive-only; active mode is not supported.")
            return result
        if self.requires_binary and not self.is_available():
            binary = self.binary_name or self.name
            result.warnings.append(f"Required binary not found: {binary}")
            return result

        ensure_dir(context.output_dir)
        timeout = int(context.settings.get("timeout_seconds") or app_config.app.timeout_seconds)
        try:
            command = self.build_command(target, context)
            result.command = command
            subprocess_result = runner(command, timeout=timeout)
            raw_output = self.collect_raw_output(subprocess_result, context)
            if subprocess_result.timed_out:
                result.errors.append(f"{self.name} timed out after {timeout} seconds.")
            elif subprocess_result.returncode != 0:
                stderr = subprocess_result.stderr.strip()
                result.warnings.append(
                    f"{self.name} exited with code {subprocess_result.returncode}: {stderr}"
                )
            findings = self.parse_output(raw_output)
            result.findings = [
                finding.model_copy(update={"collector": self.name, "scan_id": context.scan_id})
                for finding in findings
            ]
        except Exception as exc:
            result.errors.append(f"{self.name} failed: {exc}")
            if logger is not None:
                logger.exception("Collector %s failed", self.name)
        return result

    def collect_raw_output(
        self, subprocess_result: SubprocessResult, _context: CollectorContext
    ) -> str:
        """Collect stdout by default. File-output collectors override this."""
        return subprocess_result.stdout


def make_finding(
    *,
    collector: str,
    finding_type: str,
    value: str,
    redacted_value: str | None = None,
    source: str = "",
    confidence: str = "low",
    severity: str = "info",
    tags: list[str] | None = None,
    evidence: dict[str, object] | None = None,
) -> Finding:
    """Small helper to construct typed findings in collectors."""
    return Finding(
        collector=collector,
        finding_type=cast(FindingType, finding_type),
        value=value,
        redacted_value=redacted_value,
        source=source,
        confidence=cast(Confidence, confidence),
        severity=cast(Severity, severity),
        tags=tags or [],
        evidence=evidence or {},
    )
