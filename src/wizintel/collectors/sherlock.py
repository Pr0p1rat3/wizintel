"""Sherlock username collector."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, ClassVar

from wizintel.collectors.base import BaseCollector, make_finding
from wizintel.normalizers.hosts import normalize_url
from wizintel.schemas.collector import CollectorContext
from wizintel.schemas.finding import Finding
from wizintel.schemas.target import Target, TargetType
from wizintel.utils.subprocess_runner import SubprocessResult


class SherlockCollector(BaseCollector):
    """Wrap Sherlock and label matches as unverified public profile matches."""

    name: ClassVar[str] = "sherlock"
    description: ClassVar[str] = "Public username/social profile discovery."
    supported_target_types: ClassVar[set[TargetType]] = {"username"}
    passive_only: ClassVar[bool] = True
    requires_binary: ClassVar[bool] = True
    binary_name: ClassVar[str | None] = "sherlock"

    def build_command(self, target: Target, config: CollectorContext) -> list[str]:
        return [
            "sherlock",
            target.value,
            "--print-found",
            "--json",
            str(self._output_file(config)),
        ]

    def collect_raw_output(
        self, subprocess_result: SubprocessResult, context: CollectorContext
    ) -> str:
        output_file = self._output_file(context)
        if output_file.exists():
            return output_file.read_text(encoding="utf-8", errors="replace")
        return subprocess_result.stdout

    def parse_output(self, raw_output: str) -> list[Finding]:
        if not raw_output.strip():
            return []
        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            return self._parse_text(raw_output)
        if isinstance(parsed, dict):
            return self._parse_json_mapping(parsed)
        if isinstance(parsed, list):
            return self._parse_json_list(parsed)
        return []

    def _parse_json_mapping(self, parsed: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for site, item in parsed.items():
            if isinstance(item, dict):
                status = str(item.get("status") or item.get("status_code") or "").lower()
                exists = item.get("exists")
                url = str(item.get("url_user") or item.get("url") or "")
                found = exists is True or status in {"claimed", "found", "200"}
            else:
                url = str(item)
                found = bool(url)
            if found and url:
                findings.append(self._profile_finding(site=site, url=url))
        return findings

    def _parse_json_list(self, parsed: list[Any]) -> list[Finding]:
        findings: list[Finding] = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or item.get("url_user") or "")
            site = str(item.get("site") or item.get("name") or "")
            if url:
                findings.append(self._profile_finding(site=site, url=url))
        return findings

    def _parse_text(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        pattern = re.compile(r"^\[\+\]\s*([^:]+):\s*(https?://\S+)")
        for line in raw_output.splitlines():
            match = pattern.search(line.strip())
            if match:
                findings.append(self._profile_finding(site=match.group(1), url=match.group(2)))
        return findings

    def _profile_finding(self, *, site: str, url: str) -> Finding:
        normalized = normalize_url(url)
        return make_finding(
            collector=self.name,
            finding_type="username_profile",
            value=normalized,
            source=site or "sherlock",
            confidence="low",
            severity="info",
            tags=["passive", "unverified", "public-profile-match"],
            evidence={
                "site": site,
                "note": "Unverified public profile match; analyst review required.",
            },
        )

    def _output_file(self, context: CollectorContext) -> Path:
        return context.output_dir / "sherlock.json"
