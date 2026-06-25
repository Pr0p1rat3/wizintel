"""Collector registry."""

from __future__ import annotations

from collections.abc import Iterable

from wizintel.collectors.amass import AmassCollector
from wizintel.collectors.base import BaseCollector
from wizintel.collectors.sherlock import SherlockCollector
from wizintel.collectors.spiderfoot import SpiderFootCollector
from wizintel.collectors.subfinder import SubfinderCollector
from wizintel.collectors.theharvester import TheHarvesterCollector
from wizintel.collectors.trufflehog import TruffleHogCollector
from wizintel.config import WizIntelConfig
from wizintel.schemas.target import TargetType


def get_default_collectors() -> list[BaseCollector]:
    """Return the default collector instances."""
    return [
        SubfinderCollector(),
        AmassCollector(),
        TheHarvesterCollector(),
        SherlockCollector(),
        TruffleHogCollector(),
        SpiderFootCollector(),
    ]


def get_collector_by_name(name: str) -> BaseCollector | None:
    """Find a collector by name."""
    for collector in get_default_collectors():
        if collector.name == name:
            return collector
    return None


def collectors_for_target(
    target_type: TargetType,
    config: WizIntelConfig,
    *,
    candidates: Iterable[BaseCollector] | None = None,
) -> list[BaseCollector]:
    """Return enabled collectors that support a target type."""
    selected: list[BaseCollector] = []
    for collector in candidates or get_default_collectors():
        settings = config.collector_settings(collector.name)
        if not settings.enabled:
            continue
        if target_type in collector.supported_target_types:
            selected.append(collector)
    return selected
