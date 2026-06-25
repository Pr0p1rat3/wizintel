from __future__ import annotations

from wizintel.collectors.registry import (
    collectors_for_target,
    get_collector_by_name,
    get_default_collectors,
)
from wizintel.config import WizIntelConfig


def test_registry_contains_required_collectors() -> None:
    names = {collector.name for collector in get_default_collectors()}
    assert {
        "theharvester",
        "subfinder",
        "amass",
        "sherlock",
        "trufflehog",
        "spiderfoot",
    } <= names


def test_collector_lookup() -> None:
    assert get_collector_by_name("subfinder") is not None
    assert get_collector_by_name("missing") is None


def test_collectors_for_domain_excludes_disabled_spiderfoot() -> None:
    config = WizIntelConfig.model_validate(
        {"collectors": {"spiderfoot": {"enabled": False}}}
    )
    names = {collector.name for collector in collectors_for_target("domain", config)}
    assert "subfinder" in names
    assert "amass" in names
    assert "spiderfoot" not in names
