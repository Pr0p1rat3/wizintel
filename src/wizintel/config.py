"""Configuration loading."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from wizintel.constants import DEFAULT_DATA_DIR

_load_dotenv: Callable[[], bool] | None
try:
    from dotenv import load_dotenv as _dotenv_load_dotenv

    def _load_dotenv() -> bool:
        return _dotenv_load_dotenv()

except ImportError:  # pragma: no cover - dependency is declared; fallback keeps --help robust.
    _load_dotenv = None


DEFAULT_CONFIG_YAML = """app:
  name: WizIntel
  data_dir: ./data
  passive_default: true
  redact_secrets: true
  timeout_seconds: 120

collectors:
  theharvester:
    enabled: true
    timeout_seconds: 180
  subfinder:
    enabled: true
    timeout_seconds: 120
  amass:
    enabled: true
    passive_only: true
    timeout_seconds: 300
  sherlock:
    enabled: true
    timeout_seconds: 180
  trufflehog:
    enabled: true
    redact: true
    timeout_seconds: 300
  spiderfoot:
    enabled: false
    timeout_seconds: 600

scoring:
  interesting_keywords:
    - admin
    - vpn
    - portal
    - dev
    - test
    - staging
    - backup
    - sso
    - auth
    - git
    - ci
    - jenkins
    - grafana
    - kibana
"""


class AppSettings(BaseModel):
    """Top-level app settings."""

    name: str = "WizIntel"
    data_dir: str = DEFAULT_DATA_DIR
    passive_default: bool = True
    redact_secrets: bool = True
    timeout_seconds: int = 120


class CollectorSettings(BaseModel):
    """Per-collector settings."""

    enabled: bool = True
    timeout_seconds: int | None = None
    passive_only: bool = True
    redact: bool = True


class ScoringSettings(BaseModel):
    """Scoring settings."""

    interesting_keywords: list[str] = Field(
        default_factory=lambda: [
            "admin",
            "vpn",
            "portal",
            "dev",
            "test",
            "staging",
            "backup",
            "sso",
            "auth",
            "git",
            "ci",
            "jenkins",
            "grafana",
            "kibana",
        ]
    )


class WizIntelConfig(BaseModel):
    """Validated configuration."""

    app: AppSettings = Field(default_factory=AppSettings)
    collectors: dict[str, CollectorSettings] = Field(default_factory=dict)
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)

    def collector_settings(self, collector_name: str) -> CollectorSettings:
        return self.collectors.get(collector_name, CollectorSettings())

    @property
    def data_dir(self) -> Path:
        return Path(self.app.data_dir)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "wizintel.db"


def load_config(config_path: Path | str | None = None) -> WizIntelConfig:
    """Load config.yml if present, otherwise return defaults."""
    if _load_dotenv is not None:
        _load_dotenv()
    path = Path(config_path) if config_path is not None else Path("config.yml")
    if not path.exists():
        raw: dict[str, Any] = yaml.safe_load(DEFAULT_CONFIG_YAML)
    else:
        with path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
    return WizIntelConfig.model_validate(raw)


def write_default_config(destination: Path) -> bool:
    """Write config.example contents to destination when missing."""
    if destination.exists():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(DEFAULT_CONFIG_YAML, encoding="utf-8")
    return True
