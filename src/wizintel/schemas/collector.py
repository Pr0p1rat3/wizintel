"""Collector schemas."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from wizintel.schemas.finding import Finding


class CollectorContext(BaseModel):
    """Runtime context passed to collectors."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    output_dir: Path
    passive: bool = True
    settings: dict[str, Any] = Field(default_factory=dict)


class CollectorResult(BaseModel):
    """Structured collector execution result."""

    collector: str
    findings: list[Finding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    command: list[str] = Field(default_factory=list)


class CollectorToolStatus(BaseModel):
    """CLI status row for an external tool."""

    tool: str
    found: bool
    path: str | None
    version: str | None
    collector_status: str
