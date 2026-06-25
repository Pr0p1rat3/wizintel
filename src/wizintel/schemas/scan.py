"""Scan schema."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from wizintel.schemas.target import Target
from wizintel.utils.time import utc_now

ScanStatus = Literal["pending", "running", "completed", "failed", "partial"]


class Scan(BaseModel):
    """A local WizIntel scan case."""

    id: str = Field(default_factory=lambda: f"case_{uuid4().hex[:12]}")
    target: Target
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    status: ScanStatus = "pending"
    collectors_run: list[str] = Field(default_factory=list)
    findings_count: int = 0
    output_dir: str
