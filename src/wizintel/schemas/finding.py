"""Finding schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from wizintel.utils.time import utc_now

FindingType = Literal[
    "domain",
    "subdomain",
    "email",
    "username_profile",
    "host",
    "ip",
    "secret_exposure",
    "metadata",
]
Confidence = Literal["low", "medium", "high"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    """Normalized OSINT finding."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    scan_id: str = ""
    collector: str
    finding_type: FindingType
    value: str
    redacted_value: str | None = None
    source: str = ""
    confidence: Confidence = "low"
    severity: Severity = "info"
    tags: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def set_default_redacted_value(self) -> Finding:
        if self.redacted_value is None:
            self.redacted_value = self.value
        return self
