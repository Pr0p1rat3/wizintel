"""Report schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ReportMetadata(BaseModel):
    """Report generation metadata."""

    project: str = "WizIntel"
    redaction_note: str = "Reports use redacted values by default."
    safety_note: str = (
        "Use only for systems, organizations, or repositories you are authorized to assess."
    )
    generated_files: list[str] = Field(default_factory=list)
