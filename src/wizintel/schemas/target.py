"""Target schema."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

TargetType = Literal["domain", "email", "username", "github_repo"]


class Target(BaseModel):
    """Explicit scan scope object."""

    type: TargetType
    value: str
    scope_note: str = Field(
        default="CLI supplied scope. User is responsible for authorization."
    )
    authorized: bool
    passive: bool = True

    @field_validator("value", "scope_note")
    @classmethod
    def strip_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value must not be empty.")
        return value
