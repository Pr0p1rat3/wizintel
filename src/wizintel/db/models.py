"""SQLAlchemy storage models."""

from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base."""


class ScanRecord(Base):
    """Persisted scan."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    target_json: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[str] = mapped_column(String(40), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    collectors_run_json: Mapped[str] = mapped_column(Text, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_dir: Mapped[str] = mapped_column(Text, nullable=False)


class FindingRecord(Base):
    """Persisted finding."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(80), ForeignKey("scans.id"), index=True)
    collector: Mapped[str] = mapped_column(String(80), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(80), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    redacted_value: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    tags_json: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
