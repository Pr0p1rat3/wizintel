"""SQLite storage layer."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, desc, select
from sqlalchemy.orm import sessionmaker

from wizintel.db.models import Base, FindingRecord, ScanRecord
from wizintel.schemas.finding import Finding
from wizintel.schemas.scan import Scan, ScanStatus
from wizintel.schemas.target import Target
from wizintel.utils.filesystem import ensure_dir
from wizintel.utils.time import utc_now


class Storage:
    """Local SQLite storage service."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        ensure_dir(db_path.parent)
        self.engine = create_engine(f"sqlite:///{db_path}", future=True)
        self.session_factory = sessionmaker(self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)

    def create_scan(self, target: Target, output_dir: Path, scan_id: str | None = None) -> Scan:
        """Create and persist a running scan."""
        scan = Scan(
            id=scan_id or f"case_{uuid4().hex[:12]}",
            target=target,
            status="running",
            output_dir=str(output_dir),
        )
        with self.session_factory() as session:
            session.add(_scan_to_record(scan))
            session.commit()
        return scan

    def update_scan(self, scan: Scan) -> None:
        """Update a persisted scan."""
        with self.session_factory() as session:
            record = session.get(ScanRecord, scan.id)
            if record is None:
                session.add(_scan_to_record(scan))
            else:
                replacement = _scan_to_record(scan)
                record.target_json = replacement.target_json
                record.started_at = replacement.started_at
                record.completed_at = replacement.completed_at
                record.status = replacement.status
                record.collectors_run_json = replacement.collectors_run_json
                record.findings_count = replacement.findings_count
                record.output_dir = replacement.output_dir
            session.commit()

    def complete_scan(self, scan: Scan, *, status: ScanStatus = "completed") -> Scan:
        """Mark a scan complete and persist it."""
        completed = scan.model_copy(update={"status": status, "completed_at": utc_now()})
        self.update_scan(completed)
        return completed

    def save_findings(self, findings: list[Finding]) -> None:
        """Persist findings."""
        with self.session_factory() as session:
            for finding in findings:
                session.merge(_finding_to_record(finding))
            session.commit()

    def get_scan(self, scan_id: str) -> Scan | None:
        """Fetch one scan."""
        with self.session_factory() as session:
            record = session.get(ScanRecord, scan_id)
            return _record_to_scan(record) if record is not None else None

    def get_latest_scan(self) -> Scan | None:
        """Fetch newest scan."""
        with self.session_factory() as session:
            statement = select(ScanRecord).order_by(desc(ScanRecord.started_at))
            record = session.scalars(statement).first()
            return _record_to_scan(record) if record is not None else None

    def list_scans(self) -> list[Scan]:
        """List scans newest first."""
        with self.session_factory() as session:
            statement = select(ScanRecord).order_by(desc(ScanRecord.started_at))
            records = session.scalars(statement).all()
            return [_record_to_scan(record) for record in records]

    def get_findings_for_scan(self, scan_id: str) -> list[Finding]:
        """Fetch findings for a scan."""
        with self.session_factory() as session:
            records = session.scalars(
                select(FindingRecord).where(FindingRecord.scan_id == scan_id)
            ).all()
            return [_record_to_finding(record) for record in records]


def _scan_to_record(scan: Scan) -> ScanRecord:
    return ScanRecord(
        id=scan.id,
        target_json=json.dumps(scan.target.model_dump(mode="json"), sort_keys=True),
        started_at=scan.started_at.isoformat(),
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        status=scan.status,
        collectors_run_json=json.dumps(scan.collectors_run),
        findings_count=scan.findings_count,
        output_dir=scan.output_dir,
    )


def _record_to_scan(record: ScanRecord) -> Scan:
    return Scan.model_validate(
        {
            "id": record.id,
            "target": json.loads(record.target_json),
            "started_at": record.started_at,
            "completed_at": record.completed_at,
            "status": record.status,
            "collectors_run": json.loads(record.collectors_run_json),
            "findings_count": record.findings_count,
            "output_dir": record.output_dir,
        }
    )


def _finding_to_record(finding: Finding) -> FindingRecord:
    return FindingRecord(
        id=finding.id,
        scan_id=finding.scan_id,
        collector=finding.collector,
        finding_type=finding.finding_type,
        value=finding.value,
        redacted_value=finding.redacted_value or finding.value,
        source=finding.source,
        confidence=finding.confidence,
        severity=finding.severity,
        tags_json=json.dumps(finding.tags, sort_keys=True),
        evidence_json=json.dumps(finding.evidence, sort_keys=True),
        created_at=finding.created_at.isoformat(),
    )


def _record_to_finding(record: FindingRecord) -> Finding:
    return Finding.model_validate(
        {
            "id": record.id,
            "scan_id": record.scan_id,
            "collector": record.collector,
            "finding_type": record.finding_type,
            "value": record.value,
            "redacted_value": record.redacted_value,
            "source": record.source,
            "confidence": record.confidence,
            "severity": record.severity,
            "tags": json.loads(record.tags_json),
            "evidence": json.loads(record.evidence_json),
            "created_at": record.created_at,
        }
    )
