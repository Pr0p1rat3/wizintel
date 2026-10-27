"""Experimental FastAPI routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from wizintel.config import load_config
from wizintel.constants import VERSION
from wizintel.db.storage import Storage
from wizintel.serialization import serialize_finding, serialize_scan

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    """Health check."""
    return {"status": "ok"}


@router.get("/version")
def version() -> dict[str, str]:
    """Version endpoint."""
    return {"version": VERSION, "api": "experimental"}


@router.get("/scans")
def scans() -> list[dict[str, object]]:
    """List local scans with email addresses masked; no full-fidelity API option."""
    config = load_config()
    storage = Storage(config.db_path)
    return [serialize_scan(scan) for scan in storage.list_scans()]


@router.get("/scans/{scan_id}")
def scan(scan_id: str) -> dict[str, object]:
    """Get one local scan and findings with email addresses masked."""
    config = load_config()
    storage = Storage(config.db_path)
    stored_scan = storage.get_scan(scan_id)
    if stored_scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = storage.get_findings_for_scan(scan_id)
    return {
        "scan": serialize_scan(stored_scan),
        "findings": [serialize_finding(finding) for finding in findings],
    }
