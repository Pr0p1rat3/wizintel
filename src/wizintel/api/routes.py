"""Experimental FastAPI routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from wizintel.config import load_config
from wizintel.constants import VERSION
from wizintel.db.storage import Storage

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
    """List local scans."""
    config = load_config()
    storage = Storage(config.db_path)
    return [scan.model_dump(mode="json") for scan in storage.list_scans()]


@router.get("/scans/{scan_id}")
def scan(scan_id: str) -> dict[str, object]:
    """Get one local scan and findings."""
    config = load_config()
    storage = Storage(config.db_path)
    stored_scan = storage.get_scan(scan_id)
    if stored_scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = storage.get_findings_for_scan(scan_id)
    return {
        "scan": stored_scan.model_dump(mode="json"),
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }
