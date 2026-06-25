"""Logging setup."""

from __future__ import annotations

import logging
from pathlib import Path


def configure_scan_logger(scan_id: str, log_path: Path) -> logging.Logger:
    """Create an isolated file logger for a scan."""
    logger = logging.getLogger(f"wizintel.scan.{scan_id}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers.clear()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger
