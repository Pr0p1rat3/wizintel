"""Filesystem helpers."""

from __future__ import annotations

import shutil
from pathlib import Path


def ensure_dir(path: Path) -> Path:
    """Create a directory and return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def copy_file_if_missing(source: Path, destination: Path) -> bool:
    """Copy source to destination when destination does not exist."""
    if destination.exists():
        return False
    ensure_dir(destination.parent)
    shutil.copyfile(source, destination)
    return True
