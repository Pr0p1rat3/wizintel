"""External tool detection."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from wizintel.utils.subprocess_runner import run_command


@dataclass(frozen=True)
class ToolDetection:
    """Detected external tool metadata."""

    name: str
    binary: str
    found: bool
    path: str | None
    version: str | None


def detect_tool(name: str, binary: str, timeout: int = 10) -> ToolDetection:
    """Detect an external binary and best-effort version text."""
    binary_path = shutil.which(binary)
    if binary_path is None:
        return ToolDetection(name=name, binary=binary, found=False, path=None, version=None)

    version = _detect_version(binary_path, timeout=timeout)
    return ToolDetection(name=name, binary=binary, found=True, path=binary_path, version=version)


def _detect_version(binary_path: str, *, timeout: int) -> str | None:
    for args in ([binary_path, "--version"], [binary_path, "-version"], [binary_path, "-h"]):
        result = run_command(args, timeout=timeout, cwd=Path.cwd())
        text = (result.stdout or result.stderr).strip()
        if text:
            return text.splitlines()[0][:160]
    return None
