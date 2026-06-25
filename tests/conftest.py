from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))


def fixture_text(name: str) -> str:
    return (ROOT / "tests" / "fixtures" / name).read_text(encoding="utf-8")
