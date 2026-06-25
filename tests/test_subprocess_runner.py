from __future__ import annotations

import sys

import pytest

from wizintel.utils.subprocess_runner import run_command


def test_run_command_success() -> None:
    result = run_command([sys.executable, "-c", "print('ok')"], timeout=10)
    assert result.ok
    assert result.stdout.strip() == "ok"


def test_run_command_requires_args() -> None:
    with pytest.raises(ValueError):
        run_command([], timeout=10)


def test_run_command_missing_binary() -> None:
    result = run_command(["definitely-not-a-real-wizintel-binary"], timeout=1)
    assert result.returncode == 127
    assert not result.ok
