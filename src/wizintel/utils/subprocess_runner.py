"""Safe subprocess execution helpers."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SubprocessResult:
    """Normalized subprocess result."""

    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run_command(
    args: Sequence[str],
    *,
    timeout: int,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> SubprocessResult:
    """Run a command using list args and no shell."""
    if not args:
        raise ValueError("Command args must not be empty.")
    normalized_args = [str(arg) for arg in args]
    try:
        completed = subprocess.run(  # noqa: S603 - command is passed as list args with shell=False
            normalized_args,
            capture_output=True,
            check=False,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            shell=False,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _coerce_output(exc.stdout)
        stderr = _coerce_output(exc.stderr) or f"Command timed out after {timeout} seconds."
        return SubprocessResult(
            args=normalized_args,
            returncode=124,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
        )
    except FileNotFoundError as exc:
        return SubprocessResult(
            args=normalized_args,
            returncode=127,
            stdout="",
            stderr=str(exc),
            timed_out=False,
        )

    return SubprocessResult(
        args=normalized_args,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _coerce_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
