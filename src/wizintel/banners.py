"""Authorization and safety banners."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from wizintel.constants import APP_NAME, TAGLINE
from wizintel.redaction import redact_email
from wizintel.schemas.target import Target


def print_authorization_banner(console: Console) -> None:
    """Print the responsible-use banner."""
    console.print(
        Panel(
            (
                f"[bold]{APP_NAME}[/bold]\n{TAGLINE}\n\n"
                "Use this tool only for assets, repositories, accounts, and organizations "
                "you are authorized to assess. v1 is passive-first and does not implement "
                "active scanning, exploitation, brute force, authentication bypass, or "
                "intrusion workflows. Sherlock matches are unverified public profile matches."
            ),
            title="Authorization Required",
            border_style="yellow",
        )
    )


def print_scan_banner(console: Console, target: Target) -> None:
    """Print a pre-scan banner."""
    mode = "passive" if target.passive else "active"
    target_value = redact_email(target.value) if target.type == "email" else target.value
    console.print(
        Panel(
            (
                f"Target type: [bold]{target.type}[/bold]\n"
                f"Target: [bold]{target_value}[/bold]\n"
                f"Mode: [bold]{mode}[/bold]\n"
                f"Scope note: {target.scope_note}"
            ),
            title="Scan Scope",
            border_style="cyan",
        )
    )
