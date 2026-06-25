"""Typer CLI for WizIntel."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from wizintel.banners import print_authorization_banner, print_scan_banner
from wizintel.collectors.registry import get_default_collectors
from wizintel.config import load_config, write_default_config
from wizintel.constants import APP_NAME, DEFAULT_CONFIG_FILE, VERSION
from wizintel.db.storage import Storage
from wizintel.exceptions import ActiveScanNotSupportedError, AuthorizationError
from wizintel.orchestrator import regenerate_report, run_scan
from wizintel.schemas.target import Target, TargetType
from wizintel.utils.filesystem import ensure_dir
from wizintel.utils.tool_detection import detect_tool

console = Console()
app = typer.Typer(
    name="wizintel",
    help="Passive OSINT and external exposure intelligence for security analysts.",
    no_args_is_help=True,
)
tools_app = typer.Typer(help="External tool checks.")
scan_app = typer.Typer(help="Run passive scans.")
report_app = typer.Typer(help="Generate reports from stored cases.")
app.add_typer(tools_app, name="tools")
app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"{APP_NAME} {VERSION}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, help="Show version and exit."),
    ] = False,
) -> None:
    """WizIntel CLI."""


@app.command()
def init(
    config_path: Annotated[
        Path, typer.Option("--config", "-c", help="Config file to create.")
    ] = Path(DEFAULT_CONFIG_FILE),
    data_dir: Annotated[
        Path | None, typer.Option("--data-dir", help="Data directory to create.")
    ] = None,
) -> None:
    """Create config.yml and local data directories."""
    print_authorization_banner(console)
    created_config = write_default_config(config_path)
    config = load_config(config_path)
    target_data_dir = data_dir or config.data_dir
    ensure_dir(target_data_dir)
    ensure_dir(target_data_dir / "cases")
    Storage(target_data_dir / "wizintel.db")
    console.print(f"[green]Data directory ready:[/green] {target_data_dir}")
    console.print(
        f"[green]Config {'created' if created_config else 'already exists'}:[/green] {config_path}"
    )
    console.print("Next steps: run [bold]wizintel tools check[/bold], then run a passive scan.")


@tools_app.command("check")
def tools_check(
    config_path: Annotated[
        Path, typer.Option("--config", "-c", help="Config file to load.")
    ] = Path(DEFAULT_CONFIG_FILE),
) -> None:
    """Check whether external collector binaries are installed."""
    config = load_config(config_path)
    table = Table(title="WizIntel Collector Tool Status")
    table.add_column("Tool")
    table.add_column("Found")
    table.add_column("Path")
    table.add_column("Version")
    table.add_column("Collector Status")
    for collector in get_default_collectors():
        settings = config.collector_settings(collector.name)
        if collector.requires_binary and collector.binary_name is not None:
            detected = detect_tool(collector.name, collector.binary_name)
            found = detected.found
            path = detected.path or "-"
            version = detected.version or "-"
        else:
            found = True
            path = "-"
            version = "-"
        if not settings.enabled:
            status = "disabled"
        elif found:
            status = "ready"
        else:
            status = "missing binary"
        table.add_row(
            collector.name,
            "true" if found else "false",
            path,
            version,
            status,
        )
    console.print(table)


@scan_app.command("domain")
def scan_domain(
    value: Annotated[str, typer.Argument(help="Authorized domain to assess.")],
    passive: Annotated[
        bool, typer.Option("--passive/--active", help="Passive mode only; active is refused.")
    ] = True,
    config_path: Annotated[
        Path, typer.Option("--config", "-c", help="Config file to load.")
    ] = Path(DEFAULT_CONFIG_FILE),
    scope_note: Annotated[
        str, typer.Option("--scope-note", help="Scope and authorization note.")
    ] = "CLI supplied domain scope.",
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized/--not-authorized",
            help="Confirm you are authorized to assess this target.",
        ),
    ] = True,
) -> None:
    """Run passive domain OSINT collectors."""
    _run_scan("domain", value, passive, config_path, scope_note, authorized)


@scan_app.command("email")
def scan_email(
    value: Annotated[str, typer.Argument(help="Authorized email address to assess.")],
    passive: Annotated[
        bool, typer.Option("--passive/--active", help="Passive mode only; active is refused.")
    ] = True,
    config_path: Annotated[
        Path, typer.Option("--config", "-c", help="Config file to load.")
    ] = Path(DEFAULT_CONFIG_FILE),
    scope_note: Annotated[
        str, typer.Option("--scope-note", help="Scope and authorization note.")
    ] = "CLI supplied email scope.",
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized/--not-authorized",
            help="Confirm you are authorized to assess this target.",
        ),
    ] = True,
) -> None:
    """Run passive email-oriented OSINT where supported."""
    _run_scan("email", value, passive, config_path, scope_note, authorized)


@scan_app.command("username")
def scan_username(
    value: Annotated[str, typer.Argument(help="Authorized username handle to assess.")],
    passive: Annotated[
        bool, typer.Option("--passive/--active", help="Passive mode only; active is refused.")
    ] = True,
    config_path: Annotated[
        Path, typer.Option("--config", "-c", help="Config file to load.")
    ] = Path(DEFAULT_CONFIG_FILE),
    scope_note: Annotated[
        str, typer.Option("--scope-note", help="Scope and authorization note.")
    ] = "CLI supplied username scope.",
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized/--not-authorized",
            help="Confirm you are authorized to assess this target.",
        ),
    ] = True,
) -> None:
    """Run Sherlock public profile discovery."""
    _run_scan("username", value, passive, config_path, scope_note, authorized)


@scan_app.command("github")
def scan_github(
    value: Annotated[str, typer.Argument(help="Authorized public GitHub repository URL.")],
    passive: Annotated[
        bool, typer.Option("--passive/--active", help="Passive mode only; active is refused.")
    ] = True,
    config_path: Annotated[
        Path, typer.Option("--config", "-c", help="Config file to load.")
    ] = Path(DEFAULT_CONFIG_FILE),
    scope_note: Annotated[
        str, typer.Option("--scope-note", help="Scope and authorization note.")
    ] = "CLI supplied public GitHub repository scope.",
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized/--not-authorized",
            help="Confirm you are authorized to assess this target.",
        ),
    ] = True,
) -> None:
    """Run safe public-repository TruffleHog checks."""
    _run_scan("github_repo", value, passive, config_path, scope_note, authorized)


@report_app.command("latest")
def report_latest(
    html: Annotated[bool, typer.Option("--html", help="Generate HTML report.")] = False,
    json_report: Annotated[
        bool, typer.Option("--json", help="Generate JSON report.")
    ] = False,
    csv: Annotated[bool, typer.Option("--csv", help="Generate CSV report.")] = False,
    config_path: Annotated[
        Path, typer.Option("--config", "-c", help="Config file to load.")
    ] = Path(DEFAULT_CONFIG_FILE),
) -> None:
    """Generate or regenerate reports for the latest case."""
    config = load_config(config_path)
    storage = Storage(config.db_path)
    scan = storage.get_latest_scan()
    if scan is None:
        console.print("[red]No scans found.[/red]")
        raise typer.Exit(1)
    _write_requested_reports(storage, scan.id, html=html, json_report=json_report, csv=csv)


@report_app.command("case")
def report_case(
    case_id: Annotated[str, typer.Argument(help="Case ID to report.")],
    html: Annotated[bool, typer.Option("--html", help="Generate HTML report.")] = False,
    json_report: Annotated[
        bool, typer.Option("--json", help="Generate JSON report.")
    ] = False,
    csv: Annotated[bool, typer.Option("--csv", help="Generate CSV report.")] = False,
    config_path: Annotated[
        Path, typer.Option("--config", "-c", help="Config file to load.")
    ] = Path(DEFAULT_CONFIG_FILE),
) -> None:
    """Generate or regenerate a case report."""
    config = load_config(config_path)
    storage = Storage(config.db_path)
    _write_requested_reports(storage, case_id, html=html, json_report=json_report, csv=csv)


def _run_scan(
    target_type: TargetType,
    value: str,
    passive: bool,
    config_path: Path,
    scope_note: str,
    authorized: bool,
) -> None:
    config = load_config(config_path)
    target = Target(
        type=target_type,
        value=value,
        scope_note=scope_note,
        authorized=authorized,
        passive=passive,
    )
    print_authorization_banner(console)
    print_scan_banner(console, target)
    try:
        execution = run_scan(target, config)
    except (AuthorizationError, ActiveScanNotSupportedError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(f"[green]Scan complete:[/green] {execution.scan.id}")
    console.print(f"Findings: {execution.scan.findings_count}")
    console.print(f"Output: {execution.output_dir}")
    for warning in execution.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")
    for error in execution.errors:
        console.print(f"[red]Error:[/red] {error}")


def _write_requested_reports(
    storage: Storage,
    case_id: str,
    *,
    html: bool,
    json_report: bool,
    csv: bool,
) -> None:
    scan = storage.get_scan(case_id)
    if scan is None:
        console.print(f"[red]Case not found:[/red] {case_id}")
        raise typer.Exit(1)
    findings = storage.get_findings_for_scan(case_id)
    formats = _requested_formats(html=html, json_report=json_report, csv=csv)
    for output_format in formats:
        path = regenerate_report(scan, findings, output_format=output_format)
        console.print(f"[green]{output_format.upper()} report:[/green] {path}")


def _requested_formats(*, html: bool, json_report: bool, csv: bool) -> list[str]:
    formats: list[str] = []
    if html:
        formats.append("html")
    if json_report:
        formats.append("json")
    if csv:
        formats.append("csv")
    return formats or ["html"]


if __name__ == "__main__":
    app()
