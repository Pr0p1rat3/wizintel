"""Scan orchestration."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from wizintel.collectors.base import BaseCollector
from wizintel.collectors.registry import collectors_for_target
from wizintel.config import WizIntelConfig
from wizintel.db.storage import Storage
from wizintel.exceptions import ActiveScanNotSupportedError, AuthorizationError
from wizintel.logging_config import configure_scan_logger
from wizintel.normalizers import deduplicate_findings
from wizintel.redaction import redact_email
from wizintel.reports import write_csv_report, write_html_report, write_json_report
from wizintel.schemas.collector import CollectorContext
from wizintel.schemas.finding import Finding
from wizintel.schemas.scan import Scan
from wizintel.schemas.target import Target
from wizintel.scoring import score_findings
from wizintel.utils.filesystem import ensure_dir
from wizintel.utils.time import utc_now, utc_timestamp_slug


@dataclass(frozen=True)
class ScanExecution:
    """Completed scan execution details."""

    scan: Scan
    findings: list[Finding]
    warnings: list[str]
    errors: list[str]
    output_dir: Path


def run_scan(
    target: Target,
    config: WizIntelConfig,
    *,
    collectors: Sequence[BaseCollector] | None = None,
) -> ScanExecution:
    """Run an authorized passive scan and generate default artifacts."""
    _validate_scan_scope(target)
    storage = Storage(config.db_path)
    case_id = f"case_{utc_timestamp_slug()}_{uuid4().hex[:8]}"
    output_dir = ensure_dir(config.data_dir / "cases" / case_id)
    raw_dir = ensure_dir(output_dir / "raw")
    logger = configure_scan_logger(case_id, output_dir / "scan.log")
    logger.info("scan_id=%s", case_id)
    logger.info("target_type=%s target=%s", target.type, _safe_target_value(target))
    logger.info("passive_mode=%s output_path=%s", target.passive, output_dir)

    scan = storage.create_scan(target, output_dir, scan_id=case_id)
    selected_collectors = list(collectors) if collectors is not None else collectors_for_target(
        target.type, config
    )
    logger.info(
        "collectors_selected=%s",
        ",".join(collector.name for collector in selected_collectors),
    )

    all_findings: list[Finding] = []
    warnings: list[str] = []
    errors: list[str] = []
    collectors_run: list[str] = []

    for collector in selected_collectors:
        settings = config.collector_settings(collector.name)
        context = CollectorContext(
            scan_id=scan.id,
            output_dir=raw_dir,
            passive=target.passive,
            settings=settings.model_dump(mode="json"),
        )
        result = collector.run(target, config, context, logger=logger)
        warnings.extend(result.warnings)
        errors.extend(result.errors)
        if result.command:
            collectors_run.append(collector.name)
            logger.info("collector=%s command=%s", collector.name, result.command)
        for warning in result.warnings:
            logger.warning("collector=%s warning=%s", collector.name, warning)
        for error in result.errors:
            logger.error("collector=%s error=%s", collector.name, error)
        all_findings.extend(result.findings)

    scored_findings = score_findings(
        deduplicate_findings(all_findings),
        interesting_keywords=config.scoring.interesting_keywords,
    )
    storage.save_findings(scored_findings)

    status = "partial" if errors else "completed"
    completed_scan = scan.model_copy(
        update={
            "completed_at": utc_now(),
            "status": status,
            "collectors_run": collectors_run,
            "findings_count": len(scored_findings),
        }
    )
    storage.update_scan(completed_scan)
    write_default_artifacts(completed_scan, scored_findings, output_dir)
    logger.info("findings_count=%s status=%s", len(scored_findings), status)
    return ScanExecution(
        scan=completed_scan,
        findings=scored_findings,
        warnings=warnings,
        errors=errors,
        output_dir=output_dir,
    )


def write_default_artifacts(scan: Scan, findings: list[Finding], output_dir: Path) -> list[Path]:
    """Write standard case artifacts."""
    return [
        write_json_report(scan, findings, output_dir / "findings.json"),
        write_csv_report(findings, output_dir / "findings.csv"),
        write_html_report(scan, findings, output_dir / "report.html"),
    ]


def regenerate_report(
    scan: Scan,
    findings: list[Finding],
    *,
    output_format: str,
) -> Path:
    """Regenerate a report for an existing case."""
    output_dir = Path(scan.output_dir)
    if output_format == "json":
        return write_json_report(scan, findings, output_dir / "findings.json")
    if output_format == "csv":
        return write_csv_report(findings, output_dir / "findings.csv")
    if output_format == "html":
        return write_html_report(scan, findings, output_dir / "report.html")
    raise ValueError(f"Unsupported report format: {output_format}")


def _validate_scan_scope(target: Target) -> None:
    if not target.authorized:
        raise AuthorizationError("Scan refused: target scope is not authorized.")
    if not target.passive:
        raise ActiveScanNotSupportedError("Active scanning is not implemented in WizIntel v1.")


def _safe_target_value(target: Target) -> str:
    if target.type == "email":
        return redact_email(target.value)
    return target.value
