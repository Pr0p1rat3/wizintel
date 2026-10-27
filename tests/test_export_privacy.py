from __future__ import annotations

import csv
import json
from html import unescape
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from wizintel.api.main import app as api_app
from wizintel.cli import app as cli_app
from wizintel.collectors.theharvester import TheHarvesterCollector
from wizintel.collectors.trufflehog import TruffleHogCollector
from wizintel.config import WizIntelConfig
from wizintel.db.storage import Storage
from wizintel.orchestrator import regenerate_report, run_scan, write_default_artifacts
from wizintel.reports.csv_report import CSV_COLUMNS, write_csv_report
from wizintel.reports.html import write_html_report
from wizintel.reports.json_report import build_json_report, write_json_report
from wizintel.schemas.finding import Finding
from wizintel.schemas.scan import Scan
from wizintel.schemas.target import Target

TARGET_EMAIL = "owner@example.com"
FINDING_EMAIL = "alice@example.com"
OTHER_EMAIL = "amanda@example.com"


@pytest.fixture
def privacy_case(tmp_path: Path) -> tuple[Scan, list[Finding]]:
    scan = Scan(
        target=Target(
            type="email",
            value=TARGET_EMAIL,
            authorized=True,
            scope_note=f"Requested by {TARGET_EMAIL}",
        ),
        output_dir=str(tmp_path / TARGET_EMAIL),
    )
    findings = TheHarvesterCollector().parse_output(json.dumps({"emails": [FINDING_EMAIL]}))
    findings[0].scan_id = scan.id
    findings[0].source = f"https://example.com/contact?email={FINDING_EMAIL}"
    findings[0].tags.append(f"contact:{OTHER_EMAIL}")
    findings[0].evidence = {
        "contacts": [TARGET_EMAIL, {"owner": OTHER_EMAIL, "count": 2, "verified": True}],
        FINDING_EMAIL: {"line": 10},
        OTHER_EMAIL: {"line": 20},
        "a***@example.com#2": {"line": 30},
        "optional": None,
    }
    return scan, findings


def assert_no_original_emails(text: str) -> None:
    text = unescape(text).lower()
    for email in (TARGET_EMAIL, FINDING_EMAIL, OTHER_EMAIL):
        assert email not in text


@pytest.mark.parametrize("output_format", ["json", "csv", "html"])
def test_default_reports_mask_all_exported_email_fields(
    privacy_case: tuple[Scan, list[Finding]],
    output_format: str,
) -> None:
    scan, findings = privacy_case
    before = [scan.model_dump_json(), findings[0].model_dump_json()]
    path = regenerate_report(scan, findings, output_format=output_format)
    text = path.read_text(encoding="utf-8")
    assert_no_original_emails(text)
    assert "a***@example.com" in text
    assert before == [scan.model_dump_json(), findings[0].model_dump_json()]
    if output_format == "json":
        report = json.loads(text)
        assert report["metadata"]["redaction_mode"] == "redacted"
        assert report["scan"]["target"]["value"] == "o***@example.com"
        exported = report["findings"][0]
        assert exported["value"] == exported["redacted_value"] == "a***@example.com"
        assert exported["source"] == "https://example.com/contact?email=a***@example.com"
        evidence = exported["evidence"]
        assert evidence["contacts"][1] == {
            "owner": "a***@example.com",
            "count": 2,
            "verified": True,
        }
        assert sorted(v["line"] for v in evidence.values() if isinstance(v, dict)) == [10, 20, 30]
        assert evidence["optional"] is None
        assert set(exported) == set(findings[0].model_dump())
    if output_format == "csv":
        rows = list(csv.DictReader(text.splitlines()))
        assert list(rows[0]) == CSV_COLUMNS
        assert rows[0]["redacted_value"] == "a***@example.com"


@pytest.mark.parametrize("output_format", ["json", "csv", "html"])
@pytest.mark.parametrize(
    "redacted_value", [None, "", FINDING_EMAIL, "a***@example.com", "[withheld]"]
)
def test_reports_do_not_trust_missing_or_unmasked_collector_values(
    tmp_path: Path,
    output_format: str,
    redacted_value: str | None,
) -> None:
    scan = Scan(
        target=Target(type="email", value=TARGET_EMAIL, authorized=True), output_dir=str(tmp_path)
    )
    # model_copy also exercises legacy/imported findings with a null redacted_value.
    finding = Finding(collector="fixture", finding_type="email", value=FINDING_EMAIL).model_copy(
        update={"redacted_value": redacted_value}
    )
    path = regenerate_report(scan, [finding], output_format=output_format)
    text = path.read_text(encoding="utf-8")
    assert_no_original_emails(text)
    if redacted_value == "[withheld]":
        assert "[withheld]" in text


def test_empty_redaction_is_not_replaced_with_raw_value(tmp_path: Path) -> None:
    finding = Finding(
        collector="fixture", finding_type="metadata", value="private", redacted_value=""
    )
    path = write_csv_report([finding], tmp_path / "findings.csv")
    rows = list(csv.DictReader(path.read_text().splitlines()))
    assert rows[0]["redacted_value"] == ""


@pytest.mark.parametrize("output_format", ["json", "csv", "html"])
def test_full_export_is_explicit_and_keeps_default_files(
    privacy_case: tuple[Scan, list[Finding]],
    output_format: str,
) -> None:
    scan, findings = privacy_case
    default_path = regenerate_report(scan, findings, output_format=output_format)
    default_text = default_path.read_text()
    full_path = regenerate_report(
        scan, findings, output_format=output_format, include_sensitive=True
    )
    assert ".full." in full_path.name
    assert full_path != default_path
    assert default_path.read_text() == default_text
    full_text = full_path.read_text()
    assert FINDING_EMAIL in full_text
    if output_format == "json":
        full = json.loads(full_text)
        assert full["metadata"]["redaction_mode"] == "full-fidelity"
        assert full["scan"] == scan.model_dump(mode="json")
        assert full["findings"] == [finding.model_dump(mode="json") for finding in findings]
    elif output_format == "csv":
        row = next(iter(csv.DictReader(full_text.splitlines())))
        assert list(row) == [*CSV_COLUMNS, "value"]
        assert row["value"] == FINDING_EMAIL
        assert row["redacted_value"] == "a***@example.com"
    else:
        assert TARGET_EMAIL in full_text
        assert "Full-fidelity export" in full_text
    # The next invocation returns to the default policy.
    assert (
        regenerate_report(scan, findings, output_format=output_format).read_text() == default_text
    )


def test_default_artifacts_and_stored_data_have_separate_privacy_policies(
    privacy_case: tuple[Scan, list[Finding]],
    tmp_path: Path,
) -> None:
    scan, findings = privacy_case
    storage = Storage(tmp_path / "cases.db")
    storage.update_scan(scan)
    storage.save_findings(findings)
    stored_scan = storage.get_scan(scan.id)
    assert stored_scan is not None
    stored_findings = storage.get_findings_for_scan(scan.id)
    for path in write_default_artifacts(stored_scan, stored_findings, tmp_path / "reports"):
        assert_no_original_emails(path.read_text())
    assert storage.get_scan(scan.id).target.value == TARGET_EMAIL
    assert storage.get_findings_for_scan(scan.id)[0].value == FINDING_EMAIL


def test_automatic_email_scan_reports_are_masked(tmp_path: Path) -> None:
    config = WizIntelConfig.model_validate({"app": {"data_dir": str(tmp_path)}})
    target = Target(type="email", value=TARGET_EMAIL, authorized=True)
    execution = run_scan(target, config, collectors=[])
    for name in ("findings.json", "findings.csv", "report.html"):
        assert_no_original_emails((execution.output_dir / name).read_text())
    assert execution.scan.target.value == TARGET_EMAIL


@pytest.mark.parametrize(
    "target_type,value",
    [
        ("domain", "example.com"),
        ("username", "analyst"),
        ("github_repo", "https://github.com/example/repo"),
    ],
)
def test_non_email_data_is_preserved(tmp_path: Path, target_type: str, value: str) -> None:
    scan = Scan.model_validate(
        {
            "target": {"type": target_type, "value": value, "authorized": True},
            "output_dir": str(tmp_path),
        }
    )
    finding = Finding(
        collector="fixture",
        finding_type="subdomain",
        value="vpn.example.com",
        evidence={"port": 443, "verified": False},
    )
    report = build_json_report(scan, [finding])
    assert report["scan"] == scan.model_dump(mode="json")
    assert report["findings"] == [finding.model_dump(mode="json")]


@pytest.mark.parametrize("include_sensitive", [False, True])
def test_secret_values_remain_unrecoverable(tmp_path: Path, include_sensitive: bool) -> None:
    fixture = (Path(__file__).parent / "fixtures" / "trufflehog_sample.json").read_text()
    findings = TruffleHogCollector().parse_output(fixture)
    scan = Scan(
        target=Target(type="domain", value="example.com", authorized=True), output_dir=str(tmp_path)
    )
    paths = [
        write_json_report(
            scan, findings, tmp_path / "findings.json", include_sensitive=include_sensitive
        ),
        write_csv_report(findings, tmp_path / "findings.csv", include_sensitive=include_sensitive),
        write_html_report(
            scan, findings, tmp_path / "report.html", include_sensitive=include_sensitive
        ),
    ]
    for path in paths:
        assert "AKIAIOSFODNN7EXAMPLE" not in path.read_text()


@pytest.mark.parametrize("include_sensitive", [False, True])
def test_html_escapes_untrusted_fields(tmp_path: Path, include_sensitive: bool) -> None:
    payload = '<script>alert("test")</script>'
    scan = Scan(
        target=Target(type="username", value=payload, authorized=True), output_dir=str(tmp_path)
    )
    finding = Finding(collector="fixture", finding_type="metadata", value=payload, source=payload)
    path = write_html_report(
        scan, [finding], tmp_path / "report.html", include_sensitive=include_sensitive
    )
    assert payload not in path.read_text()
    assert "&lt;script&gt;" in path.read_text()


@pytest.mark.parametrize("query", ["", "?include_sensitive=true"])
def test_api_always_masks_list_and_detail_responses(
    privacy_case: tuple[Scan, list[Finding]],
    tmp_path: Path,
    monkeypatch,
    query: str,
) -> None:
    scan, findings = privacy_case
    config = WizIntelConfig.model_validate({"app": {"data_dir": str(tmp_path)}})
    storage = Storage(config.db_path)
    storage.update_scan(scan)
    storage.save_findings(findings)
    monkeypatch.setattr("wizintel.api.routes.load_config", lambda: config)
    with TestClient(api_app) as client:
        listing = client.get(f"/scans{query}")
        detail = client.get(f"/scans/{scan.id}{query}")
        assert listing.status_code == detail.status_code == 200
        assert_no_original_emails(listing.text)
        assert_no_original_emails(detail.text)
        assert listing.json()[0]["target"]["value"] == "o***@example.com"
        assert set(detail.json()) == {"scan", "findings"}
        assert detail.json()["findings"][0]["value"] == "a***@example.com"
        assert client.get("/scans/missing").status_code == 404
    assert storage.get_findings_for_scan(scan.id)[0].value == FINDING_EMAIL


@pytest.mark.parametrize("command", ["case", "latest"])
@pytest.mark.parametrize("include_sensitive", [False, True])
def test_cli_export_policy(
    privacy_case: tuple[Scan, list[Finding]],
    tmp_path: Path,
    monkeypatch,
    command: str,
    include_sensitive: bool,
) -> None:
    monkeypatch.chdir(tmp_path)
    scan, findings = privacy_case
    storage = Storage(tmp_path / "data" / "wizintel.db")
    storage.update_scan(scan)
    storage.save_findings(findings)
    args = ["report", command]
    if command == "case":
        args.append(scan.id)
    args.extend(["--json", "--csv", "--html"])
    if include_sensitive:
        args.append("--include-sensitive")
    result = CliRunner().invoke(cli_app, args)
    assert result.exit_code == 0, result.output
    assert ("Sensitive export" in result.output) == include_sensitive
    suffix = ".full" if include_sensitive else ""
    for name in (f"findings{suffix}.json", f"findings{suffix}.csv", f"report{suffix}.html"):
        text = (Path(scan.output_dir) / name).read_text()
        if include_sensitive:
            assert FINDING_EMAIL in text
        else:
            assert_no_original_emails(text)
