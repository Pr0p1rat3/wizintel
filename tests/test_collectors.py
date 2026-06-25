from __future__ import annotations

from pathlib import Path

from wizintel.collectors.amass import AmassCollector
from wizintel.collectors.sherlock import SherlockCollector
from wizintel.collectors.subfinder import SubfinderCollector
from wizintel.collectors.theharvester import TheHarvesterCollector
from wizintel.collectors.trufflehog import TruffleHogCollector

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_subfinder_parser() -> None:
    findings = SubfinderCollector().parse_output(fixture_text("subfinder_sample.json"))
    assert any(f.value == "admin.example.com" for f in findings)
    assert any(f.finding_type == "ip" for f in findings)


def test_amass_parser() -> None:
    findings = AmassCollector().parse_output(fixture_text("amass_sample.json"))
    assert any(f.value == "vpn.example.com" for f in findings)
    assert any(f.value == "203.0.113.20" for f in findings)


def test_theharvester_parser() -> None:
    findings = TheHarvesterCollector().parse_output(fixture_text("theharvester_sample.json"))
    assert any(
        f.finding_type == "email" and f.redacted_value == "a***@example.com"
        for f in findings
    )
    assert any(f.value == "dev.example.com" for f in findings)


def test_sherlock_parser_marks_unverified() -> None:
    findings = SherlockCollector().parse_output(fixture_text("sherlock_sample.json"))
    assert len(findings) == 1
    assert findings[0].finding_type == "username_profile"
    assert "unverified" in findings[0].tags


def test_trufflehog_parser_redacts_secrets() -> None:
    raw = fixture_text("trufflehog_sample.json")
    findings = TruffleHogCollector().parse_output(raw)
    assert len(findings) == 2
    assert all("AKIAIOSFODNN7EXAMPLE" not in f.model_dump_json() for f in findings)
    assert findings[0].evidence["verified"] is True
