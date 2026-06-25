from __future__ import annotations

from wizintel.normalizers import (
    deduplicate_findings,
    normalize_domain,
    normalize_email,
    normalize_url,
    normalize_username,
)
from wizintel.schemas.finding import Finding


def test_normalizers() -> None:
    assert normalize_domain("https://Admin.Example.com/path") == "admin.example.com"
    assert normalize_email("User@Example.COM ") == "user@example.com"
    assert normalize_username("@SomeHandle") == "somehandle"
    assert normalize_url("GitHub.com/SomeHandle/") == "https://github.com/SomeHandle"


def test_deduplicate_findings() -> None:
    findings = [
        Finding(collector="a", finding_type="subdomain", value="Admin.Example.com"),
        Finding(collector="b", finding_type="subdomain", value="admin.example.com"),
        Finding(collector="c", finding_type="email", value="User@Example.com"),
    ]
    assert len(deduplicate_findings(findings)) == 2
