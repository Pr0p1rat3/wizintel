from __future__ import annotations

from wizintel.schemas.finding import Finding
from wizintel.scoring import score_finding


def test_scores_public_email_low() -> None:
    finding = Finding(collector="test", finding_type="email", value="a@example.com")
    assert score_finding(finding).severity == "low"


def test_scores_interesting_subdomain_medium() -> None:
    finding = Finding(collector="test", finding_type="subdomain", value="vpn.example.com")
    assert score_finding(finding).severity == "medium"


def test_scores_unverified_username_profile_info() -> None:
    finding = Finding(
        collector="sherlock",
        finding_type="username_profile",
        value="https://github.com/example",
        tags=["unverified"],
    )
    assert score_finding(finding).severity == "info"


def test_scores_verified_secret_high() -> None:
    finding = Finding(
        collector="trufflehog",
        finding_type="secret_exposure",
        value="sha256:abc",
        evidence={"verified": True},
    )
    assert score_finding(finding).severity == "high"
