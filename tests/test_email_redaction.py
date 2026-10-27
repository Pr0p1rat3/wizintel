from __future__ import annotations

import subprocess
import sys

import pytest

from wizintel.redaction import redact_emails_in_text


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Alice+tag@Example.COM", "A***@example.com"),
        (
            "Contact <alice@example.com>, bob@example.org.",
            "Contact <a***@example.com>, b***@example.org.",
        ),
        ("mailto:alice@example.com", "mailto:a***@example.com"),
        (
            "https://example.com/?email=alice@example.com",
            "https://example.com/?email=a***@example.com",
        ),
        (
            "https://example.com/?email=alice%40example.com",
            "https://example.com/?email=a***%40example.com",
        ),
        ("/cases/alice@example.com/output", "/cases/a***@example.com/output"),
        ("a@example.com", "a***@example.com"),
        ("josé@example.com", "j***@example.com"),
        ("a***@example.com", "a***@example.com"),
        ("example.com and 203.0.113.10", "example.com and 203.0.113.10"),
    ],
)
def test_email_text_redaction(text: str, expected: str) -> None:
    assert redact_emails_in_text(text) == expected
    assert redact_emails_in_text(expected) == expected


def test_email_text_redaction_handles_long_adversarial_inputs() -> None:
    # A subprocess timeout fails safely if the new regex regresses to quadratic
    # behavior, without imposing a fragile sub-millisecond timing assertion.
    subprocess.run(
        [
            sys.executable,
            "-c",
            """
from wizintel.redaction import redact_emails_in_text
for text in ('a' * 250_000, 'a.' * 125_000, '%40' * 50_000,
             'a' * 250_000 + '@example.com', 'alice@' + 'x.' * 125_000):
    redact_emails_in_text(text)
""",
        ],
        check=True,
        timeout=5,
    )
