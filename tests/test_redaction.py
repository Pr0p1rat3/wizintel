from __future__ import annotations

from wizintel.redaction import redact_email, redact_secret, redact_token_like_strings


def test_redact_email_masks_local_part() -> None:
    assert redact_email("Admin@Example.com") == "A***@example.com"
    assert redact_email("Admin@Example.com", mask_local=False) == "Admin@example.com"


def test_redact_secret_preserves_edges_when_long_enough() -> None:
    assert redact_secret("abcd12345678wxyz") == "abcd...wxyz"
    assert redact_secret("short") == "[redacted]"


def test_redact_token_like_strings() -> None:
    text = "token=abc123XYZ789abc123XYZ789"
    redacted = redact_token_like_strings(text)
    assert "abc123XYZ789abc123XYZ789" not in redacted
    assert "abc1" in redacted
