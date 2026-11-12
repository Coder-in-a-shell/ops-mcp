import pytest

from ops_mcp.redact import redact


@pytest.mark.parametrize(
    "text, expected, n",
    [
        ("failed to send to jane.doe@example.com: mailbox full", "failed to send to [email]: mailbox full", 1),
        ("sms retry for +91 98765 43210", "sms retry for [phone]", 1),
        ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123def456", "Authorization: [secret]", 1),
        ("declined card 4111 1111 1111 1111 for x", "declined card [card] for x", 1),
        ("config api_key=sk_live_abcdef123 loaded", "config [secret] loaded", 1),
        ("key " + "AKIA" + "ABCDEFGHIJKLMNOP" + " leaked", "key [secret] leaked", 1),
    ],
)
def test_redacts_sensitive_values(text, expected, n):
    assert redact(text) == (expected, n)


def test_leaves_ordinary_text_alone():
    text = "connection pool exhausted: 0 of 20 connections free, retry 3 of 5 in 250ms"
    assert redact(text) == (text, 0)


def test_card_numbers_are_luhn_checked_so_ordinary_ids_survive_as_cards():
    # A 16-digit number that fails Luhn is not a card. It may still be treated as a phone-like
    # number (the rules err on the side of redaction) but it must never be labelled a card.
    clean, _ = redact("order 1234567890123456 placed")
    assert "[card]" not in clean


def test_no_double_processing_of_placeholders():
    clean, n = redact("mail a@b.co and c@d.io")
    assert clean == "mail [email] and [email]" and n == 2
