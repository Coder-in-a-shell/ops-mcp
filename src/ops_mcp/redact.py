"""Output redaction. Anything a tool returns passes through here first.

The goal is not perfect detection (no regex set achieves that) but a sensible floor: an
agent that asks for logs should never be handed live credentials or obvious personal data
just because they were written into a log line.
"""

from __future__ import annotations

import re

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_API_KEY = re.compile(r"(?i)\b(?:api[_-]?key|secret|password|passwd)\s*[=:]\s*\S+")
_CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")
_PHONE = re.compile(r"(?<!\w)\+?\d[\d ()-]{8,}\d(?!\w)")


def _luhn_ok(digits: str) -> bool:
    total, flip = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if flip:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        flip = not flip
    return total % 10 == 0


def redact(text: str) -> tuple[str, int]:
    """Return ``(clean_text, number_of_redactions)``."""
    count = 0

    def sub(pattern: re.Pattern, label: str, s: str, check=None) -> str:
        nonlocal count

        def repl(m: re.Match) -> str:
            nonlocal count
            if check is not None and not check(m.group(0)):
                return m.group(0)
            count += 1
            return f"[{label}]"

        return pattern.sub(repl, s)

    # Order matters: secrets first, then cards (Luhn-checked) before the looser phone rule.
    text = sub(_BEARER, "secret", text)
    text = sub(_JWT, "secret", text)
    text = sub(_AWS_KEY, "secret", text)
    text = sub(_API_KEY, "secret", text)
    text = sub(_EMAIL, "email", text)
    text = sub(_CARD, "card", text, check=lambda s: _luhn_ok(re.sub(r"\D", "", s)))
    text = sub(_PHONE, "phone", text)
    return text, count
