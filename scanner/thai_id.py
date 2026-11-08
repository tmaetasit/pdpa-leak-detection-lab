"""Thai national ID detection: find candidates, validate the check digit, mask.

A Thai national ID has 13 digits. The 13th digit is a check digit computed
from the first 12:

    total = sum(digit[i] * (13 - i) for i in 0..11)
    check = (11 - total % 11) % 10

Validating it removes most false positives from random 13-digit numbers
(order IDs, tracking numbers, invoice references). A random 13-digit number
passes only about 1 time in 10.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# 13 digits, optionally written as 1-2345-67890-12-3 (dashes or spaces).
# Lookarounds stop us matching inside a longer run of digits.
CANDIDATE_RE = re.compile(
    r"(?<!\d)(\d[ -]?\d{4}[ -]?\d{5}[ -]?\d{2}[ -]?\d)(?!\d)"
)


def digits_only(text: str) -> str:
    return re.sub(r"\D", "", text)


def checksum_digit(first12: str) -> int:
    total = sum(int(d) * (13 - i) for i, d in enumerate(first12))
    return (11 - total % 11) % 10


def is_valid_thai_id(number: str) -> bool:
    """True when the number is 13 digits, starts with 1-8, and its check digit matches."""
    d = digits_only(number)
    if len(d) != 13 or d[0] in "09":
        return False
    return checksum_digit(d[:12]) == int(d[12])


def mask(number: str) -> str:
    """Keep only the first and last digit: 1-XXXX-XXXXX-XX-3."""
    d = digits_only(number)
    return f"{d[0]}-XXXX-XXXXX-XX-{d[12]}"


@dataclass
class Finding:
    valid: list[str]      # masked IDs that passed the checksum
    invalid_count: int    # 13-digit candidates that failed it

    @property
    def candidate_count(self) -> int:
        return len(self.valid) + self.invalid_count


def find_thai_ids(text: str, use_checksum: bool = True) -> Finding:
    """Find Thai IDs in text.

    With use_checksum=False every 13-digit candidate counts as a hit; this is
    the "regex only" baseline used to measure how much the checksum helps.
    """
    valid: list[str] = []
    invalid = 0
    for match in CANDIDATE_RE.finditer(text):
        raw = match.group(1)
        if not use_checksum or is_valid_thai_id(raw):
            valid.append(mask(raw))
        else:
            invalid += 1
    return Finding(valid=valid, invalid_count=invalid)
