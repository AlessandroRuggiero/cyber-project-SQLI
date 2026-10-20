"""Detector registry and the shared severity vocabulary: each module exposes check_value(value) -> (Severity, reason)."""

from enum import Enum
from functools import total_ordering


@total_ordering
class Severity(Enum):
    """How serious a flagged value is. Ordered: CLEAN < SUSPICIOUS < MALICIOUS.

    CLEAN      -> forwarded, no reputation cost
    SUSPICIOUS -> forwarded, but the client's suspicion score goes up a little
    MALICIOUS  -> blocked, and the suspicion score goes up a lot
    """

    CLEAN = 0
    SUSPICIOUS = 1
    MALICIOUS = 2

    def __str__(self):
        return self.name.lower()

    def __lt__(self, other):
        if isinstance(other, Severity):
            return self.value < other.value
        return NotImplemented


def words(text):
    found, current = [], []
    for ch in text:
        if ch.isalpha():
            current.append(ch.lower())
        elif current:
            found.append("".join(current))
            current = []
    if current:
        found.append("".join(current))
    return found


# Imported after Severity/words are defined so each detector module can do
# `from detectors import Severity, words` without a circular-import error.
from . import (  # noqa: E402
    regex_rules,
    #tokenizer,
)

# Every active detector.
DETECTORS = (
    regex_rules.check_value,
    #tokenizer.check_value,
)


def check_value(value):
    """Run every detector over `value` and return the highest-severity (Severity, reason).

    Returns ``(Severity.CLEAN, "")`` when nothing flags the value.
    """
    best = (Severity.CLEAN, "")
    for detector in DETECTORS:
        result = detector(value)
        if result[0] > best[0]:
            best = result
    return best
