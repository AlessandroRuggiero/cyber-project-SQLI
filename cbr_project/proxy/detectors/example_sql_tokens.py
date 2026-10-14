"""EXAMPLE detector: weaker SQL signals (a comment marker or a lone SQL keyword) -> SUSPICIOUS."""

from . import Severity, words

_KEYWORDS = {"union", "select", "insert", "update", "delete", "drop"}


def check_value(value):
    if "--" in value or "/*" in value:
        return Severity.SUSPICIOUS, "SQL comment marker"
    if _KEYWORDS.intersection(words(value)):
        return Severity.SUSPICIOUS, "SQL keyword"
    return Severity.CLEAN, ""
