"""EXAMPLE detector: weaker SQL signals -> SUSPICIOUS (allowed, score goes up).

One of the bundled example detectors — a template to copy, not a finished WAF.
Plain string checks (no regex): a SQL comment marker, or a lone SQL keyword.
Note: "or"/"and" are left out on purpose — they are far too common in plain
text ("coffee or tea") to flag without drowning in false positives. A bare ';'
is not flagged either: it appears in normal input (a browser User-Agent like
"...(X11; Linux x86_64)..."), and a real stacked query starts with a SQL command,
which the keyword check below (or the obvious-injection rule for writes) catches.
"""

from . import Severity, words

_KEYWORDS = {"union", "select", "insert", "update", "delete", "drop"}


def check_value(value):
    if "--" in value or "/*" in value:
        return Severity.SUSPICIOUS, "SQL comment marker"
    if _KEYWORDS.intersection(words(value)):
        return Severity.SUSPICIOUS, "SQL keyword"
    return Severity.CLEAN, ""
