"""EXAMPLE detector: time-based blind injection -> MALICIOUS.

One of the bundled example detectors — a template to copy, not a finished WAF.
Time-based blind SQLi makes the database pause so the attacker reads the answer
from the response time. The function names below do not occur in normal input,
so a plain case-insensitive substring match is enough.
"""

from . import Severity

# Pause/benchmark primitives across SQLite, MySQL, Postgres, MSSQL, Oracle.
_SLEEP_CALLS = (
    "sleep(",                   # MySQL / generic
    "pg_sleep",                 # PostgreSQL
    "benchmark(",               # MySQL CPU burn
    "waitfor delay",            # MSSQL
    "dbms_pipe.receive_message",  # Oracle
)


def check_value(value):
    low = value.lower()
    if any(call in low for call in _SLEEP_CALLS):
        return Severity.MALICIOUS, "time-based blind probe"
    return Severity.CLEAN, ""
