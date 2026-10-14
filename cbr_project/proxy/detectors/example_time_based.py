"""EXAMPLE detector: time-based blind injection (SLEEP / pg_sleep / WAITFOR DELAY) -> MALICIOUS."""

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
