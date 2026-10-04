"""EXAMPLE detector: database-metadata / recon tokens -> SUSPICIOUS.

One of the bundled example detectors — a template to copy, not a finished WAF.
These tokens show up when an attacker is enumerating the database (schema,
version, current user) rather than attacking a specific query. They are strong
hints but not a working injection on their own, so this flags SUSPICIOUS: the
request is forwarded, but repeated recon drives the client's score up and the
reputation throttle eventually kicks in.
"""

from . import Severity

_RECON_TOKENS = (
    "information_schema",  # standard SQL catalog (MySQL/Postgres/MSSQL)
    "sqlite_master",       # SQLite catalog (this app's backend)
    "pg_catalog",          # PostgreSQL catalog
    "@@version",           # MySQL/MSSQL version global
    "version()",           # MySQL/Postgres version function
    "database()",          # MySQL current-database function
)


def check_value(value):
    low = value.lower()
    if any(token in low for token in _RECON_TOKENS):
        return Severity.SUSPICIOUS, "database-metadata reference"
    return Severity.CLEAN, ""
