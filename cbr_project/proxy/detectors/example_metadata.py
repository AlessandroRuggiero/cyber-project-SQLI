"""EXAMPLE detector: database-metadata / recon tokens (information_schema, sqlite_master, ...) -> SUSPICIOUS."""

from . import Severity

_RECON_TOKENS = (
    "information_schema",  # standard SQL catalog (MySQL/Postgres/MSSQL)
    "sqlite_master",  # SQLite catalog (this app's backend)
    "pg_catalog",  # PostgreSQL catalog
    "@@version",  # MySQL/MSSQL version global
    "version()",  # MySQL/Postgres version function
    "database()",  # MySQL current-database function
)


def check_value(value):
    low = value.lower()
    if any(token in low for token in _RECON_TOKENS):
        return Severity.SUSPICIOUS, "database-metadata reference"
    return Severity.CLEAN, ""
