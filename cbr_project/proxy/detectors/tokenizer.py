"""
A more complex detector using tokeniziation to try to identify SQL syntax.
Libinjection is an existing library for SQLi detection that tokenizes the query and matches the tokens it to a database of "fingerprints", known injection patterns.
It leans toward prioritizing a low rate of false positives (especially compared to our attempts here), which means any matches are very likely injection attempts, but there's a risk of missing subtler attempts.
"""

import libinjection

from . import Severity


# Might want to run normalize?
# unsure if it would be helpful or not, comments etc are probably included in fingerprints
def check_value(value: str) -> tuple[Severity, str]:
    result = libinjection.is_sql_injection(value)
    if result["is_sqli"]:
        return (
            Severity.MALICIOUS,
            f"libinjection detection! fingerprint: {result['fingerprint']} ",
        )
    else:
        return (Severity.CLEAN, "")
