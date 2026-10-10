"""SQL injection detection: the plug-in point of the proxy.

The web layer calls `extract_inputs(...)` then `inspect(...)`. The individual
detectors live in the `detectors/` package, one per file; this module owns the
request-level framework (input extraction, findings, verdict) and delegates each
value to them through `check_value()`.
"""

from dataclasses import dataclass

import cbr_project.proxy.detectors as detectors
from cbr_project.proxy.detectors import Severity  # re-exported so callers can use detector.Severity

# Headers that are attacker-controlled and commonly end up in SQL queries
# (logging tables, analytics...). Extend as needed.
INSPECTED_HEADERS = ("User-Agent", "Referer", "X-Forwarded-For")


@dataclass
class Finding:
    location: str  # "path", "query", "form", "json", "body", "cookie", "header"
    name: str      # parameter / cookie / header name ("" for path and raw body)
    value: str          # the offending value as received
    severity: Severity  # Severity.SUSPICIOUS or Severity.MALICIOUS
    reason: str         # why check_value() flagged it


def _flatten_json(data, prefix=""):
    """Yield (dotted.name, value) for every scalar leaf of a JSON document."""
    if isinstance(data, dict):
        for key, value in data.items():
            yield from _flatten_json(value, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(data, list):
        for index, value in enumerate(data):
            yield from _flatten_json(value, f"{prefix}[{index}]")
    elif data is not None:
        yield prefix, str(data)


def extract_inputs(*, path, query=(), form=(), json_data=None, body="",
                   cookies=(), headers=None):
    """Collect every attacker-controlled value of a request into (location, name, value).

    Framework-agnostic: the web layer decodes the request and passes the pieces.
      path       str
      query      iterable of (name, value)   — already URL-decoded
      form       iterable of (name, value)   — urlencoded/multipart fields
      json_data  parsed JSON, or None
      body       raw text body (when it is neither form nor JSON)
      cookies    iterable of (name, value)
      headers    case-insensitive mapping with .get(name)
    """
    inputs = [("path", "", path)]

    for name, value in query:
        inputs.append(("query", name, value))

    if form:
        for name, value in form:
            inputs.append(("form", name, value))
    elif json_data is not None:
        for name, value in _flatten_json(json_data):
            inputs.append(("json", name, value))
    elif body:
        inputs.append(("body", "", body))

    for name, value in cookies:
        inputs.append(("cookie", name, value))

    if headers is not None:
        for name in INSPECTED_HEADERS:
            value = headers.get(name)
            if value:
                inputs.append(("header", name, value))

    return inputs


def check_value(value):
    """Decide whether a single value looks like a SQL injection.

    Runs every detector in the `detectors/` package and keeps the highest
    severity. Returns ``(Severity, reason)``; a clean value is
    ``(Severity.CLEAN, "")``.
    """
    return detectors.check_value(value)


def inspect(inputs):
    """Run check_value() over a list of (location, name, value) and return findings."""
    findings = []
    for location, name, value in inputs:
        severity, reason = check_value(value)
        if severity is not Severity.CLEAN:
            findings.append(Finding(location, name, value, severity, reason))
    return findings


def verdict(findings):
    """Reduce findings to a single verdict: the highest severity, or CLEAN."""
    return max((f.severity for f in findings), default=Severity.CLEAN)
