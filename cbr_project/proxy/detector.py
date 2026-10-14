"""SQL injection detection: the plug-in point of the proxy, delegating each value to detectors/."""

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Literal

import cbr_project.proxy.detectors as detectors
from cbr_project.proxy.detectors import Severity  # re-exported so callers can use detector.Severity

Location = Literal["path", "query", "form", "json", "body", "cookie", "header"]

# Headers that are attacker-controlled and commonly end up in SQL queries
# (logging tables, analytics...). Extend as needed.
INSPECTED_HEADERS = ("User-Agent", "Referer", "X-Forwarded-For")


@dataclass
class Finding:
    location: Location
    name: str  # parameter / cookie / header name ("" for path and raw body)
    value: str  # the offending value as received
    severity: Severity  # Severity.SUSPICIOUS or Severity.MALICIOUS
    reason: str  # why check_value() flagged it


# Path style follows JSONPath's dot/bracket addressing (IETF draft-ietf-jsonpath-base-05): a.b[0].
def _flatten_json(data: object, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Yield (dotted.name, value) for every scalar leaf of a JSON document."""
    if isinstance(data, dict):
        for key, value in data.items():
            yield from _flatten_json(value, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(data, list):
        for index, value in enumerate(data):
            yield from _flatten_json(value, f"{prefix}[{index}]")
    elif data is not None:
        yield prefix, str(data)


def extract_inputs(
    *,
    path: str,
    query: Iterable[tuple[str, str]] = (),  # already URL-decoded
    form: Iterable[tuple[str, str]] = (),
    json_data: object = None,
    body: str = "",
    cookies: Iterable[tuple[str, str]] = (),
    headers: Mapping[str, str] | None = None,  # case-insensitive .get(name)
) -> list[tuple[Location, str, str]]:
    """Collect every attacker-controlled value of a request into (location, name, value)."""
    inputs: list[tuple[Location, str, str]] = [("path", "", path)]

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


def inspect(inputs: list[tuple[Location, str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for location, name, value in inputs:
        severity, reason = detectors.check_value(value)
        if severity is not Severity.CLEAN:
            findings.append(Finding(location, name, value, severity, reason))
    return findings


def verdict(findings: list[Finding]) -> Severity:
    return max((f.severity for f in findings), default=Severity.CLEAN)
