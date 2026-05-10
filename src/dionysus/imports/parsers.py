"""Scanner-agnostic parser contracts for imported reports."""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

JSONValue = None | bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"]
JSONObject = dict[str, Any]
Parser = Callable[[bytes | str], "ParsedReport"]


class ParserProtocol(Protocol):
    """Callable parser interface for scanner report payloads.

    Args:
        payload: Raw scanner report content as bytes or text.

    Returns:
        A normalized parsed report.

    Raises:
        ParserError: If the payload cannot be safely parsed.
    """

    def __call__(self, payload: bytes | str) -> ParsedReport: ...


class ParserError(ValueError):
    """Safe parser failure that never includes raw report content."""


@dataclass(frozen=True)
class ParsedFinding:
    """A normalized vulnerability finding from a scanner report.

    Args:
        scanner: Stable scanner identifier.
        scanner_finding_id: Scanner-native finding identifier.
        primary_identifier: Preferred vulnerability identifier.
        identifiers: Ordered identifiers with the primary identifier first.
        additional_identifiers: Identifiers retained after the primary identifier.
        severity: Normalized scanner severity.
        cvss: JSON-compatible CVSS data grouped by source and version.
        package_name: Affected package name, when available.
        package_version: Installed package version, when available.
        fixed_version: Fixed package version, when available.
        package_path: Package path or lockfile location, when available.
        artifact_name: Report artifact name, such as an image reference.
        artifact_type: Scanner artifact type or package ecosystem.
        artifact_path: Scanner target path for this finding.
        dedupe_key: Conservative parser-level deduplication key.
        references: Ordered vulnerability reference URLs.
        source: Safe, JSON-compatible scanner context for later persistence.
    """

    scanner: str
    scanner_finding_id: str
    primary_identifier: str
    identifiers: list[str] = field(default_factory=list)
    additional_identifiers: list[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    cvss: JSONObject = field(default_factory=dict)
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    package_path: str | None = None
    artifact_name: str | None = None
    artifact_type: str | None = None
    artifact_path: str | None = None
    dedupe_key: str = ""
    references: list[str] = field(default_factory=list)
    source: JSONObject = field(default_factory=dict)


@dataclass(frozen=True)
class ParsedReport:
    """A normalized scanner report with metadata and findings.

    Args:
        scanner: Stable scanner identifier.
        report_kind: Stable report format identifier.
        parser_version: Parser implementation version.
        target: Human-readable report target, such as an image reference.
        metadata: JSON-compatible scan and target metadata.
        findings: Normalized findings parsed from the report.
        scan_started_at: Scanner-reported scan start time, when available.
        scan_finished_at: Scanner-reported scan finish time, when available.
    """

    scanner: str
    report_kind: str
    parser_version: str
    target: str
    metadata: JSONObject = field(default_factory=dict)
    findings: list[ParsedFinding] = field(default_factory=list)
    scan_started_at: datetime | None = None
    scan_finished_at: datetime | None = None


def json_object(mapping: Mapping[str, Any]) -> JSONObject:
    """Return a shallow JSON-compatible dictionary.

    Args:
        mapping: Mapping that may contain non-JSON values.

    Returns:
        A dictionary containing only JSON-compatible scalar, list, and dict values.
    """

    return {key: _json_value(value) for key, value in mapping.items()}


def string_list(values: Sequence[Any] | None) -> list[str]:
    """Return a list of non-empty string values.

    Args:
        values: Optional sequence of unknown values.

    Returns:
        Non-empty strings in their original order.
    """

    if values is None:
        return []
    return [value for value in values if isinstance(value, str) and value]


def _json_value(value: Any) -> JSONValue:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping):
        return {str(key): _json_value(nested) for key, nested in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_json_value(item) for item in value]
    return str(value)
