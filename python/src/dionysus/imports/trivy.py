"""Parser for `trivy image --format json` reports."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, NoReturn

from dionysus.imports.parsers import (
    JSONObject,
    ParsedFinding,
    ParsedReport,
    ParserError,
    json_object,
    string_list,
)

SCANNER = "trivy"
REPORT_KIND = "trivy-image-json"
PARSER_VERSION = "1.0"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_SEVERITY_RANK = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def parse_trivy_image_json(payload: bytes | str) -> ParsedReport:
    """Parse a Trivy image JSON report into normalized scanner-agnostic data.

    Args:
        payload: Trivy JSON report content as bytes or text.

    Returns:
        Parsed report metadata and deduplicated findings.

    Raises:
        ParserError: If the payload is not valid Trivy image JSON. Error messages are
            sanitized and never include raw report content.
    """

    data = _load_report(payload)
    artifact_name = _string(data.get("ArtifactName")) or ""
    artifact_type = _string(data.get("ArtifactType"))
    metadata = _metadata(data, artifact_name, artifact_type)

    findings_by_key: dict[str, ParsedFinding] = {}
    for result in _results(data):
        result_target = _string(result.get("Target"))
        result_class = _string(result.get("Class"))
        result_type = _string(result.get("Type"))
        for vulnerability in _vulnerabilities(result):
            finding = _finding(
                vulnerability=vulnerability,
                artifact_name=artifact_name,
                result_target=result_target,
                result_class=result_class,
                result_type=result_type,
            )
            existing = findings_by_key.get(finding.dedupe_key)
            findings_by_key[finding.dedupe_key] = (
                finding if existing is None else _merge_duplicate(existing, finding)
            )

    return ParsedReport(
        scanner=SCANNER,
        report_kind=REPORT_KIND,
        parser_version=PARSER_VERSION,
        target=artifact_name,
        metadata=metadata,
        findings=list(findings_by_key.values()),
        scan_started_at=_datetime(data.get("CreatedAt")),
    )


def _load_report(payload: bytes | str) -> Mapping[str, Any]:
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ParserError("invalid JSON: report is not valid UTF-8") from exc

    if not isinstance(payload, str):
        raise ParserError("invalid Trivy report: payload must be bytes or string")

    try:
        data = json.loads(payload, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ParserError("invalid JSON: unable to parse Trivy report") from exc

    if not isinstance(data, Mapping):
        raise ParserError("invalid Trivy report: top-level JSON value must be an object")
    return data


def _reject_json_constant(_constant: str) -> NoReturn:
    raise ValueError("non-standard JSON constant")


def _metadata(
    data: Mapping[str, Any],
    artifact_name: str,
    artifact_type: str | None,
) -> JSONObject:
    report_metadata = data.get("Metadata")
    metadata: dict[str, Any] = {
        "artifact_name": artifact_name,
        "artifact_type": artifact_type,
    }
    if isinstance(report_metadata, Mapping):
        metadata["image_id"] = _string(report_metadata.get("ImageID"))
        metadata["repo_tags"] = string_list(_list(report_metadata.get("RepoTags")))
        metadata["repo_digests"] = string_list(_list(report_metadata.get("RepoDigests")))
        os_metadata = report_metadata.get("OS")
        if isinstance(os_metadata, Mapping):
            metadata["os"] = {
                "family": _string(os_metadata.get("Family")),
                "name": _string(os_metadata.get("Name")),
            }
    return json_object(metadata)


def _results(data: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    results = data.get("Results")
    if results is None:
        return []
    if not isinstance(results, list):
        raise ParserError("invalid Trivy report: Results must be a list")
    return [result for result in results if isinstance(result, Mapping)]


def _vulnerabilities(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    vulnerabilities = result.get("Vulnerabilities")
    if vulnerabilities is None:
        return []
    if not isinstance(vulnerabilities, list):
        raise ParserError("invalid Trivy report: Vulnerabilities must be a list")
    return [
        vulnerability for vulnerability in vulnerabilities if isinstance(vulnerability, Mapping)
    ]


def _finding(
    *,
    vulnerability: Mapping[str, Any],
    artifact_name: str,
    result_target: str | None,
    result_class: str | None,
    result_type: str | None,
) -> ParsedFinding:
    vulnerability_id = _string(vulnerability.get("VulnerabilityID")) or "UNKNOWN"
    package_name = _string(vulnerability.get("PkgName"))
    package_version = _string(vulnerability.get("InstalledVersion"))
    fixed_version = _string(vulnerability.get("FixedVersion"))
    primary_identifier, identifiers = _identifiers(vulnerability, vulnerability_id)
    severity = _normalize_severity(_string(vulnerability.get("Severity")))
    dedupe_key = _dedupe_key(
        result_target=result_target,
        package_name=package_name,
        package_version=package_version,
        fixed_version=fixed_version,
        primary_identifier=primary_identifier,
    )

    return ParsedFinding(
        scanner=SCANNER,
        scanner_finding_id=_scanner_finding_id(primary_identifier, package_name, package_version),
        primary_identifier=primary_identifier,
        identifiers=identifiers,
        additional_identifiers=[
            identifier for identifier in identifiers if identifier != primary_identifier
        ],
        severity=severity,
        cvss=_cvss(vulnerability.get("CVSS")),
        package_name=package_name,
        package_version=package_version,
        fixed_version=fixed_version,
        package_path=_string(vulnerability.get("PkgPath")),
        artifact_name=artifact_name or None,
        artifact_type=result_type,
        artifact_path=result_target,
        dedupe_key=dedupe_key,
        references=string_list(_list(vulnerability.get("References"))),
        source=json_object(
            {
                "scanner": SCANNER,
                "vulnerability_id": vulnerability_id,
                "package_id": _string(vulnerability.get("PkgID")),
                "result_target": result_target,
                "result_class": result_class,
                "result_type": result_type,
                "title": _string(vulnerability.get("Title")),
                "description": _string(vulnerability.get("Description")),
            }
        ),
    )


def _identifiers(
    vulnerability: Mapping[str, Any],
    vulnerability_id: str,
) -> tuple[str, list[str]]:
    identifiers = _unique(
        [
            *string_list(_list(vulnerability.get("CveIDs"))),
            vulnerability_id,
            *string_list(_list(vulnerability.get("CweIDs"))),
            *string_list(_list(vulnerability.get("VendorIDs"))),
        ]
    )
    cve_identifiers = [identifier for identifier in identifiers if _CVE_RE.match(identifier)]
    primary = cve_identifiers[0] if cve_identifiers else vulnerability_id
    ordered = _unique([primary, *identifiers])
    return primary, ordered


def _cvss(raw_cvss: Any) -> JSONObject:
    if not isinstance(raw_cvss, Mapping):
        return {}

    normalized: dict[str, Any] = {}
    for source, source_cvss in raw_cvss.items():
        if not isinstance(source, str) or not isinstance(source_cvss, Mapping):
            continue
        source_values: dict[str, Any] = {}
        v2 = _cvss_version(source_cvss, "V2")
        v3 = _cvss_version(source_cvss, "V3")
        if v2:
            source_values["v2"] = v2
        if v3:
            source_values["v3"] = v3
        if source_values:
            normalized[source] = source_values
    return json_object(normalized)


def _cvss_version(source_cvss: Mapping[str, Any], prefix: str) -> dict[str, Any]:
    version: dict[str, Any] = {}
    score = source_cvss.get(f"{prefix}Score")
    vector = _string(source_cvss.get(f"{prefix}Vector"))
    if isinstance(score, int | float) and not isinstance(score, bool) and math.isfinite(score):
        version["score"] = score
    if vector:
        version["vector"] = vector
    return version


def _merge_duplicate(existing: ParsedFinding, duplicate: ParsedFinding) -> ParsedFinding:
    identifiers = _unique([*existing.identifiers, *duplicate.identifiers])
    primary_identifier = existing.primary_identifier
    return ParsedFinding(
        scanner=existing.scanner,
        scanner_finding_id=existing.scanner_finding_id,
        primary_identifier=primary_identifier,
        identifiers=identifiers,
        additional_identifiers=[
            identifier for identifier in identifiers if identifier != primary_identifier
        ],
        severity=_highest_severity(existing.severity, duplicate.severity),
        cvss=_merge_cvss(existing.cvss, duplicate.cvss),
        package_name=existing.package_name,
        package_version=existing.package_version,
        fixed_version=existing.fixed_version,
        package_path=existing.package_path or duplicate.package_path,
        artifact_name=existing.artifact_name,
        artifact_type=existing.artifact_type,
        artifact_path=existing.artifact_path,
        dedupe_key=existing.dedupe_key,
        references=_unique([*existing.references, *duplicate.references]),
        source=_merge_source(existing.source, duplicate.source),
    )


def _merge_cvss(existing: JSONObject, duplicate: JSONObject) -> JSONObject:
    merged: dict[str, Any] = {}
    for source, values in existing.items():
        merged[source] = dict(values) if isinstance(values, Mapping) else values
    for source, source_values in duplicate.items():
        if not isinstance(source_values, Mapping):
            continue
        current = merged.setdefault(source, {})
        if isinstance(current, dict):
            current.update(source_values)
    return json_object(merged)


def _merge_source(existing: JSONObject, duplicate: JSONObject) -> JSONObject:
    duplicate_count = existing.get("duplicate_count", 1)
    if not isinstance(duplicate_count, int):
        duplicate_count = 1
    return json_object(
        {
            **existing,
            "duplicate_count": duplicate_count + 1,
            "duplicate_vulnerability_ids": _unique(
                [
                    _string(existing.get("vulnerability_id")),
                    _string(duplicate.get("vulnerability_id")),
                ]
            ),
        }
    )


def _highest_severity(left: str, right: str) -> str:
    return left if _SEVERITY_RANK.get(left, 0) >= _SEVERITY_RANK.get(right, 0) else right


def _dedupe_key(
    *,
    result_target: str | None,
    package_name: str | None,
    package_version: str | None,
    fixed_version: str | None,
    primary_identifier: str,
) -> str:
    parts = [
        SCANNER,
        result_target or "",
        package_name or "",
        package_version or "",
        fixed_version or "",
        primary_identifier,
    ]
    return "|".join(parts)


def _scanner_finding_id(
    primary_identifier: str,
    package_name: str | None,
    package_version: str | None,
) -> str:
    return ":".join([primary_identifier, package_name or "", package_version or ""])


def _normalize_severity(severity: str | None) -> str:
    normalized = severity.upper() if severity else "UNKNOWN"
    return normalized if normalized in _SEVERITY_RANK else "UNKNOWN"


def _unique(values: list[str | None]) -> list[str]:
    seen: set[str] = set()
    unique_values: list[str] = []
    for value in values:
        if value and value not in seen:
            unique_values.append(value)
            seen.add(value)
    return unique_values


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _datetime(value: Any) -> datetime | None:
    raw_value = _string(value)
    if raw_value is None:
        return None
    try:
        normalized = raw_value.strip().removesuffix("Z")
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ParserError("invalid Trivy report: CreatedAt must be an ISO-8601 datetime") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _list(value: Any) -> list[Any] | None:
    return value if isinstance(value, list) else None
