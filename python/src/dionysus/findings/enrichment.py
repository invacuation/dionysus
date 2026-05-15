"""Lightweight enrichment helpers for normalized findings."""

from __future__ import annotations

import re
from dataclasses import replace

from dionysus.imports.parsers import ParsedFinding

_CVE_PATTERN = re.compile(r"^CVE-(?P<year>\d{4})-(?P<number>\d{4,})$", re.IGNORECASE)
_NVD_CVE_URL_PREFIX = "https://nvd.nist.gov/vuln/detail/"


def cve_identifiers_for_finding(finding: ParsedFinding) -> list[str]:
    """Return ordered CVE identifiers from a parsed finding.

    Args:
        finding: Parsed finding that may include CVE identifiers in primary or
            secondary identifier fields.

    Returns:
        Uppercase CVE identifiers in first-seen order, with case-insensitive
        duplicates removed.
    """

    identifiers = [finding.primary_identifier, *finding.identifiers]
    seen: set[str] = set()
    cves: list[str] = []
    for identifier in identifiers:
        if not isinstance(identifier, str):
            continue
        match = _CVE_PATTERN.match(identifier)
        if match is None:
            continue

        cve = f"CVE-{match.group('year')}-{match.group('number')}".upper()
        if cve.casefold() in seen:
            continue

        cves.append(cve)
        seen.add(cve.casefold())
    return cves


def nvd_cve_url(cve_identifier: str) -> str:
    """Build the canonical NVD vulnerability URL for a CVE identifier.

    Args:
        cve_identifier: CVE identifier to place in the NVD detail URL.

    Returns:
        Canonical NVD detail URL with the CVE identifier uppercased.
    """

    return f"{_NVD_CVE_URL_PREFIX}{cve_identifier.upper()}"


def enrich_parsed_finding_with_cve_references(finding: ParsedFinding) -> ParsedFinding:
    """Return a parsed finding enriched with missing CVE source links.

    Existing reference order is preserved. Canonical NVD references are appended
    for CVE identifiers that do not already have that NVD link.

    Args:
        finding: Parsed finding to enrich.

    Returns:
        The original finding when no enrichment is needed, otherwise a new
        frozen dataclass instance with enriched references and source metadata.
    """

    cves = cve_identifiers_for_finding(finding)
    if not cves:
        return finding

    references = list(finding.references)
    seen_references = {reference.casefold().rstrip("/") for reference in references}
    added_links: list[str] = []
    for cve in cves:
        url = nvd_cve_url(cve)
        normalized_url = url.casefold().rstrip("/")
        if normalized_url in seen_references:
            continue

        references.append(url)
        seen_references.add(normalized_url)
        added_links.append(url)

    if not added_links:
        return finding

    source = {
        **finding.source,
        "enrichment": {
            **_safe_dict(finding.source.get("enrichment")),
            "cve_source_links": added_links,
        },
    }
    return replace(finding, references=references, source=source)


def _safe_dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    return {}
