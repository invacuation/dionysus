from dionysus.findings.enrichment import enrich_parsed_finding_with_cve_references
from dionysus.imports.parsers import ParsedFinding


def _finding(
    *,
    primary_identifier: str = "CVE-2026-1001",
    identifiers: list[str] | None = None,
    references: list[str] | None = None,
) -> ParsedFinding:
    return ParsedFinding(
        scanner="trivy",
        scanner_finding_id=primary_identifier,
        primary_identifier=primary_identifier,
        identifiers=identifiers if identifiers is not None else [primary_identifier],
        severity="HIGH",
        dedupe_key=f"trivy|{primary_identifier}|pkg:openssl",
        references=references if references is not None else [],
    )


def test_enrichment_adds_nvd_reference_for_cve_with_no_references() -> None:
    enriched = enrich_parsed_finding_with_cve_references(_finding())

    assert enriched.references == ["https://nvd.nist.gov/vuln/detail/CVE-2026-1001"]


def test_enrichment_preserves_existing_reference_order() -> None:
    enriched = enrich_parsed_finding_with_cve_references(
        _finding(
            references=[
                "https://vendor.example.test/advisories/CVE-2026-1001",
                "https://security.example.test/CVE-2026-1001",
            ],
        )
    )

    assert enriched.references == [
        "https://vendor.example.test/advisories/CVE-2026-1001",
        "https://security.example.test/CVE-2026-1001",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1001",
    ]


def test_enrichment_does_not_duplicate_existing_nvd_reference_case_insensitively() -> None:
    enriched = enrich_parsed_finding_with_cve_references(
        _finding(
            primary_identifier="cve-2026-1001",
            identifiers=["cve-2026-1001"],
            references=["https://nvd.nist.gov/vuln/detail/cve-2026-1001"],
        )
    )

    assert enriched.references == ["https://nvd.nist.gov/vuln/detail/cve-2026-1001"]


def test_enrichment_ignores_non_cve_identifiers() -> None:
    finding = _finding(primary_identifier="GHSA-abcd-1234-wxyz", identifiers=["TEMP-0001"])

    enriched = enrich_parsed_finding_with_cve_references(finding)

    assert enriched is finding
    assert enriched.references == []
