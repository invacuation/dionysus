import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dionysus.imports.parsers import ParserError
from dionysus.imports.trivy import parse_trivy_image_json

FIXTURE = Path(__file__).parent / "fixtures" / "trivy-image.json"


def test_trivy_parser_accepts_bytes_and_returns_scan_metadata() -> None:
    report = parse_trivy_image_json(FIXTURE.read_bytes())

    assert report.scanner == "trivy"
    assert report.report_kind == "trivy-image-json"
    assert report.parser_version
    assert report.target == "registry.example.test/dionysus/api:2026.05.07"
    assert report.metadata["artifact_name"] == "registry.example.test/dionysus/api:2026.05.07"
    assert report.metadata["artifact_type"] == "container_image"
    assert report.metadata["image_id"].startswith("sha256:")
    assert report.metadata["os"] == {"family": "debian", "name": "12.5"}
    assert report.scan_started_at == datetime(2026, 5, 7, 12, 34, 56, tzinfo=UTC)
    assert len(report.findings) == 2


def test_trivy_parser_accepts_string_payload() -> None:
    report = parse_trivy_image_json(FIXTURE.read_text())

    assert report.target == "registry.example.test/dionysus/api:2026.05.07"
    assert {finding.package_name for finding in report.findings} == {"openssl", "requests"}


def test_trivy_parser_normalizes_identifiers_and_package_context() -> None:
    report = parse_trivy_image_json(FIXTURE.read_bytes())

    os_finding = next(finding for finding in report.findings if finding.package_name == "openssl")
    assert os_finding.primary_identifier == "CVE-2026-1001"
    assert os_finding.identifiers[:3] == ["CVE-2026-1001", "CWE-787", "DSA-2026-001"]
    assert os_finding.additional_identifiers[:2] == ["CWE-787", "DSA-2026-001"]
    assert os_finding.package_version == "3.0.11-1"
    assert os_finding.fixed_version == "3.0.13-1"
    assert os_finding.package_path == "/usr/lib/ssl"
    assert os_finding.artifact_name == "registry.example.test/dionysus/api:2026.05.07"
    assert os_finding.artifact_type == "debian"
    assert os_finding.artifact_path == "registry.example.test/dionysus/api:2026.05.07 (debian 12.5)"
    assert os_finding.source["result_class"] == "os-pkgs"
    assert os_finding.source["description"] == "A representative OpenSSL vulnerability."
    assert os_finding.references == [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1001",
        "https://security-tracker.debian.org/tracker/CVE-2026-1001",
        "https://example.test/advisories/CVE-2026-1001",
    ]


def test_trivy_parser_chooses_cve_as_primary_identifier_when_present() -> None:
    report = parse_trivy_image_json(FIXTURE.read_text())

    lang_finding = next(
        finding for finding in report.findings if finding.package_name == "requests"
    )
    assert lang_finding.primary_identifier == "CVE-2026-2002"
    assert lang_finding.identifiers == ["CVE-2026-2002", "GHSA-abcd-1234-wxyz", "CWE-601"]
    assert lang_finding.additional_identifiers == ["GHSA-abcd-1234-wxyz", "CWE-601"]
    assert lang_finding.severity == "MEDIUM"
    assert lang_finding.package_path is None
    assert lang_finding.artifact_type == "python-pkg"
    assert lang_finding.artifact_path == "app/requirements.txt"


def test_trivy_parser_splits_cvss_by_source_and_version() -> None:
    report = parse_trivy_image_json(FIXTURE.read_bytes())
    lang_finding = next(
        finding for finding in report.findings if finding.package_name == "requests"
    )

    assert lang_finding.cvss == {
        "ghsa": {
            "v3": {
                "score": 6.5,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            },
        },
    }
    json.dumps(lang_finding.cvss)


@pytest.mark.parametrize("non_finite_score", ["NaN", "Infinity", "-Infinity"])
def test_trivy_parser_rejects_non_finite_cvss_score(
    non_finite_score: str,
) -> None:
    raw_payload = f"""
    {{
        "ArtifactName": "secret-registry.example.test/private:latest",
        "Results": [
            {{
                "Target": "private",
                "Vulnerabilities": [
                    {{
                        "VulnerabilityID": "CVE-2026-3003",
                        "PkgName": "unsafe-lib",
                        "CVSS": {{
                            "nvd": {{
                                "V3Score": {non_finite_score}
                            }}
                        }}
                    }}
                ]
            }}
        ]
    }}
    """

    with pytest.raises(ParserError) as exc_info:
        parse_trivy_image_json(raw_payload)

    message = str(exc_info.value)
    assert "invalid JSON" in message
    assert non_finite_score not in message
    assert "secret-registry" not in message
    assert "private:latest" not in message


def test_trivy_parser_missing_optional_fields_use_safe_empty_values() -> None:
    payload = {
        "ArtifactName": "registry.example.test/minimal:latest",
        "Results": [
            {
                "Target": "minimal",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "TEMP-0001",
                        "PkgName": "minimal-lib",
                    }
                ],
            }
        ],
    }

    report = parse_trivy_image_json(json.dumps(payload))

    finding = report.findings[0]
    assert finding.primary_identifier == "TEMP-0001"
    assert finding.additional_identifiers == []
    assert finding.severity == "UNKNOWN"
    assert finding.cvss == {}
    assert finding.package_version is None
    assert finding.fixed_version is None
    assert finding.package_path is None
    assert finding.artifact_type is None
    assert finding.references == []


def test_trivy_parser_normalizes_unrecognized_severity_to_unknown_for_duplicates() -> None:
    payload = {
        "ArtifactName": "registry.example.test/info:latest",
        "Results": [
            {
                "Target": "info",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "TEMP-INFO-0001",
                        "PkgName": "info-lib",
                        "InstalledVersion": "1.0.0",
                        "Severity": "INFORMATIONAL",
                    },
                ],
            }
        ],
    }

    report = parse_trivy_image_json(json.dumps(payload))

    assert report.findings[0].severity == "UNKNOWN"

    payload["Results"][0]["Vulnerabilities"].append(
        {
            "VulnerabilityID": "TEMP-INFO-0001",
            "PkgName": "info-lib",
            "InstalledVersion": "1.0.0",
            "Severity": "LOW",
        }
    )

    report = parse_trivy_image_json(json.dumps(payload))

    assert len(report.findings) == 1
    assert report.findings[0].severity == "LOW"


def test_trivy_parser_collapses_duplicates_conservatively() -> None:
    report = parse_trivy_image_json(FIXTURE.read_bytes())

    os_finding = next(finding for finding in report.findings if finding.package_name == "openssl")
    assert len([finding for finding in report.findings if finding.package_name == "openssl"]) == 1
    assert os_finding.severity == "CRITICAL"
    assert os_finding.additional_identifiers == ["CWE-787", "DSA-2026-001", "CWE-120"]
    assert os_finding.cvss["nvd"]["v3"]["score"] == 9.1
    assert os_finding.references == [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1001",
        "https://security-tracker.debian.org/tracker/CVE-2026-1001",
        "https://example.test/advisories/CVE-2026-1001",
    ]
    assert os_finding.dedupe_key == (
        "trivy|registry.example.test/dionysus/api:2026.05.07 (debian 12.5)|openssl|"
        "3.0.11-1|3.0.13-1|CVE-2026-1001"
    )


def test_trivy_parser_invalid_json_raises_safe_parser_error() -> None:
    raw_payload = b'{"ArtifactName":"secret-registry.example.test/private:latest",'

    with pytest.raises(ParserError) as exc_info:
        parse_trivy_image_json(raw_payload)

    message = str(exc_info.value)
    assert "invalid JSON" in message
    assert "secret-registry" not in message
    assert "private:latest" not in message
