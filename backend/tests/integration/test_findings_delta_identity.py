"""The findings delta matches what the analyzers actually persist across two scans.

Each case runs real analyzer output through the aggregator and the engine's persist path, so the
delta sees the documents a scan stores, including the fields that drift between runs.
"""

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.finding import Finding, FindingType, Severity
from app.repositories.findings import FindingRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _persist_findings_and_waivers, _prepare_finding_records
from app.services.analytics.findings_delta import (
    FINDING_IDENTITY_PROJECTION,
    compute_findings_delta,
    finding_identity_key,
)
from app.services.analyzers.crypto.base import crypto_findings_for_assets
from app.services.analyzers.crypto.catalogs.loader import CipherSuiteEntry
from app.services.analyzers.crypto.certificate_lifecycle import evaluate_certificates
from app.services.analyzers.crypto.protocol_cipher import evaluate_protocols
from app.services.crypto_policy.resolver import EffectivePolicy
from tests.helpers.findings import stored_vulnerability

_PROJECT = "identity-project"
# Whole seconds, so the server's millisecond precision cannot move the dates the tests compare.
_NOW = datetime.now(timezone.utc).replace(microsecond=0)
_FIXTURES = Path(__file__).parents[1] / "fixtures"
_KICS = json.loads((_FIXTURES / "iac/kics_2.1.20_results.json").read_text())
_OPENGREP = json.loads((_FIXTURES / "sast/crypto_misuse_findings.json").read_text())

_DATABASES = [
    pytest.param("attrappe", id="attrappe"),
    pytest.param("real-mongo", marks=pytest.mark.live_mongo, id="real-mongo"),
]

_NO_POLICY = EffectivePolicy(rules=[], system_rules=[], system_version=1, override_version=None)
_MD5_RULE = CryptoRule(
    rule_id="md5",
    name="MD5",
    description="MD5 is broken",
    finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
    default_severity=Severity.HIGH,
    source=CryptoPolicySource.CUSTOM,
    match_name_patterns=["MD5"],
)
_RC4_SUITE = CipherSuiteEntry(
    name="TLS_RSA_WITH_RC4_128_MD5",
    value="0x00,0x04",
    key_exchange="RSA",
    authentication="RSA",
    cipher="RC4_128",
    mac="MD5",
    weaknesses=["weak-cipher-rc4", "weak-mac-md5"],
)


def _days_ago(days: int) -> datetime:
    return _NOW - timedelta(days=days)


def _aggregated(*results: tuple[str, dict]) -> list[Finding]:
    aggregator = ResultAggregator()
    for analyzer, result in results:
        aggregator.aggregate(analyzer, result)
    return aggregator.get_findings()


async def _persist(db, scan_id: str, findings: list[Finding], created_at: datetime = _NOW) -> None:
    records, _ = _prepare_finding_records(findings, scan_id, _PROJECT, created_at)
    await _persist_findings_and_waivers(records, scan_id, _PROJECT, FindingRepository(db), db)


async def _delta(db, from_scan: str = "scan-a", to_scan: str = "scan-b"):
    return await compute_findings_delta(
        db,
        project_id=_PROJECT,
        from_scan=from_scan,
        to_scan=to_scan,
        page=1,
        page_size=50,
        change=None,
        severity=None,
        finding_type=None,
    )


def _totals(response) -> tuple[int, int, int]:
    return response.totals.added, response.totals.removed, response.totals.unchanged


def _kics_shifted(lines: int) -> dict:
    shifted = copy.deepcopy(_KICS)
    for query in shifted["queries"]:
        for entry in query["files"]:
            entry["line"] += lines
    return shifted


def _kics_with_a_second_instance() -> dict:
    grown = copy.deepcopy(_KICS)
    files = grown["queries"][0]["files"]
    files.append({**files[0], "line": 9, "similarity_id": "0" * 64})
    return grown


def _opengrep_shifted(lines: int) -> dict:
    shifted = copy.deepcopy(_OPENGREP)
    for result in shifted["results"]:
        result["start"]["line"] += lines
        result["end"]["line"] += lines
    return shifted


def _outdated(latest: str) -> dict:
    return {
        "outdated_dependencies": [
            {
                "component": "lodash",
                "current_version": "4.17.20",
                "latest_version": latest,
                "purl": "pkg:npm/lodash@4.17.20",
                "severity": "INFO",
                "message": f"Update available: {latest}",
            }
        ],
        "ahead_of_default": [
            {
                "component": "react",
                "current_version": "19.1.0-rc",
                "default_version": "19.0.0",
                "purl": "pkg:npm/react@19.1.0-rc",
                "severity": "INFO",
                "message": "Installed 19.1.0-rc is newer than the registry default 19.0.0.",
            }
        ],
    }


def _maintainer_risk(days_since_release: int) -> dict:
    return {
        "maintainer_issues": [
            {
                "component": "left-pad",
                "version": "1.3.0",
                "purl": "pkg:npm/left-pad@1.3.0",
                "risks": [
                    {
                        "type": "stale_package",
                        "severity_score": 3,
                        "message": f"No releases in {days_since_release} days - potentially abandoned",
                        "detail": "Last release: 2025-08-01",
                    }
                ],
                "severity": "MEDIUM",
                "maintainer_info": {},
            }
        ]
    }


def _crypto(bom_suffix: str) -> list[tuple[str, dict]]:
    md5 = CryptoAsset(
        project_id=_PROJECT,
        scan_id="s",
        bom_ref=f"crypto/md5-{bom_suffix}",
        name="MD5",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.HASH,
        occurrence_locations=["src/hash.py:4"],
    )
    cert = CryptoAsset(
        project_id=_PROJECT,
        scan_id="s",
        bom_ref=f"crypto/cert-{bom_suffix}",
        name="api.example.com",
        asset_type=CryptoAssetType.CERTIFICATE,
        subject_name="CN=api.example.com",
        issuer_name="CN=Example CA",
        not_valid_after=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )
    tls = CryptoAsset(
        project_id=_PROJECT,
        scan_id="s",
        bom_ref=f"crypto/tls-{bom_suffix}",
        name="TLS",
        asset_type=CryptoAssetType.PROTOCOL,
        protocol_type="tls",
        version="1.2",
        cipher_suites=[_RC4_SUITE.name],
    )
    return [
        ("crypto_weak_algorithm", {"findings": crypto_findings_for_assets([md5], [_MD5_RULE], scanner="md5")}),
        ("crypto_certificate_lifecycle", evaluate_certificates([cert], _NO_POLICY)),
        ("crypto_protocol_cipher", evaluate_protocols([tls], _NO_POLICY, catalog={_RC4_SUITE.name: _RC4_SUITE})),
    ]


def _every_type() -> list[Finding]:
    kics = _kics_with_a_second_instance()
    kics["queries"][1]["files"][0]["similarity_id"] = None
    vulnerability = Finding.model_validate(
        stored_vulnerability("lodash", "4.17.20", [{"id": "CVE-2021-23337"}, {"id": "CVE-2020-8203", "waived": True}])
    )
    return [
        vulnerability,
        *_aggregated(
            ("kics", kics),
            ("opengrep", _OPENGREP),
            ("outdated_packages", _outdated("4.17.21")),
            ("maintainer_risk", _maintainer_risk(400)),
            (
                "end_of_life",
                {
                    "eol_issues": [
                        {"component": "python", "version": "3.8.10", "eol_info": {"cycle": "3.8", "eol": "2024-10-07"}}
                    ]
                },
            ),
            (
                "license_compliance",
                {
                    "license_issues": [
                        {
                            "component": "tzdata",
                            "version": "2026c",
                            "license": "GPL-2.0-only",
                            "severity": "HIGH",
                            "category": "strong_copyleft",
                            "message": "Strong copyleft",
                        }
                    ]
                },
            ),
            (
                "typosquatting",
                {
                    "typosquatting_issues": [
                        {
                            "component": "axios2",
                            "version": "1.0.0",
                            "imitated_package": "axios",
                            "similarity": 0.92,
                            "severity": "CRITICAL",
                            "message": "similar to axios",
                        }
                    ]
                },
            ),
            (
                "trufflehog",
                {
                    "findings": [
                        {
                            "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/config.py", "line": 3}}},
                            "SourceType": 15,
                            "DetectorType": 2,
                            "DetectorName": "AWS",
                            "Verified": False,
                            "Raw": "AKIAIOSFODNN7EXAMPLE",
                        }
                    ]
                },
            ),
            *_crypto("1"),
        ),
    ]


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_every_path_an_extractor_reads_is_projected(db):
    await _persist(db, "scan-a", _every_type())

    stored = {doc["_id"]: doc async for doc in db.findings.find({"scan_id": "scan-a"})}
    projected = {doc["_id"]: doc async for doc in db.findings.find({"scan_id": "scan-a"}, FINDING_IDENTITY_PROJECTION)}

    assert {doc["type"] for doc in stored.values()} >= {
        "vulnerability",
        "iac",
        "sast",
        "crypto_key_management",
        "outdated",
        "quality",
        "eol",
        "license",
        "malware",
        "secret",
        "crypto_weak_algorithm",
        "crypto_cert_expired",
        "crypto_weak_protocol",
    }
    assert {i: finding_identity_key(d) for i, d in projected.items()} == {
        i: finding_identity_key(d) for i, d in stored.items()
    }
    assert {i: finding_identity_key(d, include_waived=True) for i, d in projected.items()} == {
        i: finding_identity_key(d, include_waived=True) for i, d in stored.items()
    }


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_second_instance_of_an_iac_rule_in_one_file_is_added(db, database):
    await _persist(db, "scan-a", _aggregated(("kics", _KICS)))
    await _persist(db, "scan-b", _aggregated(("kics", _kics_with_a_second_instance())))

    assert _totals(await _delta(db)) == (1, 0, 6)


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_iac_findings_that_moved_down_the_file_are_unchanged(db, database):
    await _persist(db, "scan-a", _aggregated(("kics", _KICS)))
    await _persist(db, "scan-b", _aggregated(("kics", _kics_shifted(3))))

    assert _totals(await _delta(db)) == (0, 0, 6)


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_sast_findings_that_moved_down_the_file_are_unchanged(db, database):
    await _persist(db, "scan-a", _aggregated(("opengrep", _OPENGREP)))
    await _persist(db, "scan-b", _aggregated(("opengrep", _opengrep_shifted(2))))

    assert _totals(await _delta(db)) == (0, 0, 3)


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_an_upstream_release_leaves_outdated_findings_unchanged(db, database):
    await _persist(db, "scan-a", _aggregated(("outdated_packages", _outdated("4.17.21"))))
    await _persist(db, "scan-b", _aggregated(("outdated_packages", _outdated("4.17.22"))))

    assert _totals(await _delta(db)) == (0, 0, 2)


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_maintainer_risk_whose_day_count_grew_is_unchanged(db, database):
    await _persist(db, "scan-a", _aggregated(("maintainer_risk", _maintainer_risk(400))))
    await _persist(db, "scan-b", _aggregated(("maintainer_risk", _maintainer_risk(401))))

    assert _totals(await _delta(db)) == (0, 0, 1)


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_crypto_findings_with_regenerated_bom_refs_are_unchanged(db, database):
    await _persist(db, "scan-a", _aggregated(*_crypto("1")))
    await _persist(db, "scan-b", _aggregated(*_crypto("2")))

    assert _totals(await _delta(db)) == (0, 0, 3)


@pytest.mark.parametrize("database", _DATABASES)
@pytest.mark.asyncio
async def test_a_removed_finding_reports_its_first_detection_not_its_scan_date(db, database):
    lodash = Finding.model_validate(stored_vulnerability("lodash", "4.17.20", [{"id": "CVE-2021-23337"}]))
    await _persist(db, "scan-1", [lodash], _days_ago(200))
    await _persist(db, "scan-a", [lodash], _days_ago(100))
    await _persist(db, "scan-b", [], _NOW)

    [removed] = (await _delta(db)).items

    assert (removed.change, removed.first_seen) == ("removed", _days_ago(200))
