import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.analyzers.crypto.base import CryptoRuleAnalyzer, crypto_findings_for_assets

_SHARED_PROJECT = "p4"
_SHARED_SCAN = "s4"
_ASSET_LIMIT = 50_000
_POLL_ATTEMPTS = 200
_POLL_INTERVAL_SECONDS = 0.1
_NON_TERMINAL_STATUSES = ("running", "pending", "processing", None)
# Regenerated per call, so it is the one field two evaluations of the same rules cannot share.
_GENERATED_FIELD = "id"


def _without_generated_ids(findings):
    return [{key: value for key, value in finding.items() if key != _GENERATED_FIELD} for finding in findings]


def _rule(rule_id, ft, **extra):
    return CryptoRule(
        rule_id=rule_id,
        name=rule_id,
        description="",
        finding_type=ft,
        default_severity=Severity.HIGH,
        source=CryptoPolicySource.CUSTOM,
        **extra,
    )


@pytest.mark.asyncio
async def test_analyzer_emits_findings_for_matching_assets(db):
    repo = CryptoAssetRepository(db)
    await repo.bulk_upsert(
        "p",
        "s",
        [
            CryptoAsset(
                project_id="p",
                scan_id="s",
                bom_ref="a1",
                name="MD5",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.HASH,
            ),
            CryptoAsset(
                project_id="p",
                scan_id="s",
                bom_ref="a2",
                name="SHA-256",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.HASH,
            ),
        ],
    )
    policy = CryptoPolicy(
        scope="system",
        version=1,
        rules=[
            _rule("md5", FindingType.CRYPTO_WEAK_ALGORITHM, match_name_patterns=["MD5"]),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(policy)

    analyzer = CryptoRuleAnalyzer(
        name="crypto_weak_algorithm",
        finding_types={FindingType.CRYPTO_WEAK_ALGORITHM},
    )
    result = await analyzer.analyze(
        sbom={},
        settings={},
        parsed_components=None,
        project_id="p",
        scan_id="s",
        db=db,
    )
    findings = result["findings"]
    assert len(findings) == 1
    assert findings[0]["component"].startswith("MD5")
    assert findings[0]["type"] == "crypto_weak_algorithm"


@pytest.mark.asyncio
async def test_analyzer_only_emits_for_its_finding_types(db):
    repo = CryptoAssetRepository(db)
    await repo.bulk_upsert(
        "p2",
        "s2",
        [
            CryptoAsset(
                project_id="p2",
                scan_id="s2",
                bom_ref="a",
                name="RSA",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.PKE,
                key_size_bits=1024,
            ),
        ],
    )
    policy = CryptoPolicy(
        scope="system",
        version=1,
        rules=[
            _rule(
                "rsa-quantum",
                FindingType.CRYPTO_QUANTUM_VULNERABLE,
                match_name_patterns=["RSA"],
                quantum_vulnerable=True,
            ),
            _rule("rsa-short", FindingType.CRYPTO_WEAK_KEY, match_name_patterns=["RSA"], match_min_key_size_bits=2048),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(policy)

    weak_key = CryptoRuleAnalyzer(
        name="crypto_weak_key",
        finding_types={FindingType.CRYPTO_WEAK_KEY},
    )
    result = await weak_key.analyze(
        sbom={},
        settings={},
        parsed_components=None,
        project_id="p2",
        scan_id="s2",
        db=db,
    )
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "crypto_weak_key"


@pytest.mark.asyncio
async def test_analyzer_respects_disabled_rule(db):
    await CryptoAssetRepository(db).bulk_upsert(
        "p3",
        "s3",
        [
            CryptoAsset(
                project_id="p3",
                scan_id="s3",
                bom_ref="a",
                name="MD5",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.HASH,
            ),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(
            scope="system",
            version=1,
            rules=[
                _rule("md5", FindingType.CRYPTO_WEAK_ALGORITHM, match_name_patterns=["MD5"], enabled=False),
            ],
        )
    )
    analyzer = CryptoRuleAnalyzer(
        name="crypto_weak_algorithm",
        finding_types={FindingType.CRYPTO_WEAK_ALGORITHM},
    )
    result = await analyzer.analyze(
        sbom={},
        settings={},
        parsed_components=None,
        project_id="p3",
        scan_id="s3",
        db=db,
    )
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_analyzer_adds_nothing_to_the_shared_rule_evaluation(db):
    """``crypto_findings_for_assets`` is shared with the ad-hoc path, which owns no scan.

    The analyzer's whole contribution over it is the stored assets, the resolved policy and the
    finding-type filter, so a change made for the other caller cannot pass unseen here.
    """
    stored = [
        CryptoAsset(
            project_id=_SHARED_PROJECT,
            scan_id=_SHARED_SCAN,
            bom_ref="a1",
            name="MD5",
            asset_type=CryptoAssetType.ALGORITHM,
            primitive=CryptoPrimitive.HASH,
        ),
        CryptoAsset(
            project_id=_SHARED_PROJECT,
            scan_id=_SHARED_SCAN,
            bom_ref="a2",
            name="RSA",
            asset_type=CryptoAssetType.ALGORITHM,
            primitive=CryptoPrimitive.PKE,
            key_size_bits=1024,
        ),
        CryptoAsset(
            project_id=_SHARED_PROJECT,
            scan_id=_SHARED_SCAN,
            bom_ref="a3",
            name="SHA-256",
            asset_type=CryptoAssetType.ALGORITHM,
            primitive=CryptoPrimitive.HASH,
        ),
    ]
    await CryptoAssetRepository(db).bulk_upsert(_SHARED_PROJECT, _SHARED_SCAN, stored)

    owned = _rule("md5", FindingType.CRYPTO_WEAK_ALGORITHM, match_name_patterns=["MD5", "SHA-256"])
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(
            scope="system",
            version=1,
            rules=[
                owned,
                _rule(
                    "rsa-short",
                    FindingType.CRYPTO_WEAK_KEY,
                    match_name_patterns=["RSA"],
                    match_min_key_size_bits=2048,
                ),
                _rule("sha256-off", FindingType.CRYPTO_WEAK_ALGORITHM, match_name_patterns=["SHA-256"], enabled=False),
            ],
        )
    )
    analyzer = CryptoRuleAnalyzer(
        name="crypto_weak_algorithm",
        finding_types={FindingType.CRYPTO_WEAK_ALGORITHM},
    )

    result = await analyzer.analyze(
        sbom={},
        settings={},
        parsed_components=None,
        project_id=_SHARED_PROJECT,
        scan_id=_SHARED_SCAN,
        db=db,
    )

    assets = await CryptoAssetRepository(db).list_by_scan(_SHARED_PROJECT, _SHARED_SCAN, limit=_ASSET_LIMIT)
    expected = crypto_findings_for_assets(assets, [owned])
    assert expected, "the rule must actually match, or the comparison is vacuous"
    assert _without_generated_ids(result["findings"]) == _without_generated_ids(expected)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_end_to_end_cbom_ingest_creates_findings(client, db, running_worker, api_key_headers):
    """CBOM ingest + analyzer dispatch produce findings in the findings collection.

    The scan legitimately ends ``failed`` — it carries no SBOM — while the crypto findings are
    still written, so the assertion is about the findings and not about the scan status.
    """
    import json
    from pathlib import Path

    from app.models.crypto_policy import CryptoPolicy

    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(
            scope="system",
            version=1,
            rules=[
                _rule("md5", FindingType.CRYPTO_WEAK_ALGORITHM, match_name_patterns=["MD5"]),
            ],
        )
    )

    fix = Path(__file__).parent.parent / "fixtures" / "cbom" / "legacy_crypto_mixed.json"
    payload = {
        "scan_metadata": {},
        "cbom": json.loads(fix.read_text()),
    }
    resp = await client.post("/api/v1/ingest/cbom", json=payload, headers=api_key_headers)
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    import asyncio

    for _ in range(_POLL_ATTEMPTS):
        scan = await db.scans.find_one({"_id": scan_id})
        if scan and scan.get("status") not in _NON_TERMINAL_STATUSES:
            break
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)

    findings = [f async for f in db.findings.find({"scan_id": scan_id})]
    md5_findings = [
        f for f in findings if f.get("type") == "crypto_weak_algorithm" and f.get("details", {}).get("rule_id") == "md5"
    ]
    assert len(md5_findings) >= 1
