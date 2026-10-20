from collections import Counter

import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.analyzers.crypto.base import crypto_findings_for_assets
from app.services.cbom_parser import parse_crypto_components
from tests.helpers.analyzers import evaluate_crypto, ingest_and_analyze_cbom, scan_cbom
from tests.helpers.cbom import load_cbom, store_assets

_SHARED_PROJECT = "p4"
_SHARED_SCAN = "s4"
_ASSET_LIMIT = 50_000
_POLL_ATTEMPTS = 200
_POLL_INTERVAL_SECONDS = 0.1
_NON_TERMINAL_STATUSES = ("running", "pending", "processing", None)


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
    await store_assets(
        db,
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

    result = await evaluate_crypto("crypto_weak_algorithm", db)
    findings = result["findings"]
    assert len(findings) == 1
    assert findings[0]["component"].startswith("MD5")
    assert findings[0]["type"] == "crypto_weak_algorithm"


@pytest.mark.asyncio
async def test_analyzer_only_emits_for_its_finding_types(db):
    await store_assets(
        db,
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

    result = await evaluate_crypto("crypto_weak_key", db, "p2", "s2")
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "crypto_weak_key"


@pytest.mark.asyncio
async def test_analyzer_respects_disabled_rule(db):
    await store_assets(
        db,
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
    result = await evaluate_crypto("crypto_weak_algorithm", db, "p3", "s3")
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_analyzer_adds_nothing_to_the_shared_rule_evaluation(db):
    """crypto_findings_for_assets is shared with the ad-hoc path, so a change made for that caller must show here."""
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
    await store_assets(db, _SHARED_PROJECT, _SHARED_SCAN, stored)

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

    result = await evaluate_crypto("crypto_weak_algorithm", db, _SHARED_PROJECT, _SHARED_SCAN)

    assets = await CryptoAssetRepository(db).list_by_scan(_SHARED_PROJECT, _SHARED_SCAN, limit=_ASSET_LIMIT)
    expected = crypto_findings_for_assets(assets, [owned], scanner="crypto_weak_algorithm")
    assert expected, "the rule must actually match, or the comparison is vacuous"
    assert result["findings"] == expected


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_end_to_end_cbom_ingest_creates_findings(client, db, running_worker, api_key_headers):
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
    payload = {"cbom": json.loads(fix.read_text())}
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


def test_a_rule_finding_carries_the_first_twenty_locations_and_the_total():
    (parsed,) = parse_crypto_components(
        [
            {
                "type": "cryptographic-asset",
                "bom-ref": "md5",
                "name": "MD5",
                "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
                "evidence": {
                    "occurrences": [{"location": f"src/Crypto{index}.java", "line": index} for index in range(25)]
                },
            }
        ]
    )
    asset = CryptoAsset(project_id="p", scan_id="s", **parsed.model_dump())
    rule = _rule("md5", FindingType.CRYPTO_WEAK_ALGORITHM, match_name_patterns=["MD5"])
    (finding,) = crypto_findings_for_assets([asset], [rule], scanner="crypto_weak_algorithm")
    assert finding["found_in"] == asset.occurrence_locations[:20]
    assert finding["details"]["occurrence_count"] == 25


def test_every_crypto_finding_names_the_asset_it_flags():
    assets, findings = scan_cbom(load_cbom("tls_service.json"))
    by_ref = {asset.bom_ref: asset for asset in assets}

    named = Counter(
        (f["details"].get("asset_name"), f["details"].get("asset_type"), f["details"].get("primitive"))
        for f in findings
    )

    assert named == {
        ("api.example.com", "certificate", None): 4,
        ("TLS", "protocol", None): 3,
        ("SHA1withRSA", "algorithm", "signature"): 1,
        ("RSA", "algorithm", "pke"): 1,
        ("MD5", "algorithm", "hash"): 1,
        ("RSA-1024", "related-crypto-material", None): 1,
    }
    assert all(f["details"]["asset_name"] == by_ref[f["details"]["bom_ref"]].name for f in findings)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_every_finding_of_a_scanned_cbom_counts_under_its_asset_in_the_hotspots(
    client, db, api_key_headers, member_auth_headers
):
    scan_id = await ingest_and_analyze_cbom(client, db, api_key_headers, load_cbom("tls_service.json"), branch="main")

    async def hotspots(group_by):
        resp = await client.get(
            "/api/v1/analytics/crypto/hotspots",
            params={"scope": "project", "scope_id": "test-project-id", "group_by": group_by},
            headers=member_auth_headers,
        )
        assert resp.status_code == 200, resp.text
        return {e["key"]: (e["asset_count"], e["finding_count"]) for e in resp.json()["items"]}

    by_type = await hotspots("asset_type")
    assert by_type == {
        "algorithm": (4, 3),
        "certificate": (1, 4),
        "protocol": (1, 3),
        "related-crypto-material": (1, 1),
    }
    assert sum(findings for _, findings in by_type.values()) == await db.findings.count_documents({"scan_id": scan_id})
    assert await hotspots("name") == {
        "api.example.com": (1, 4),
        "TLS": (1, 3),
        "SHA1withRSA": (1, 1),
        "RSA": (1, 1),
        "MD5": (1, 1),
        "RSA-1024": (1, 1),
        "AES": (1, 0),
    }
    assert await hotspots("primitive") == {"signature": (1, 1), "pke": (1, 1), "hash": (1, 1), "block-cipher": (1, 0)}
