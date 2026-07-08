"""Project-level CryptoPolicy overrides tested directly against CryptoRuleAnalyzer with the fake DB."""

import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.analyzers.crypto.base import CryptoRuleAnalyzer


def _rule(rule_id, enabled=True, **extra):
    return CryptoRule(
        rule_id=rule_id,
        name=rule_id,
        description="",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=Severity.HIGH,
        source=CryptoPolicySource.CUSTOM,
        enabled=enabled,
        **extra,
    )


@pytest.mark.asyncio
async def test_override_disables_rule_and_suppresses_findings(db):
    """A project override with enabled=False suppresses findings from the matching system rule."""
    policy_repo = CryptoPolicyRepository(db)
    asset_repo = CryptoAssetRepository(db)

    await asset_repo.bulk_upsert(
        "proj",
        "scan",
        [
            CryptoAsset(
                project_id="proj",
                scan_id="scan",
                bom_ref="a",
                name="MD5",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.HASH,
            ),
        ],
    )

    await policy_repo.upsert_system_policy(
        CryptoPolicy(
            scope="system",
            version=1,
            rules=[_rule("md5", match_name_patterns=["MD5"])],
        )
    )

    analyzer = CryptoRuleAnalyzer(
        name="crypto_weak_algorithm",
        finding_types={FindingType.CRYPTO_WEAK_ALGORITHM},
    )

    r1 = await analyzer.analyze(
        sbom={},
        project_id="proj",
        scan_id="scan",
        db=db,
    )
    assert any(f["details"]["rule_id"] == "md5" for f in r1["findings"]), (
        "Expected a finding for rule 'md5' before override was applied"
    )

    await policy_repo.upsert_project_policy(
        CryptoPolicy(
            scope="project",
            project_id="proj",
            version=1,
            rules=[_rule("md5", match_name_patterns=["MD5"], enabled=False)],
        )
    )

    r2 = await analyzer.analyze(
        sbom={},
        project_id="proj",
        scan_id="scan",
        db=db,
    )
    assert not any(f["details"]["rule_id"] == "md5" for f in r2["findings"]), (
        "Expected no findings for rule 'md5' after project override disabled it"
    )


@pytest.mark.asyncio
async def test_override_adds_custom_rule(db):
    """A project override can add a custom rule absent from the system policy."""
    policy_repo = CryptoPolicyRepository(db)
    asset_repo = CryptoAssetRepository(db)

    await asset_repo.bulk_upsert(
        "proj2",
        "scan",
        [
            CryptoAsset(
                project_id="proj2",
                scan_id="scan",
                bom_ref="a",
                name="BLOWFISH",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.BLOCK_CIPHER,
            ),
        ],
    )
    await policy_repo.upsert_system_policy(
        CryptoPolicy(
            scope="system",
            version=1,
            rules=[],
        )
    )
    await policy_repo.upsert_project_policy(
        CryptoPolicy(
            scope="project",
            project_id="proj2",
            version=1,
            rules=[_rule("blowfish", match_name_patterns=["BLOWFISH"])],
        )
    )
    analyzer = CryptoRuleAnalyzer(
        name="crypto_weak_algorithm",
        finding_types={FindingType.CRYPTO_WEAK_ALGORITHM},
    )
    r = await analyzer.analyze(sbom={}, project_id="proj2", scan_id="scan", db=db)
    assert any(f["details"]["rule_id"] == "blowfish" for f in r["findings"]), (
        "Expected a finding for custom rule 'blowfish' added by project override"
    )
