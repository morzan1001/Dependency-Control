"""
Integration tests: project-level CryptoPolicy overrides.

These tests call CryptoRuleAnalyzer directly against the in-process _FakeDb
(via the `db` fixture in conftest.py).  They do NOT go through the
worker→engine pipeline because that path requires a live worker queue and is
not exercised in the fake-DB environment (see the @pytest.mark.skip test in
test_crypto_analyzer_pipeline.py for rationale).

Testing at the analyzer layer is the highest layer that actually has real
behavior in this environment: the fake DB can persist and query crypto assets
and policies, and CryptoRuleAnalyzer reads both from DB to produce findings.
"""

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
        rule_id=rule_id, name=rule_id, description="",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=Severity.HIGH,
        source=CryptoPolicySource.CUSTOM,
        enabled=enabled, **extra,
    )


@pytest.mark.asyncio
async def test_override_disables_rule_and_suppresses_findings(db):
    """Project override with enabled=False on a system rule suppresses findings.

    Flow:
    1. Seed an MD5 asset in the fake DB.
    2. Seed a system policy with a matching rule (enabled=True).
    3. Assert the analyzer emits a finding.
    4. Upsert a project-level override that disables the same rule.
    5. Assert the analyzer emits no findings (rule is suppressed).

    This exercises CryptoPolicyResolver.resolve(), which merges system and
    project policies — disabled project rules override enabled system rules.
    """
    policy_repo = CryptoPolicyRepository(db)
    asset_repo = CryptoAssetRepository(db)

    # Seed an MD5 asset
    await asset_repo.bulk_upsert("proj", "scan", [
        CryptoAsset(project_id="proj", scan_id="scan", bom_ref="a",
                    name="MD5", asset_type=CryptoAssetType.ALGORITHM,
                    primitive=CryptoPrimitive.HASH),
    ])

    # System policy with the rule enabled
    await policy_repo.upsert_system_policy(CryptoPolicy(
        scope="system", version=1,
        rules=[_rule("md5", match_name_patterns=["MD5"])],
    ))

    analyzer = CryptoRuleAnalyzer(
        name="crypto_weak_algorithm",
        finding_types={FindingType.CRYPTO_WEAK_ALGORITHM},
    )

    # Before override: finding emitted
    r1 = await analyzer.analyze(
        sbom={}, project_id="proj", scan_id="scan", db=db,
    )
    assert any(f["details"]["rule_id"] == "md5" for f in r1["findings"]), (
        "Expected a finding for rule 'md5' before override was applied"
    )

    # Add project override disabling the rule
    await policy_repo.upsert_project_policy(CryptoPolicy(
        scope="project", project_id="proj", version=1,
        rules=[_rule("md5", match_name_patterns=["MD5"], enabled=False)],
    ))

    # After override: rule is disabled → no finding
    r2 = await analyzer.analyze(
        sbom={}, project_id="proj", scan_id="scan", db=db,
    )
    assert not any(f["details"]["rule_id"] == "md5" for f in r2["findings"]), (
        "Expected no findings for rule 'md5' after project override disabled it"
    )


@pytest.mark.asyncio
async def test_override_adds_custom_rule(db):
    """Project override can add a custom rule not present in the system policy.

    The system policy has no rules, but the project override adds one for
    BLOWFISH.  After applying the override, the analyzer should emit a finding
    for the BLOWFISH asset.
    """
    policy_repo = CryptoPolicyRepository(db)
    asset_repo = CryptoAssetRepository(db)

    await asset_repo.bulk_upsert("proj2", "scan", [
        CryptoAsset(project_id="proj2", scan_id="scan", bom_ref="a",
                    name="BLOWFISH", asset_type=CryptoAssetType.ALGORITHM,
                    primitive=CryptoPrimitive.BLOCK_CIPHER),
    ])
    await policy_repo.upsert_system_policy(CryptoPolicy(
        scope="system", version=1, rules=[],
    ))
    await policy_repo.upsert_project_policy(CryptoPolicy(
        scope="project", project_id="proj2", version=1,
        rules=[_rule("blowfish", match_name_patterns=["BLOWFISH"])],
    ))
    analyzer = CryptoRuleAnalyzer(
        name="crypto_weak_algorithm",
        finding_types={FindingType.CRYPTO_WEAK_ALGORITHM},
    )
    r = await analyzer.analyze(sbom={}, project_id="proj2", scan_id="scan", db=db)
    assert any(f["details"]["rule_id"] == "blowfish" for f in r["findings"]), (
        "Expected a finding for custom rule 'blowfish' added by project override"
    )
