import pytest

from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.crypto_policy.resolver import CryptoPolicyResolver


def _rule(rule_id: str, enabled: bool = True, severity=Severity.HIGH):
    return CryptoRule(
        rule_id=rule_id, name=rule_id, description="",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=severity,
        source=CryptoPolicySource.NIST_SP_800_131A,
        enabled=enabled,
    )


@pytest.mark.asyncio
async def test_system_only_returned_when_no_override(db):
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(
        CryptoPolicy(scope="system", rules=[_rule("a"), _rule("b")], version=1)
    )
    effective = await CryptoPolicyResolver(db).resolve("new-project")
    assert {r.rule_id for r in effective.rules} == {"a", "b"}
    assert effective.override_version is None


@pytest.mark.asyncio
async def test_override_replaces_same_rule_id(db):
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(
        CryptoPolicy(scope="system", rules=[_rule("a", severity=Severity.HIGH)], version=1)
    )
    await repo.upsert_project_policy(
        CryptoPolicy(scope="project", project_id="p",
                     rules=[_rule("a", severity=Severity.LOW)], version=1)
    )
    effective = await CryptoPolicyResolver(db).resolve("p")
    a = next(r for r in effective.rules if r.rule_id == "a")
    assert str(a.default_severity).endswith("LOW")


@pytest.mark.asyncio
async def test_override_adds_new_rule(db):
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(
        CryptoPolicy(scope="system", rules=[_rule("a")], version=1)
    )
    await repo.upsert_project_policy(
        CryptoPolicy(scope="project", project_id="p",
                     rules=[_rule("custom")], version=1)
    )
    effective = await CryptoPolicyResolver(db).resolve("p")
    assert {r.rule_id for r in effective.rules} == {"a", "custom"}


@pytest.mark.asyncio
async def test_override_disable_propagates(db):
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(
        CryptoPolicy(scope="system", rules=[_rule("a", enabled=True)], version=1)
    )
    await repo.upsert_project_policy(
        CryptoPolicy(scope="project", project_id="p",
                     rules=[_rule("a", enabled=False)], version=1)
    )
    effective = await CryptoPolicyResolver(db).resolve("p")
    a = next(r for r in effective.rules if r.rule_id == "a")
    assert a.enabled is False


@pytest.mark.asyncio
async def test_cache_invalidates_on_version_bump(db):
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(
        CryptoPolicy(scope="system", rules=[_rule("a")], version=1)
    )
    resolver = CryptoPolicyResolver(db)
    e1 = await resolver.resolve("x")
    assert {r.rule_id for r in e1.rules} == {"a"}
    await repo.upsert_system_policy(
        CryptoPolicy(scope="system", rules=[_rule("a"), _rule("b")], version=2)
    )
    e2 = await resolver.resolve("x")
    assert {r.rule_id for r in e2.rules} == {"a", "b"}
