import pytest

from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.crypto_policy.resolver import CryptoPolicyResolver


def _rule(rule_id: str, enabled: bool = True, severity=Severity.HIGH):
    return CryptoRule(
        rule_id=rule_id,
        name=rule_id,
        description="",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=severity,
        source=CryptoPolicySource.NIST_SP_800_131A,
        enabled=enabled,
    )


@pytest.mark.asyncio
async def test_system_only_returned_when_no_override(db):
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(CryptoPolicy(scope="system", rules=[_rule("a"), _rule("b")], version=1))
    effective = await CryptoPolicyResolver(db).resolve("new-project")
    assert {r.rule_id for r in effective.rules} == {"a", "b"}
    assert effective.override_version is None


@pytest.mark.asyncio
async def test_override_replaces_same_rule_id(db):
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(CryptoPolicy(scope="system", rules=[_rule("a", severity=Severity.HIGH)], version=1))
    await repo.upsert_project_policy(
        CryptoPolicy(scope="project", project_id="p", rules=[_rule("a", severity=Severity.LOW)], version=1)
    )
    effective = await CryptoPolicyResolver(db).resolve("p")
    a = next(r for r in effective.rules if r.rule_id == "a")
    assert str(a.default_severity).endswith("LOW")


@pytest.mark.asyncio
async def test_override_adds_new_rule(db):
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(CryptoPolicy(scope="system", rules=[_rule("a")], version=1))
    await repo.upsert_project_policy(CryptoPolicy(scope="project", project_id="p", rules=[_rule("custom")], version=1))
    effective = await CryptoPolicyResolver(db).resolve("p")
    assert {r.rule_id for r in effective.rules} == {"a", "custom"}


@pytest.mark.asyncio
async def test_override_disable_propagates(db):
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(CryptoPolicy(scope="system", rules=[_rule("a", enabled=True)], version=1))
    await repo.upsert_project_policy(
        CryptoPolicy(scope="project", project_id="p", rules=[_rule("a", enabled=False)], version=1)
    )
    effective = await CryptoPolicyResolver(db).resolve("p")
    a = next(r for r in effective.rules if r.rule_id == "a")
    assert a.enabled is False
    assert effective.active_rules == []


@pytest.mark.asyncio
async def test_active_rules_hold_only_the_enabled_rules_while_rules_keep_all(db):
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", rules=[_rule("on"), _rule("off", enabled=False)], version=1)
    )

    effective = await CryptoPolicyResolver(db).resolve("p")

    assert [r.rule_id for r in effective.active_rules] == ["on"]
    assert [r.rule_id for r in effective.rules] == ["on", "off"]


@pytest.mark.asyncio
async def test_cache_invalidates_on_version_bump(db):
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(CryptoPolicy(scope="system", rules=[_rule("a")], version=1))
    resolver = CryptoPolicyResolver(db)
    e1 = await resolver.resolve("x")
    assert {r.rule_id for r in e1.rules} == {"a"}
    await repo.upsert_system_policy(CryptoPolicy(scope="system", rules=[_rule("a"), _rule("b")], version=2))
    e2 = await resolver.resolve("x")
    assert {r.rule_id for r in e2.rules} == {"a", "b"}


async def _lock_overrides_with_a_stored_one(db) -> None:
    from app.repositories.system_settings import SystemSettingsRepository

    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(CryptoPolicy(scope="system", rules=[_rule("a", severity=Severity.HIGH)], version=1))
    await repo.upsert_project_policy(
        CryptoPolicy(scope="project", project_id="p", rules=[_rule("a", severity=Severity.LOW), _rule("x")], version=3)
    )
    await SystemSettingsRepository(db).update({"crypto_policy_mode": "global"})


@pytest.mark.asyncio
async def test_a_stored_override_is_reported_but_not_applied_under_the_global_lock(db):
    """The override page shows 'stored but ignored' from override_version while override_locked is set."""
    await _lock_overrides_with_a_stored_one(db)

    effective = await CryptoPolicyResolver(db).resolve("p")

    assert (effective.override_version, effective.override_locked) == (3, True)
    assert effective.rules == effective.system_rules


@pytest.mark.asyncio
async def test_the_chat_tool_says_a_stored_override_is_locked_out(db):
    from app.services.chat.tools.crypto_tools import get_project_crypto_policy

    await _lock_overrides_with_a_stored_one(db)

    answer = await get_project_crypto_policy(db, project_id="p")

    assert (answer["override_version"], answer["override_locked"]) == (3, True)
    assert [r["rule_id"] for r in answer["rules"]] == ["a"]


@pytest.mark.asyncio
async def test_resolving_without_a_system_policy_fails_loud(db):
    with pytest.raises(RuntimeError, match="startup seeding did not run"):
        await CryptoPolicyResolver(db).resolve("p")
