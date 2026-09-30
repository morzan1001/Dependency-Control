"""Unit tests for the crypto-policy seeder."""

from unittest.mock import AsyncMock, patch

import pytest

from app.models.crypto_policy import CryptoPolicy
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.crypto_policy import CryptoRule
from app.services.crypto_policy.seeder import (
    CURRENT_SEED_VERSION,
    load_seed_rules,
    seed_crypto_policies,
)


@pytest.fixture(autouse=True)
def _silence_audit_history():
    """Patch out record_policy_change so seeding doesn't emit webhooks or notifications."""
    with patch(
        "app.services.crypto_policy.seeder.record_policy_change",
        new=AsyncMock(),
    ):
        yield


def test_load_seed_rules_returns_nonempty():
    rules = load_seed_rules()
    assert len(rules) > 0
    rule_ids = {r.rule_id for r in rules}
    assert "nist-131a-md5" in rule_ids
    assert "pqc-quantum-vulnerable-pke" in rule_ids


def test_the_seed_rules_are_parsed_once_into_an_immutable_tuple():
    assert isinstance(load_seed_rules(), tuple)
    assert load_seed_rules() is load_seed_rules()


def test_load_seed_rules_sources_covered():
    rules = load_seed_rules()
    sources = {r.source for r in rules}
    source_strs = {str(s) for s in sources}
    assert any("nist-sp-800-131a" in s for s in source_strs)
    assert any("bsi-tr-02102" in s for s in source_strs)
    assert any("nist-pqc" in s for s in source_strs)


@pytest.mark.asyncio
async def test_seed_is_idempotent(db):
    await seed_crypto_policies(db)
    first = await CryptoPolicyRepository(db).get_system_policy()
    await seed_crypto_policies(db)
    second = await CryptoPolicyRepository(db).get_system_policy()
    assert (first.version, first.seed_version) == (second.version, second.seed_version) == (1, CURRENT_SEED_VERSION)


@pytest.mark.asyncio
async def test_seeding_is_audited_as_a_seed_not_as_an_operator_edit(db):
    from app.services.audit.history import record_policy_change

    with patch("app.services.crypto_policy.seeder.record_policy_change", new=record_policy_change):
        await seed_crypto_policies(db)

    entries = await db.crypto_policy_history.find({}).to_list(None)
    assert [e["action"] for e in entries] == ["seed"]
    assert entries[0]["actor_user_id"] is None


@pytest.mark.asyncio
async def test_reseeding_the_same_version_writes_no_second_audit_entry(db):
    """The skip is what keeps every restart from appending an identical policy revision."""
    from app.services.audit.history import record_policy_change

    with patch("app.services.crypto_policy.seeder.record_policy_change", new=record_policy_change):
        await seed_crypto_policies(db)
        await seed_crypto_policies(db)

    assert await db.crypto_policy_history.count_documents({}) == 1


def _custom_rule() -> CryptoRule:
    return load_seed_rules()[0].model_copy(update={"rule_id": "custom-admin-rule", "name": "custom"})


@pytest.mark.asyncio
async def test_the_seed_skips_a_policy_at_the_current_seed_version_whatever_its_edit_count(db):
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(
        CryptoPolicy(scope="system", rules=[_custom_rule()], version=1, seed_version=CURRENT_SEED_VERSION)
    )

    await seed_crypto_policies(db)

    got = await repo.get_system_policy()
    assert ([r.rule_id for r in got.rules], got.version) == (["custom-admin-rule"], 1)


@pytest.mark.asyncio
async def test_a_seed_bump_replaces_a_policy_no_person_edited(db):
    """A legacy document carries no seed_version, and its edit count used to decide whether the seed shipped."""
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(CryptoPolicy(scope="system", rules=[_custom_rule()], version=4))

    await seed_crypto_policies(db)

    got = await repo.get_system_policy()
    assert [r.rule_id for r in got.rules] == [r.rule_id for r in load_seed_rules()]
    assert (got.version, got.seed_version, got.updated_by) == (5, CURRENT_SEED_VERSION, None)


@pytest.mark.asyncio
async def test_a_seed_bump_gives_an_edited_policy_only_the_seed_rules_it_lacks(db):
    seed = load_seed_rules()
    disabled = seed[0].model_copy(update={"enabled": False})
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(
        CryptoPolicy(scope="system", rules=[disabled, _custom_rule()], version=2, updated_by="admin-user")
    )

    await seed_crypto_policies(db)

    got = await repo.get_system_policy()
    assert got.rules[:2] == [disabled, _custom_rule()]
    assert [r.rule_id for r in got.rules[2:]] == [r.rule_id for r in seed[1:]]
    assert (got.version, got.seed_version) == (3, CURRENT_SEED_VERSION)


@pytest.mark.asyncio
async def test_an_edited_policy_keeps_its_rules_and_editor_through_consecutive_seed_bumps(db):
    """The seeder reads updated_by as the edited marker, so a seed write must not clear it."""
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(
        CryptoPolicy(scope="system", rules=[_custom_rule()], version=2, updated_by="admin-user")
    )

    await seed_crypto_policies(db)
    with patch("app.services.crypto_policy.seeder.CURRENT_SEED_VERSION", CURRENT_SEED_VERSION + 1):
        await seed_crypto_policies(db)

    got = await repo.get_system_policy()
    assert (got.rules[0].rule_id, got.updated_by) == ("custom-admin-rule", "admin-user")
    assert (got.version, got.seed_version) == (4, CURRENT_SEED_VERSION + 1)
