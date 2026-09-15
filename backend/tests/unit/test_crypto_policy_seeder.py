"""Unit tests for the crypto-policy seeder."""

from unittest.mock import AsyncMock, patch

import pytest

from app.repositories.crypto_policy import CryptoPolicyRepository
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
    v1 = (await CryptoPolicyRepository(db).get_system_policy()).version
    await seed_crypto_policies(db)
    v2 = (await CryptoPolicyRepository(db).get_system_policy()).version
    assert v1 == v2 == CURRENT_SEED_VERSION


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


@pytest.mark.asyncio
async def test_seed_skipped_when_version_higher(db):
    from app.models.crypto_policy import CryptoPolicy

    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(CryptoPolicy(scope="system", rules=[], version=CURRENT_SEED_VERSION + 5))
    await seed_crypto_policies(db)
    got = await repo.get_system_policy()
    assert got.version == CURRENT_SEED_VERSION + 5
