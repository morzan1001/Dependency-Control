import pytest
import pytest_asyncio
from motor.motor_asyncio import AsyncIOMotorClient

from app.repositories.crypto_policy import CryptoPolicyRepository
from app.services.crypto_policy.seeder import (
    CURRENT_SEED_VERSION,
    seed_crypto_policies,
    load_seed_rules,
)


@pytest_asyncio.fixture
async def db():
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    database = client["test_crypto_policy_seeder"]
    yield database
    await client.drop_database("test_crypto_policy_seeder")
    client.close()


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
async def test_seed_skipped_when_version_higher(db):
    from app.models.crypto_policy import CryptoPolicy
    repo = CryptoPolicyRepository(db)
    await repo.upsert_system_policy(
        CryptoPolicy(scope="system", rules=[], version=CURRENT_SEED_VERSION + 5)
    )
    await seed_crypto_policies(db)
    got = await repo.get_system_policy()
    assert got.version == CURRENT_SEED_VERSION + 5
