"""Every pod seeds the crypto policy at startup. Pods starting together must still write one SEED revision,
or a rollout that bumps the seed version leaves one identical history row per replica."""

import asyncio

import pytest
from pymongo.errors import AutoReconnect

from app.repositories.crypto_policy import CryptoPolicyRepository
from app.services.crypto_policy.seeder import seed_crypto_policies

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]


async def _history(db) -> list[tuple[str, int]]:
    return [(e["action"], e["version"]) async for e in db.crypto_policy_history.find({}, {"action": 1, "version": 1})]


async def test_pods_seeding_together_write_one_seed_revision(db):
    await asyncio.gather(*(seed_crypto_policies(db) for _pod in range(3)))

    assert await _history(db) == [("seed", 1)]


async def test_a_pod_that_read_the_policy_before_the_seed_landed_writes_no_second_revision(db, monkeypatch):
    await seed_crypto_policies(db)

    async def _read_before_the_seed(_repo):
        return None

    monkeypatch.setattr(CryptoPolicyRepository, "get_system_policy", _read_before_the_seed)
    await seed_crypto_policies(db)

    assert await _history(db) == [("seed", 1)]


async def test_a_seed_whose_write_failed_is_applied_by_the_next_start(db, monkeypatch):
    async def _primary_stepped_down(_repo, _policy):
        raise AutoReconnect("primary stepped down")

    with monkeypatch.context() as patched:
        patched.setattr(CryptoPolicyRepository, "upsert_system_policy", _primary_stepped_down)
        with pytest.raises(AutoReconnect):
            await seed_crypto_policies(db)

    await seed_crypto_policies(db)

    assert await _history(db) == [("seed", 1)]
