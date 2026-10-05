"""Every pod seeds the crypto policy at startup. Pods starting together must still write one SEED revision,
or a rollout that bumps the seed version leaves one identical history row per replica."""

import asyncio

import pytest

from app.services.crypto_policy.seeder import seed_crypto_policies

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]


async def test_pods_seeding_together_write_one_seed_revision(db):
    await asyncio.gather(*(seed_crypto_policies(db) for _pod in range(3)))

    history = [
        (e["action"], e["version"]) async for e in db.crypto_policy_history.find({}, {"action": 1, "version": 1})
    ]
    assert history == [("seed", 1)]
