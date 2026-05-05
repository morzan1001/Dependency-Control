"""
Crypto-policy seeder.

Loads YAML seed files from ./seed/*.yaml and upserts the system policy if the
stored version is lower than CURRENT_SEED_VERSION. Project overrides are never
touched by this function.
"""

import logging
from pathlib import Path
from typing import List

import yaml
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_policy import CryptoPolicy
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.crypto_policy import CryptoRule
from app.schemas.policy_audit import PolicyAuditAction
from app.services.audit.history import record_policy_change

logger = logging.getLogger(__name__)

# Bump this whenever the content of any seed/*.yaml changes.
CURRENT_SEED_VERSION = 1

_SEED_DIR = Path(__file__).parent / "seed"


def load_seed_rules() -> List[CryptoRule]:
    rules: List[CryptoRule] = []
    for path in sorted(_SEED_DIR.glob("*.yaml")):
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        for rule_dict in data.get("rules") or []:
            rules.append(CryptoRule.model_validate(rule_dict))
    return rules


async def seed_crypto_policies(db: AsyncIOMotorDatabase) -> None:
    repo = CryptoPolicyRepository(db)
    existing = await repo.get_system_policy()
    if existing is not None and existing.version >= CURRENT_SEED_VERSION:
        logger.info(
            "crypto_policy_seed: skipping, existing version %s >= %s",
            existing.version,
            CURRENT_SEED_VERSION,
        )
        return
    rules = load_seed_rules()
    new_policy = CryptoPolicy(scope="system", rules=rules, version=CURRENT_SEED_VERSION)
    await repo.upsert_system_policy(new_policy)
    await record_policy_change(
        db,
        policy_scope="system",
        project_id=None,
        old_policy=existing,
        new_policy=new_policy,
        action=PolicyAuditAction.SEED,
        actor=None,
        comment=None,
    )
    logger.info(
        "crypto_policy_seed: upserted system policy with %d rules (version %d)",
        len(rules),
        CURRENT_SEED_VERSION,
    )
