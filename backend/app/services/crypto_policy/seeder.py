"""Seeds the system crypto policy from ./seed/*.yaml; project overrides are untouched."""

import functools
import logging
from pathlib import Path

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


@functools.cache
def load_seed_file(name: str) -> tuple[CryptoRule, ...]:
    with open(_SEED_DIR / name) as f:
        data = yaml.safe_load(f) or {}
    return tuple(CryptoRule.model_validate(rule_dict) for rule_dict in data.get("rules") or [])


@functools.cache
def load_seed_rules() -> tuple[CryptoRule, ...]:
    return tuple(rule for path in sorted(_SEED_DIR.glob("*.yaml")) for rule in load_seed_file(path.name))


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
    new_policy = CryptoPolicy(scope="system", rules=list(rules), version=CURRENT_SEED_VERSION)
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
