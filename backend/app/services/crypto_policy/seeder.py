"""Seeds the system crypto policy from ./seed/*.yaml and holds the one write path of every crypto policy."""

import functools
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

import yaml
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_policy import CryptoPolicy
from app.models.user import User
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.schemas.crypto_policy import CryptoRule
from app.schemas.policy_audit import PolicyAuditAction
from app.services.audit.history import record_policy_change

logger = logging.getLogger(__name__)

# Bump whenever any seed/*.yaml changes; an edited system policy regains every seed rule_id it lacks, deleted ones too.
CURRENT_SEED_VERSION = 2

_SEED_DIR = Path(__file__).parent / "seed"


@functools.cache
def load_seed_file(name: str) -> tuple[CryptoRule, ...]:
    with open(_SEED_DIR / name) as f:
        data = yaml.safe_load(f) or {}
    return tuple(CryptoRule.model_validate(rule_dict) for rule_dict in data.get("rules") or [])


@functools.cache
def load_seed_rules() -> tuple[CryptoRule, ...]:
    return tuple(rule for path in sorted(_SEED_DIR.glob("*.yaml")) for rule in load_seed_file(path.name))


async def write_policy(
    db: AsyncIOMotorDatabase,
    *,
    scope: Literal["system", "project"],
    project_id: str | None,
    rules: Sequence[CryptoRule] | None,
    action: PolicyAuditAction,
    actor: User | None,
    comment: str | None = None,
    reverted_from_version: int | None = None,
    editor: str | None = None,
) -> CryptoPolicy | None:
    """The one write path of a crypto policy; rules=None deletes the project override and returns None if none existed."""
    repo = CryptoPolicyRepository(db)
    if scope == "system":
        current = await repo.get_system_policy()
    else:
        assert project_id is not None
        if rules is None:
            current = await repo.delete_project_policy(project_id)
            if current is None:
                return None
        else:
            current = await repo.get_project_policy(project_id)
    # The audit history outlives a deleted override, so a recreated one continues its numbering.
    audited = await PolicyAuditRepository(db).max_version(policy_scope=scope, project_id=project_id)
    policy = CryptoPolicy(
        scope=scope,
        project_id=project_id,
        rules=list(rules or []),
        version=max(current.version if current else 0, audited) + 1,
        # A seed write keeps the last editor, the marker by which the seeder spares an edited policy.
        updated_by=str(actor.id) if actor else editor,
        seed_version=CURRENT_SEED_VERSION
        if action == PolicyAuditAction.SEED
        else (current.seed_version if current else None),
    )
    if rules is not None:
        await (repo.upsert_system_policy(policy) if scope == "system" else repo.upsert_project_policy(policy))
    await record_policy_change(
        db,
        policy_scope=scope,
        project_id=project_id,
        old_policy=current,
        new_policy=policy,
        action=PolicyAuditAction.CREATE if current is None and action == PolicyAuditAction.UPDATE else action,
        actor=actor,
        comment=comment,
        reverted_from_version=reverted_from_version,
    )
    return policy


async def seed_crypto_policies(db: AsyncIOMotorDatabase) -> None:
    existing = await CryptoPolicyRepository(db).get_system_policy()
    if existing is not None and (existing.seed_version or 0) >= CURRENT_SEED_VERSION:
        logger.info("crypto_policy_seed: skipping, seed version %s is current", existing.seed_version)
        return
    rules = list(load_seed_rules())
    editor = existing.updated_by if existing else None
    if existing is not None and existing.seed_version is None and editor is None:
        # Reverts once stored no updated_by, so a legacy policy's last editor is read from its audit history.
        newest = await PolicyAuditRepository(db).list(policy_scope="system", limit=1)
        editor = newest[0].actor_user_id if newest else None
    if existing is not None and editor is not None:
        # A person edited this policy, so their rules stand and only seed rule_ids it lacks are added.
        held = {r.rule_id for r in existing.rules}
        rules = existing.rules + [r for r in rules if r.rule_id not in held]
    await write_policy(
        db, scope="system", project_id=None, rules=rules, action=PolicyAuditAction.SEED, actor=None, editor=editor
    )
    logger.info(
        "crypto_policy_seed: applied seed version %d, system policy holds %d rules",
        CURRENT_SEED_VERSION,
        len(rules),
    )
