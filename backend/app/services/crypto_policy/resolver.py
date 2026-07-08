"""Merges the system default crypto policy with a project override."""

from dataclasses import dataclass
from typing import List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.repositories.crypto_policy import CryptoPolicyRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.schemas.crypto_policy import CryptoRule


@dataclass
class EffectivePolicy:
    rules: List[CryptoRule]
    system_rules: List[CryptoRule]
    system_version: int
    override_version: Optional[int]
    override_locked: bool = False  # system enforces global policy; project override ignored


class CryptoPolicyResolver:
    def __init__(self, db: AsyncIOMotorDatabase):
        self._repo = CryptoPolicyRepository(db)
        self._settings_repo = SystemSettingsRepository(db)

    async def resolve(self, project_id: str) -> EffectivePolicy:
        system = await self._repo.get_system_policy()
        if system is None:
            return EffectivePolicy(rules=[], system_rules=[], system_version=0, override_version=None)

        settings = await self._settings_repo.get()
        override_locked = settings.crypto_policy_mode == "global"

        override = None if override_locked else await self._repo.get_project_policy(project_id)
        override_version = override.version if override else None

        rules_by_id = {r.rule_id: r for r in system.rules}
        if override is not None:
            for r in override.rules:
                rules_by_id[r.rule_id] = r

        return EffectivePolicy(
            rules=list(rules_by_id.values()),
            system_rules=list(system.rules),
            system_version=system.version,
            override_version=override_version,
            override_locked=override_locked,
        )
