"""Merges the system default crypto policy with a project override."""

import functools
from dataclasses import dataclass

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import SETTINGS_MODE_GLOBAL
from app.models.system import SystemSettings
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.schemas.crypto_policy import CryptoRule


@dataclass
class EffectivePolicy:
    rules: list[CryptoRule]
    system_rules: list[CryptoRule]
    system_version: int
    override_version: int | None  # the stored override, merged into rules only while not override_locked
    override_locked: bool = False

    @functools.cached_property
    def active_rules(self) -> list[CryptoRule]:
        return [r for r in self.rules if r.enabled]


def project_overrides_locked(settings: SystemSettings) -> bool:
    return settings.crypto_policy_mode == SETTINGS_MODE_GLOBAL


class CryptoPolicyResolver:
    def __init__(self, db: AsyncIOMotorDatabase):
        self._repo = CryptoPolicyRepository(db)
        self._settings_repo = SystemSettingsRepository(db)

    async def resolve(self, project_id: str) -> EffectivePolicy:
        system = await self._repo.require_system_policy()
        override_locked = project_overrides_locked(await self._settings_repo.get())
        override = await self._repo.get_project_policy(project_id)

        rules_by_id = {r.rule_id: r for r in system.rules}
        if override is not None and not override_locked:
            for r in override.rules:
                rules_by_id[r.rule_id] = r

        return EffectivePolicy(
            rules=list(rules_by_id.values()),
            system_rules=list(system.rules),
            system_version=system.version,
            override_version=override.version if override else None,
            override_locked=override_locked,
        )
