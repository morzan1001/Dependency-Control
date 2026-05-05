"""
CryptoPolicyResolver — merges system default with project override.

Cache is per-instance; one resolver lives for the duration of a scan analysis
run. The cache key includes the system version, override version, and the
system-wide enforcement mode, so any write or admin-toggle implicitly
invalidates the cached effective policy.
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.repositories.crypto_policy import CryptoPolicyRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.schemas.crypto_policy import CryptoRule


@dataclass
class EffectivePolicy:
    rules: List[CryptoRule]  # merged: system overlaid with override
    system_rules: List[CryptoRule]  # raw system baseline (for UI diffing)
    system_version: int
    override_version: Optional[int]
    override_locked: bool = False  # True when system enforces global policy (project override ignored)


class CryptoPolicyResolver:
    def __init__(self, db: AsyncIOMotorDatabase):
        self._repo = CryptoPolicyRepository(db)
        self._settings_repo = SystemSettingsRepository(db)
        self._cache: dict[Tuple[str, int, Optional[int], bool], EffectivePolicy] = {}

    async def resolve(self, project_id: str) -> EffectivePolicy:
        system = await self._repo.get_system_policy()
        if system is None:
            return EffectivePolicy(rules=[], system_rules=[], system_version=0, override_version=None)

        settings = await self._settings_repo.get()
        override_locked = settings.crypto_policy_mode == "global"

        override = None if override_locked else await self._repo.get_project_policy(project_id)
        override_version = override.version if override else None
        cache_key = (project_id, system.version, override_version, override_locked)
        if cache_key in self._cache:
            return self._cache[cache_key]

        rules_by_id = {r.rule_id: r for r in system.rules}
        if override is not None:
            for r in override.rules:
                rules_by_id[r.rule_id] = r

        effective = EffectivePolicy(
            rules=list(rules_by_id.values()),
            system_rules=list(system.rules),
            system_version=system.version,
            override_version=override_version,
            override_locked=override_locked,
        )
        self._cache[cache_key] = effective
        return effective
