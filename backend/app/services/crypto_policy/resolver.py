"""
CryptoPolicyResolver — merges system default with project override.

Cache is per-instance; one resolver lives for the duration of a scan analysis
run. The cache key includes both system and override versions, so any write
implicitly invalidates the cached effective policy.
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.crypto_policy import CryptoRule


@dataclass
class EffectivePolicy:
    rules: List[CryptoRule]
    system_version: int
    override_version: Optional[int]


class CryptoPolicyResolver:
    def __init__(self, db: AsyncIOMotorDatabase):
        self._repo = CryptoPolicyRepository(db)
        self._cache: dict[Tuple[str, int, Optional[int]], EffectivePolicy] = {}

    async def resolve(self, project_id: str) -> EffectivePolicy:
        system = await self._repo.get_system_policy()
        if system is None:
            return EffectivePolicy(rules=[], system_version=0, override_version=None)

        override = await self._repo.get_project_policy(project_id)
        override_version = override.version if override else None
        cache_key = (project_id, system.version, override_version)
        if cache_key in self._cache:
            return self._cache[cache_key]

        rules_by_id = {r.rule_id: r for r in system.rules}
        if override is not None:
            for r in override.rules:
                rules_by_id[r.rule_id] = r

        effective = EffectivePolicy(
            rules=list(rules_by_id.values()),
            system_version=system.version,
            override_version=override_version,
        )
        self._cache[cache_key] = effective
        return effective
