from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.cache import scope_digest
from app.models.crypto_asset import CryptoAsset, CryptoAssetType
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.projects import ProjectRepository
from app.schemas.cbom import QUANTUM_VULNERABLE_PRIMITIVES
from app.schemas.pqc_migration import (
    MigrationItem,
    MigrationPlanResponse,
    MigrationPlanSummary,
)
from app.services.analytics.cache import get_analytics_cache
from app.services.analytics.scopes import ResolvedScope
from app.services.pqc_migration.mappings_loader import (
    PQCMapping,
    Timeline,
    load_mappings,
    resolve_family,
)
from app.services.pqc_migration.scoring import priority_score, referenced_exposure, status_from_score

_GroupKey = tuple[str, str | None, int | None, str]
_LINKING_TYPES = (CryptoAssetType.CERTIFICATE, CryptoAssetType.RELATED_CRYPTO_MATERIAL)


class PQCMigrationPlanGenerator:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.mappings = load_mappings()

    async def plan(self, *, resolved: ResolvedScope, limit: int) -> MigrationPlanResponse:
        key = (
            "pqc-migration",
            resolved.scope,
            resolved.scope_id,
            scope_digest(resolved.project_ids),
            limit,
            self.mappings.version,
        )
        return await get_analytics_cache().get_or_compute(key, lambda: self.generate(resolved=resolved, limit=limit))

    async def generate(
        self,
        *,
        resolved: ResolvedScope,
        limit: int = 500,
    ) -> MigrationPlanResponse:
        assets, linked = await self._list_assets(resolved)
        now = datetime.now(timezone.utc)

        exposure = referenced_exposure(linked)
        groups = self._group_assets(assets)
        items = [self._build_item(key, group, now, exposure) for key, group in groups.items()]
        items.sort(key=lambda i: i.priority_score, reverse=True)
        returned = items[:limit]

        return MigrationPlanResponse(
            scope=resolved.scope,
            scope_id=resolved.scope_id,
            generated_at=now,
            items=returned,
            project_names=await ProjectRepository(self.db).names_by_ids(p for i in returned for p in i.project_ids),
            # Summarised over every migratable group: an under-counting plan is wrong in the direction that matters.
            summary=self._summarise(items, items_returned=len(returned)),
            mappings_version=self.mappings.version,
        )

    @staticmethod
    def _group_assets(
        assets: list[CryptoAsset],
    ) -> dict[_GroupKey, list[CryptoAsset]]:
        groups: dict[_GroupKey, list[CryptoAsset]] = {}
        for a in assets:
            key: _GroupKey = (a.name or "", a.variant, a.key_size_bits, a.bom_ref)
            groups.setdefault(key, []).append(a)
        return groups

    def _build_item(
        self,
        key: _GroupKey,
        group: list[CryptoAsset],
        now: datetime,
        exposure: dict[str, float],
    ) -> MigrationItem:
        _name, variant, key_size_bits, _ref = key
        first_asset = group[0]
        canonical = resolve_family(first_asset, self.mappings)
        mapping = self._find_mapping(canonical, first_asset.primitive)
        deadline = self._nearest_deadline(canonical, self.mappings.timelines)
        occurrences = sum(max(1, len(a.occurrence_locations)) for a in group)
        score = priority_score(
            asset=first_asset,
            source_family=canonical,
            deadline=deadline,
            now=now,
            asset_count=occurrences,
            referenced=exposure.get(first_asset.bom_ref),
        )
        return MigrationItem(
            asset_bom_ref=first_asset.bom_ref,
            asset_name=first_asset.name or canonical,
            asset_variant=variant,
            asset_key_size_bits=key_size_bits,
            project_ids=sorted({a.project_id for a in group}),
            asset_count=occurrences,
            source_family=canonical,
            source_primitive=first_asset.primitive or "",
            use_case=mapping.use_case,
            recommended_pqc=mapping.recommended_pqc,
            recommended_standard=mapping.standard,
            notes=mapping.notes,
            priority_score=score,
            status=status_from_score(score),
            recommended_deadline=deadline.isoformat() if deadline else None,
        )

    @staticmethod
    def _summarise(items: list[MigrationItem], *, items_returned: int) -> MigrationPlanSummary:
        status_counts: dict[str, int] = {}
        for item in items:
            status_counts[item.status] = status_counts.get(item.status, 0) + 1
        deadlines = [i.recommended_deadline for i in items if i.recommended_deadline]
        earliest = min(deadlines) if deadlines else None
        return MigrationPlanSummary(
            total_items=len(items),
            items_returned=items_returned,
            status_counts=status_counts,
            earliest_deadline=earliest,
        )

    async def _list_assets(self, resolved: ResolvedScope) -> tuple[list[CryptoAsset], list[CryptoAsset]]:
        """The scope's migratable algorithms, and the certificates and key material that may name them."""
        from app.services.releases import resolve_scan_ids

        scan_ids = await resolve_scan_ids(self.db, resolved.project_ids, projects=resolved.projects)
        query = {
            "project_id": {"$in": list(scan_ids)},
            "scan_id": {"$in": list(scan_ids.values())},
            "$or": [
                {"primitive": {"$in": sorted(QUANTUM_VULNERABLE_PRIMITIVES)}},
                {"asset_type": {"$in": list(_LINKING_TYPES)}},
            ],
        }
        algorithms: list[CryptoAsset] = []
        linked: list[CryptoAsset] = []
        async for a in CryptoAssetRepository(self.db).iterate(query):
            if a.asset_type in _LINKING_TYPES:
                linked.append(a)
            elif resolve_family(a, self.mappings):
                algorithms.append(a)
        return algorithms, linked

    def _find_mapping(self, family: str, primitive: str | None) -> PQCMapping:
        """``family`` is canonical, as only assets of a mapped family enter the plan."""
        candidates = [m for m in self.mappings.mappings if m.source_family == family]
        return next((m for m in candidates if m.source_primitive == primitive), candidates[0])

    @staticmethod
    def _nearest_deadline(family: str, timelines: list[Timeline]) -> datetime | None:
        return min((t.deadline for t in timelines if family in t.applies_to), default=None)
