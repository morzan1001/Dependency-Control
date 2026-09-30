"""Turns quantum-vulnerable crypto assets into a priority-ranked PQC migration plan."""

from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import MAX_CRYPTO_ASSETS_PER_SCAN, SCAN_USABLE_STATUSES
from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import QUANTUM_VULNERABLE_PRIMITIVES
from app.schemas.pqc_migration import (
    MigrationItem,
    MigrationPlanResponse,
    MigrationPlanSummary,
)
from app.services.analytics.scopes import ResolvedScope
from app.services.pqc_migration.mappings_loader import (
    CURRENT_MAPPINGS_VERSION,
    PQCMapping,
    Timeline,
    load_mappings,
    resolve_family,
)
from app.services.pqc_migration.scoring import priority_score, status_from_score

_GroupKey = tuple[str, str | None, int | None, str]


class PQCMigrationPlanGenerator:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.mappings = load_mappings()

    async def generate(
        self,
        *,
        resolved: ResolvedScope,
        limit: int = 500,
    ) -> MigrationPlanResponse:
        assets = await self._list_vulnerable_assets(resolved)
        now = datetime.now(timezone.utc)

        groups = self._group_assets(assets)
        items = [item for key, group in groups.items() if (item := self._build_item(key, group, now)) is not None]
        items.sort(key=lambda i: i.priority_score, reverse=True)
        returned = items[:limit]

        return MigrationPlanResponse(
            scope=resolved.scope,
            scope_id=resolved.scope_id,
            generated_at=now,
            items=returned,
            # Summarised over every migratable group: a plan that under-counts the work is a
            # planning document wrong in the direction that matters.
            summary=self._summarise(items, items_returned=len(returned)),
            mappings_version=CURRENT_MAPPINGS_VERSION,
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
    ) -> MigrationItem | None:
        _name, variant, key_size_bits, _ref = key
        first_asset = group[0]
        canonical = resolve_family(first_asset, self.mappings)
        mapping = self._find_mapping(canonical, first_asset.primitive)
        if mapping is None:
            return None
        score = priority_score(
            asset=first_asset,
            source_family=canonical,
            timelines=self.mappings.timelines,
            now=now,
            asset_count=len(group),
        )
        deadline = self._nearest_deadline(canonical, self.mappings.timelines)
        return MigrationItem(
            asset_bom_ref=first_asset.bom_ref,
            asset_name=first_asset.name or canonical,
            asset_variant=variant,
            asset_key_size_bits=key_size_bits,
            project_ids=sorted({a.project_id for a in group}),
            asset_count=len(group),
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

    async def _list_vulnerable_assets(
        self,
        resolved: ResolvedScope,
    ) -> list[CryptoAsset]:
        """Quantum-vulnerable assets from the head build of each resolved project."""
        from app.services.releases import resolve_scan_ids

        out: list[CryptoAsset] = []
        # None project_ids means global scope (all projects); an explicit [] means none.
        if resolved.project_ids is None:
            project_ids = await self._all_project_ids()
        else:
            project_ids = resolved.project_ids
        repo = CryptoAssetRepository(self.db)
        for pid, scan_id in (await resolve_scan_ids(self.db, project_ids, projects=resolved.projects)).items():
            assets = await repo.list_by_scan(pid, scan_id, limit=MAX_CRYPTO_ASSETS_PER_SCAN)
            out.extend(self._filter_vulnerable(assets))
        return out

    def _filter_vulnerable(self, assets: list[CryptoAsset]) -> list[CryptoAsset]:
        return [a for a in assets if a.primitive in QUANTUM_VULNERABLE_PRIMITIVES and resolve_family(a, self.mappings)]

    async def _all_project_ids(self) -> list[str]:
        """Distinct project ids that have at least one usable scan."""
        return await self.db.scans.distinct(
            "project_id",
            {"status": {"$in": SCAN_USABLE_STATUSES}},
        )

    def _find_mapping(self, family: str, primitive: str | None) -> PQCMapping | None:
        exact = next(
            (m for m in self.mappings.mappings if m.source_family == family and m.source_primitive == primitive),
            None,
        )
        if exact is not None:
            return exact
        return next(
            (m for m in self.mappings.mappings if m.source_family == family),
            None,
        )

    @staticmethod
    def _nearest_deadline(
        family: str,
        timelines: list[Timeline],
    ) -> datetime | None:
        applicable = [t for t in timelines if family in t.applies_to]
        if not applicable:
            return None
        return min(t.deadline for t in applicable)
