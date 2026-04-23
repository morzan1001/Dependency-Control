"""
PQC migration plan generator. Turns a list of quantum-vulnerable crypto
assets into a priority-ranked migration plan with NIST-standardised
PQC replacements.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoPrimitive
from app.schemas.pqc_migration import (
    MigrationItem, MigrationItemStatus,
    MigrationPlanResponse, MigrationPlanSummary,
)
from app.services.analytics.scopes import ResolvedScope
from app.services.pqc_migration.mappings_loader import (
    CURRENT_MAPPINGS_VERSION, PQCMapping, Timeline,
    load_mappings, normalise_family,
)
from app.services.pqc_migration.scoring import priority_score, status_from_score


_QV_PRIMITIVES = {CryptoPrimitive.PKE, CryptoPrimitive.SIGNATURE, CryptoPrimitive.KEM}

_GroupKey = Tuple[str, Optional[str], Optional[int], str]


class PQCMigrationPlanGenerator:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.mappings = load_mappings()

    async def generate(
        self, *, resolved: ResolvedScope, limit: int = 500,
    ) -> MigrationPlanResponse:
        assets = await self._list_vulnerable_assets(resolved)
        now = datetime.now(timezone.utc)

        groups = self._group_assets(assets)
        items = [
            item
            for key, group in groups.items()
            if (item := self._build_item(key, group, now)) is not None
        ]
        items.sort(key=lambda i: i.priority_score, reverse=True)
        items = items[:limit]

        return MigrationPlanResponse(
            scope=resolved.scope,
            scope_id=resolved.scope_id,
            generated_at=now,
            items=items,
            summary=self._summarise(items),
            mappings_version=CURRENT_MAPPINGS_VERSION,
        )

    @staticmethod
    def _group_assets(
        assets: List[CryptoAsset],
    ) -> Dict[_GroupKey, List[CryptoAsset]]:
        groups: Dict[_GroupKey, List[CryptoAsset]] = {}
        for a in assets:
            variant = getattr(a, "variant", None)
            key: _GroupKey = (
                a.name or "", variant, getattr(a, "key_size_bits", None), a.bom_ref,
            )
            groups.setdefault(key, []).append(a)
        return groups

    def _build_item(
        self, key: _GroupKey, group: List[CryptoAsset], now: datetime,
    ) -> Optional[MigrationItem]:
        name, variant, _ksize, _ref = key
        canonical = normalise_family(name, self.mappings)
        first_asset = group[0]
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
            asset_key_size_bits=getattr(first_asset, "key_size_bits", None),
            project_ids=sorted({a.project_id for a in group}),
            asset_count=len(group),
            source_family=canonical,
            source_primitive=_enum_value(first_asset.primitive),
            use_case=mapping.use_case,
            recommended_pqc=mapping.recommended_pqc,
            recommended_standard=mapping.standard,
            notes=mapping.notes,
            priority_score=score,
            status=MigrationItemStatus(status_from_score(score)),
            recommended_deadline=deadline.isoformat() if deadline else None,
        )

    @staticmethod
    def _summarise(items: List[MigrationItem]) -> MigrationPlanSummary:
        status_counts: Dict[str, int] = {}
        for item in items:
            key = item.status if isinstance(item.status, str) else item.status.value
            status_counts[key] = status_counts.get(key, 0) + 1
        deadlines = [i.recommended_deadline for i in items if i.recommended_deadline]
        earliest = min(deadlines) if deadlines else None
        return MigrationPlanSummary(
            total_items=len(items),
            status_counts=status_counts,
            earliest_deadline=earliest,
        )

    async def _list_vulnerable_assets(
        self, resolved: ResolvedScope,
    ) -> List[CryptoAsset]:
        """Return all quantum-vulnerable assets across the resolved project IDs.

        Picks the most recent completed/partial scan per project and filters
        to assets with a quantum-vulnerable primitive and a known mapping.
        """
        out: List[CryptoAsset] = []
        project_ids = resolved.project_ids or []
        repo = CryptoAssetRepository(self.db)
        canonical_families = {m.source_family for m in self.mappings.mappings}
        for pid in project_ids:
            scan_doc = await self._latest_scan_for_project(pid)
            if not scan_doc:
                continue
            assets = await repo.list_by_scan(pid, scan_doc["_id"], limit=10000)
            out.extend(self._filter_vulnerable(assets, canonical_families))
        return out

    def _filter_vulnerable(
        self, assets: List[CryptoAsset], canonical_families: set,
    ) -> List[CryptoAsset]:
        filtered: List[CryptoAsset] = []
        for a in assets:
            if _coerce_primitive(a.primitive) not in _QV_PRIMITIVES:
                continue
            canonical = normalise_family(a.name or "", self.mappings)
            if canonical in canonical_families:
                filtered.append(a)
        return filtered

    async def _latest_scan_for_project(self, project_id: str) -> Optional[dict]:
        """Most recent completed/partial scan for a project, or None.

        Uses find().to_list() + in-memory filter so it works against both the
        real motor driver and the in-process fake database used in integration
        tests (which doesn't support `$in` queries or `find_one(sort=...)`).
        """
        cursor = self.db.scans.find({"project_id": project_id})
        docs = await cursor.to_list(length=1000)
        completed = [d for d in docs if d.get("status") in ("completed", "partial")]
        if not completed:
            return None
        completed.sort(key=_created_at, reverse=True)
        return completed[0]

    def _find_mapping(self, family: str, primitive) -> Optional[PQCMapping]:
        prim_val = _enum_value(primitive)
        exact = next(
            (m for m in self.mappings.mappings
             if m.source_family == family and m.source_primitive == prim_val),
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
        family: str, timelines: List[Timeline],
    ) -> Optional[datetime]:
        applicable = [t for t in timelines if family in t.applies_to]
        if not applicable:
            return None
        return min(t.deadline for t in applicable)


def _enum_value(val) -> str:
    if hasattr(val, "value"):
        return val.value
    return val or ""


def _coerce_primitive(prim):
    if isinstance(prim, CryptoPrimitive):
        return prim
    if isinstance(prim, str):
        try:
            return CryptoPrimitive(prim)
        except ValueError:
            return None
    return None


def _created_at(doc: dict) -> datetime:
    val = doc.get("created_at")
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    return datetime.min.replace(tzinfo=timezone.utc)
