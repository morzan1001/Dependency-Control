"""Aggregate crypto_assets + findings into HotspotResponse, grouped by one of
name, primitive, asset_type, weakness_tag, or severity.
"""

from datetime import datetime, timezone
from typing import Any, get_args

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.cache import scope_digest
from app.models.finding import CRYPTO_FINDING_TYPES
from app.schemas.analytics import GroupBy, HotspotEntry, HotspotResponse
from app.services.analytics.cache import get_analytics_cache
from app.services.analytics.scopes import ResolvedScope

# The chat tool passes an unchecked string, so this is its only validation.
_SUPPORTED_GROUPINGS = frozenset(get_args(GroupBy))
# Asset-first groupings: the asset field grouped on and the findings field joined to it. Names group bare,
# because findings carry details.asset_name == asset.name without the variant. The other groupings live
# on findings alone.
_ASSET_GROUPINGS = {
    "name": ("$name", "$details.asset_name"),
    "primitive": ("$primitive", "$details.primitive"),
    "asset_type": ("$asset_type", "$details.asset_type"),
}

# $push of every occurrence_locations array can exceed MongoDB's 16MB group-doc limit on a hot
# group, so the accumulator reads the arrays of this many assets and no more.
_LOCATION_SAMPLE_ASSETS = 20
# Distinct locations one entry lists. Matches the heatmap's column budget so a row can mark
# every column it belongs to rather than reading as absent from the ones past the cut.
_LOCATIONS_PER_ENTRY = 30


def _distinct_locations(sampled: list[Any]) -> list[str]:
    """Flatten the sampled assets' location arrays, first occurrence wins."""
    flat: list[str] = []
    for entry in sampled:
        if isinstance(entry, list):
            flat.extend(str(item) for item in entry)
        elif isinstance(entry, str):
            flat.append(entry)
    return list(dict.fromkeys(flat))


class CryptoHotspotService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.cache = get_analytics_cache()

    async def hotspots(
        self,
        *,
        resolved: ResolvedScope,
        group_by: GroupBy,
        scan_id: str | None = None,
        limit: int = 100,
    ) -> HotspotResponse:
        if group_by not in _SUPPORTED_GROUPINGS:
            raise ValueError(f"unsupported group_by: {group_by!r}")
        limit = max(1, min(limit, 500))

        latest_scan_ids = await self._pick_scan_ids(resolved, scan_id)
        scope = (resolved.scope, resolved.scope_id, scope_digest(resolved.project_ids))
        key = ("crypto-hotspots", *scope, group_by, scope_digest(latest_scan_ids), limit)
        return await self.cache.get_or_compute(key, lambda: self._build(resolved, group_by, latest_scan_ids, limit))

    async def _build(
        self, resolved: ResolvedScope, group_by: GroupBy, scan_ids: list[str], limit: int
    ) -> HotspotResponse:
        items = await self._aggregate(
            project_ids=resolved.project_ids,
            scan_ids=scan_ids,
            group_by=group_by,
            limit=limit,
        )
        return HotspotResponse(
            scope=resolved.scope,
            scope_id=resolved.scope_id,
            grouping_dimension=group_by,
            items=items,
            total=len(items),
            generated_at=datetime.now(timezone.utc),
        )

    async def _pick_scan_ids(
        self,
        resolved: ResolvedScope,
        override: str | None,
    ) -> list[str]:
        if override:
            return [override]
        from app.services.releases import resolve_scan_ids

        return list((await resolve_scan_ids(self.db, resolved.project_ids, projects=resolved.projects)).values())

    async def _aggregate(
        self,
        *,
        project_ids: list[str] | None,
        scan_ids: list[str],
        group_by: GroupBy,
        limit: int,
    ) -> list[HotspotEntry]:
        if group_by not in _ASSET_GROUPINGS:
            return await self._aggregate_by_finding_dimension(
                project_ids=project_ids,
                scan_ids=scan_ids,
                group_by=group_by,
                limit=limit,
            )
        group_key, join_field = _ASSET_GROUPINGS[group_by]

        # Empty scan_ids must match nothing ($in: []), not disable the filter
        # (which would aggregate every historical scan).
        match: dict[str, Any] = {"scan_id": {"$in": scan_ids}}
        if project_ids is not None:
            match["project_id"] = {"$in": project_ids}

        asset_pipeline: list[dict[str, Any]] = [
            {"$match": match},
            {
                "$group": {
                    "_id": group_key,
                    "asset_count": {"$sum": 1},
                    "project_ids": {"$addToSet": "$project_id"},
                    "locations": {"$firstN": {"input": "$occurrence_locations", "n": _LOCATION_SAMPLE_ASSETS}},
                    "first_seen": {"$min": "$created_at"},
                    "last_seen": {"$max": "$created_at"},
                }
            },
            {"$sort": {"asset_count": -1}},
            {"$limit": limit},
        ]

        now = datetime.now(timezone.utc)
        out: list[HotspotEntry] = []
        async for row in self.db.crypto_assets.aggregate(asset_pipeline):
            key = row.get("_id")
            if not isinstance(key, str) or not key:
                continue
            distinct = _distinct_locations(row.get("locations", []))
            sampled_every_asset = row["asset_count"] <= _LOCATION_SAMPLE_ASSETS
            out.append(
                HotspotEntry(
                    key=key,
                    grouping_dimension=group_by,
                    asset_count=row["asset_count"],
                    finding_count=0,
                    severity_mix={},
                    locations=distinct[:_LOCATIONS_PER_ENTRY],
                    locations_complete=sampled_every_asset and len(distinct) <= _LOCATIONS_PER_ENTRY,
                    project_ids=list(row.get("project_ids", [])),
                    first_seen=row.get("first_seen") or now,
                    last_seen=row.get("last_seen") or now,
                )
            )

        await self._enrich_with_findings(out, project_ids, scan_ids, join_field)
        return out

    async def _aggregate_by_finding_dimension(
        self,
        *,
        project_ids: list[str] | None,
        scan_ids: list[str],
        group_by: GroupBy,
        limit: int,
    ) -> list[HotspotEntry]:
        """Aggregate hotspots whose grouping dimension lives on findings (severity/weakness_tag).

        asset_count is the count of distinct (scan_id, bom_ref) assets; finding_count the raw match count.
        """
        # Exclude waived findings (a risk decision, not current posture) so hotspots
        # agree with crypto_trends. Empty scan_ids matches nothing ($in: []).
        match: dict[str, Any] = {
            "type": {"$in": sorted(CRYPTO_FINDING_TYPES)},
            "waived": {"$ne": True},
            "scan_id": {"$in": scan_ids},
        }
        if project_ids is not None:
            match["project_id"] = {"$in": project_ids}

        pre_stages: list[dict[str, Any]] = [{"$match": match}]
        if group_by == "weakness_tag":
            pre_stages.extend(
                [
                    {"$match": {"details.weakness_tags": {"$exists": True, "$ne": []}}},
                    {"$unwind": "$details.weakness_tags"},
                ]
            )

        group_field = "$severity" if group_by == "severity" else "$details.weakness_tags"
        pipeline: list[dict[str, Any]] = [
            *pre_stages,
            {
                "$group": {
                    "_id": {"key": group_field, "severity": "$severity"},
                    "finding_count": {"$sum": 1},
                    "bom_refs": {"$addToSet": {"scan_id": "$scan_id", "bom_ref": "$details.bom_ref"}},
                    "project_ids": {"$addToSet": "$project_id"},
                    "first_seen": {"$min": "$scan_created_at"},
                    "last_seen": {"$max": "$scan_created_at"},
                }
            },
        ]

        accum: dict[str, dict[str, Any]] = {}
        async for row in self.db.findings.aggregate(pipeline):
            key = row["_id"].get("key")
            if not key:
                continue
            sev = row["_id"].get("severity") or "UNKNOWN"
            entry = accum.setdefault(
                key,
                {
                    "finding_count": 0,
                    "bom_refs": set(),
                    "project_ids": set(),
                    "severity_mix": {},
                    "first_seen": None,
                    "last_seen": None,
                },
            )
            entry["finding_count"] += row["finding_count"]
            entry["bom_refs"].update((b["scan_id"], b["bom_ref"]) for b in row["bom_refs"] if b.get("bom_ref"))
            entry["project_ids"].update(row["project_ids"])
            entry["severity_mix"][sev] = entry["severity_mix"].get(sev, 0) + row["finding_count"]
            for field, pick in (("first_seen", min), ("last_seen", max)):
                if (value := row.get(field)) is not None:
                    entry[field] = value if entry[field] is None else pick(entry[field], value)

        now = datetime.now(timezone.utc)
        ranked = sorted(accum.items(), key=lambda kv: kv[1]["finding_count"], reverse=True)[:limit]
        return [
            HotspotEntry(
                key=str(key),
                grouping_dimension=group_by,
                asset_count=len(data["bom_refs"]),
                finding_count=data["finding_count"],
                severity_mix=data["severity_mix"],
                locations=[],
                # This dimension groups findings, which carry no per-asset location.
                locations_complete=False,
                project_ids=list(data["project_ids"]),
                first_seen=data["first_seen"] or now,
                last_seen=data["last_seen"] or now,
            )
            for key, data in ranked
        ]

    async def _enrich_with_findings(
        self,
        items: list[HotspotEntry],
        project_ids: list[str] | None,
        scan_ids: list[str],
        join_field: str,
    ) -> None:
        if not items:
            return
        match: dict[str, Any] = {
            "scan_id": {"$in": scan_ids},
            "type": {"$in": sorted(CRYPTO_FINDING_TYPES)},
            # Exclude waived findings to match crypto_trends posture semantics.
            "waived": {"$ne": True},
        }
        if project_ids is not None:
            match["project_id"] = {"$in": project_ids}
        pipeline = [
            {"$match": match},
            {
                "$group": {
                    "_id": {
                        "key": join_field,
                        "severity": "$severity",
                    },
                    "count": {"$sum": 1},
                }
            },
        ]
        mix: dict[str, dict[str, int]] = {}
        total: dict[str, int] = {}
        async for row in self.db.findings.aggregate(pipeline):
            key = row["_id"].get("key") or ""
            if not key:
                continue
            sev = row["_id"].get("severity") or "UNKNOWN"
            mix.setdefault(key, {})[sev] = mix.setdefault(key, {}).get(sev, 0) + row["count"]
            total[key] = total.get(key, 0) + row["count"]

        for item in items:
            if item.key in total:
                item.finding_count = total[item.key]
                item.severity_mix = mix[item.key]
