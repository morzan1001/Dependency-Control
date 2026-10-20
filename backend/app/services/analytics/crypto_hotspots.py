import asyncio
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.sorting import case_insensitive_key, case_insensitive_sort
from app.core.cache import scope_digest
from app.core.constants import get_severity_value
from app.models.finding import CRYPTO_FINDING_TYPES
from app.schemas.analytics import GroupBy, HotspotEntry, HotspotResponse
from app.services.analytics.cache import get_analytics_cache
from app.services.analytics.scopes import ResolvedScope

# Names group bare because findings carry details.asset_name without the variant.
_ASSET_GROUPINGS = {
    "name": ("$name", "$details.asset_name"),
    "primitive": ("$primitive", "$details.primitive"),
    "asset_type": ("$asset_type", "$details.asset_type"),
}

# Pushing every occurrence_locations array can exceed MongoDB's 16MB group-doc limit on a hot group.
_LOCATION_SAMPLE_ASSETS = 20
# Matches the heatmap's column budget so a row can mark every column it belongs to.
_LOCATIONS_PER_ENTRY = 30


def _distinct_locations(sampled: list[Any]) -> list[str]:
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
        latest_scan_ids = await self._pick_scan_ids(resolved, scan_id)
        scope = (resolved.scope, resolved.scope_id, scope_digest(resolved.project_ids))
        key = ("crypto-hotspots", *scope, group_by, scope_digest(latest_scan_ids), limit)
        return await self.cache.get_or_compute(key, lambda: self._build(resolved, group_by, latest_scan_ids, limit))

    async def _build(
        self, resolved: ResolvedScope, group_by: GroupBy, scan_ids: list[str], limit: int
    ) -> HotspotResponse:
        items, total = await self._aggregate(
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
            total=total,
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
    ) -> tuple[list[HotspotEntry], int]:
        if group_by not in _ASSET_GROUPINGS:
            return await self._aggregate_by_finding_dimension(
                project_ids=project_ids,
                scan_ids=scan_ids,
                group_by=group_by,
                limit=limit,
            )
        group_key, join_field = _ASSET_GROUPINGS[group_by]

        # Empty scan_ids must match nothing ($in: []), not drop the filter and aggregate every historical scan.
        match: dict[str, Any] = {"scan_id": {"$in": scan_ids}}
        if project_ids is not None:
            match["project_id"] = {"$in": project_ids}

        named_groups: list[dict[str, Any]] = [{"$match": {"_id": {"$nin": [None, ""]}}}]
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
            *named_groups,
            *case_insensitive_sort([("asset_count", -1), ("_id", 1)], {"_id"}),
            {"$limit": limit},
        ]
        # A separate count, as a $facet would put every returned row's project_ids into one 16 MB document.
        count_pipeline: list[dict[str, Any]] = [
            {"$match": match},
            {"$group": {"_id": group_key}},
            *named_groups,
            {"$count": "groups"},
        ]
        rows, counted = await asyncio.gather(
            self.db.crypto_assets.aggregate(asset_pipeline).to_list(None),
            self.db.crypto_assets.aggregate(count_pipeline).to_list(None),
        )

        now = datetime.now(timezone.utc)
        out: list[HotspotEntry] = []
        for row in rows:
            distinct = _distinct_locations(row.get("locations", []))
            sampled_every_asset = row["asset_count"] <= _LOCATION_SAMPLE_ASSETS
            out.append(
                HotspotEntry(
                    key=row["_id"],
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
        return out, counted[0]["groups"] if counted else 0

    async def _aggregate_by_finding_dimension(
        self,
        *,
        project_ids: list[str] | None,
        scan_ids: list[str],
        group_by: GroupBy,
        limit: int,
    ) -> tuple[list[HotspotEntry], int]:
        # Waived findings are a risk decision, not posture; excluding them keeps hotspots in line with crypto_trends.
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
        severity_pipeline: list[dict[str, Any]] = [
            *pre_stages,
            {
                "$group": {
                    "_id": {"key": group_field, "severity": "$severity"},
                    "finding_count": {"$sum": 1},
                    "project_ids": {"$addToSet": "$project_id"},
                    "first_seen": {"$min": "$scan_created_at"},
                    "last_seen": {"$max": "$scan_created_at"},
                }
            },
        ]
        # Refs derive from asset content and repeat across scans, so an asset is its (scan, ref) pair.
        asset_pipeline: list[dict[str, Any]] = [
            *pre_stages,
            {"$match": {"details.bom_ref": {"$nin": [None, ""]}}},
            {"$group": {"_id": {"key": group_field, "scan_id": "$scan_id", "bom_ref": "$details.bom_ref"}}},
            {"$group": {"_id": "$_id.key", "asset_count": {"$sum": 1}}},
        ]
        severity_rows, asset_rows = await asyncio.gather(
            self.db.findings.aggregate(severity_pipeline).to_list(None),
            self.db.findings.aggregate(asset_pipeline).to_list(None),
        )
        asset_counts = {row["_id"]: row["asset_count"] for row in asset_rows}

        accum: dict[str, dict[str, Any]] = {}
        for row in severity_rows:
            key = row["_id"].get("key")
            if not key:
                continue
            sev = row["_id"].get("severity") or "UNKNOWN"
            entry = accum.setdefault(
                key,
                {
                    "finding_count": 0,
                    "project_ids": set(),
                    "severity_mix": {},
                    "first_seen": None,
                    "last_seen": None,
                },
            )
            entry["finding_count"] += row["finding_count"]
            entry["project_ids"].update(row["project_ids"])
            entry["severity_mix"][sev] = entry["severity_mix"].get(sev, 0) + row["finding_count"]
            for field, pick in (("first_seen", min), ("last_seen", max)):
                if (value := row.get(field)) is not None:
                    entry[field] = value if entry[field] is None else pick(entry[field], value)

        now = datetime.now(timezone.utc)
        tie_break = (lambda key: -get_severity_value(key)) if group_by == "severity" else case_insensitive_key
        ranked = sorted(accum.items(), key=lambda kv: (-kv[1]["finding_count"], tie_break(kv[0])))[:limit]
        entries = [
            HotspotEntry(
                key=str(key),
                grouping_dimension=group_by,
                asset_count=asset_counts.get(key, 0),
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
        return entries, len(accum)

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
