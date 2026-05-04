"""
CryptoHotspotService

Aggregates crypto_assets + findings into HotspotResponse for α/β/γ scopes.
Five grouping dimensions: name, primitive, asset_type, weakness_tag, severity.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.schemas.analytics import HotspotEntry, HotspotResponse
from app.services.analytics.cache import get_analytics_cache
from app.services.analytics.scopes import ResolvedScope

GroupBy = Literal["name", "primitive", "asset_type", "weakness_tag", "severity"]
_SUPPORTED_GROUPINGS = {"name", "primitive", "asset_type", "weakness_tag", "severity"}


class CryptoHotspotService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.cache = get_analytics_cache()

    async def hotspots(
        self,
        *,
        resolved: ResolvedScope,
        group_by: GroupBy,
        scan_id: Optional[str] = None,
        limit: int = 100,
    ) -> HotspotResponse:
        if group_by not in _SUPPORTED_GROUPINGS:
            raise ValueError(f"unsupported group_by: {group_by!r}")
        limit = max(1, min(limit, 500))

        latest_scan_ids = await self._pick_scan_ids(resolved, scan_id)
        cache_key = self._cache_key(resolved, group_by, latest_scan_ids, limit)
        hit, cached = self.cache.get(cache_key)
        if hit:
            cached_resp = HotspotResponse.model_validate(cached)
            cached_resp.cache_hit = True
            return cached_resp

        items = await self._aggregate(
            project_ids=resolved.project_ids,
            scan_ids=latest_scan_ids,
            group_by=group_by,
            limit=limit,
        )
        resp = HotspotResponse(
            scope=resolved.scope,
            scope_id=resolved.scope_id,
            grouping_dimension=group_by,
            items=items,
            total=len(items),
            generated_at=datetime.now(timezone.utc),
            cache_hit=False,
        )
        self.cache.set(cache_key, resp.model_dump())
        return resp

    async def _pick_scan_ids(
        self,
        resolved: ResolvedScope,
        override: Optional[str],
    ) -> List[str]:
        if override:
            return [override]
        match: Dict[str, Any] = {"status": {"$in": ["completed", "partial"]}}
        if resolved.project_ids is not None:
            match["project_id"] = {"$in": resolved.project_ids}
        pipeline = [
            {"$match": match},
            {"$sort": {"created_at": -1}},
            {"$group": {"_id": "$project_id", "scan_id": {"$first": "$_id"}}},
        ]
        return [row["scan_id"] async for row in self.db.scans.aggregate(pipeline)]

    async def _aggregate(
        self,
        *,
        project_ids: Optional[List[str]],
        scan_ids: List[str],
        group_by: GroupBy,
        limit: int,
    ) -> List[HotspotEntry]:
        # severity and weakness_tag are properties of findings, not assets,
        # so the aggregation pivots accordingly. Asset-bound dimensions
        # (name/primitive/asset_type) keep the asset-first pipeline.
        if group_by in ("severity", "weakness_tag"):
            return await self._aggregate_by_finding_dimension(
                project_ids=project_ids,
                scan_ids=scan_ids,
                group_by=group_by,
                limit=limit,
            )

        match: Dict[str, Any] = {"scan_id": {"$in": scan_ids}} if scan_ids else {}
        if project_ids is not None:
            match["project_id"] = {"$in": project_ids}

        group_key = self._group_key_stage(group_by)
        asset_pipeline: List[Dict[str, Any]] = [
            {"$match": match},
            {
                "$group": {
                    "_id": group_key,
                    "asset_count": {"$sum": 1},
                    "project_ids": {"$addToSet": "$project_id"},
                    "locations": {"$push": "$occurrence_locations"},
                    "first_seen": {"$min": "$created_at"},
                    "last_seen": {"$max": "$created_at"},
                }
            },
            {"$sort": {"asset_count": -1}},
            {"$limit": limit},
        ]

        now = datetime.now(timezone.utc)
        out: List[HotspotEntry] = []
        async for row in self.db.crypto_assets.aggregate(asset_pipeline):
            key = self._key_from_row(row, group_by)
            if key is None:
                continue
            locations_flat: List[str] = []
            for subl in row.get("locations", []):
                if isinstance(subl, list):
                    locations_flat.extend(subl)
                elif isinstance(subl, str):
                    locations_flat.append(subl)
            out.append(
                HotspotEntry(
                    key=key,
                    grouping_dimension=group_by,
                    asset_count=row["asset_count"],
                    finding_count=0,
                    severity_mix={},
                    locations=locations_flat[:20],
                    project_ids=list(row.get("project_ids", [])),
                    first_seen=row.get("first_seen") or now,
                    last_seen=row.get("last_seen") or now,
                )
            )

        await self._enrich_with_findings(out, project_ids, scan_ids, group_by)
        return out

    async def _aggregate_by_finding_dimension(
        self,
        *,
        project_ids: Optional[List[str]],
        scan_ids: List[str],
        group_by: GroupBy,
        limit: int,
    ) -> List[HotspotEntry]:
        """Aggregate hotspots whose grouping dimension lives on findings.

        For 'severity' we group findings by severity. For 'weakness_tag'
        we unwind details.weakness_tags (populated by the protocol_cipher
        analyzer) and group by tag. asset_count is the number of distinct
        bom_refs contributing to the group, finding_count the raw match
        count.
        """
        match: Dict[str, Any] = {"type": {"$regex": "^crypto_"}}
        if scan_ids:
            match["scan_id"] = {"$in": scan_ids}
        if project_ids is not None:
            match["project_id"] = {"$in": project_ids}

        pre_stages: List[Dict[str, Any]] = [{"$match": match}]
        if group_by == "weakness_tag":
            pre_stages.extend(
                [
                    {"$match": {"details.weakness_tags": {"$exists": True, "$ne": []}}},
                    {"$unwind": "$details.weakness_tags"},
                ]
            )

        group_field = "$severity" if group_by == "severity" else "$details.weakness_tags"
        pipeline: List[Dict[str, Any]] = pre_stages + [
            {
                "$group": {
                    "_id": {"key": group_field, "severity": "$severity"},
                    "finding_count": {"$sum": 1},
                    "bom_refs": {"$addToSet": "$details.bom_ref"},
                    "project_ids": {"$addToSet": "$project_id"},
                    "first_seen": {"$min": "$scan_created_at"},
                    "last_seen": {"$max": "$scan_created_at"},
                }
            },
        ]

        accum: Dict[str, Dict[str, Any]] = {}
        async for row in self.db.findings.aggregate(pipeline):
            key = (row.get("_id") or {}).get("key")
            if not key:
                continue
            sev = (row.get("_id") or {}).get("severity") or "UNKNOWN"
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
            entry["bom_refs"].update(b for b in row.get("bom_refs", []) if b)
            entry["project_ids"].update(row.get("project_ids", []))
            entry["severity_mix"][sev] = entry["severity_mix"].get(sev, 0) + row["finding_count"]
            for field in ("first_seen", "last_seen"):
                value = row.get(field)
                if value is None:
                    continue
                current = entry[field]
                if (
                    current is None
                    or (field == "first_seen" and value < current)
                    or (field == "last_seen" and value > current)
                ):
                    entry[field] = value

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
                project_ids=list(data["project_ids"]),
                first_seen=data["first_seen"] or now,
                last_seen=data["last_seen"] or now,
            )
            for key, data in ranked
        ]

    def _group_key_stage(self, group_by: GroupBy) -> Any:
        if group_by == "name":
            return {"name": "$name", "variant": "$variant"}
        if group_by == "primitive":
            return "$primitive"
        if group_by == "asset_type":
            return "$asset_type"
        # severity / weakness_tag take the finding-based path; not used here.
        return None

    def _key_from_row(self, row: Dict[str, Any], group_by: GroupBy) -> Optional[str]:
        key = row.get("_id")
        if group_by == "name" and isinstance(key, dict):
            name = key.get("name") or ""
            variant = key.get("variant") or ""
            return f"{name}-{variant}".rstrip("-") if name else None
        if isinstance(key, str) and key:
            return key
        return None

    async def _enrich_with_findings(
        self,
        items: List[HotspotEntry],
        project_ids: Optional[List[str]],
        scan_ids: List[str],
        group_by: GroupBy,
    ) -> None:
        if not items:
            return
        join_field = self._finding_join_field(group_by)
        if join_field is None:
            # severity/weakness_tag don't have a clean per-asset join into findings;
            # leave finding_count/severity_mix at their defaults.
            return
        match: Dict[str, Any] = {
            "scan_id": {"$in": scan_ids},
            "type": {"$regex": "^crypto_"},
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
        mix: Dict[str, Dict[str, int]] = {}
        total: Dict[str, int] = {}
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

    @staticmethod
    def _finding_join_field(group_by: GroupBy) -> Optional[str]:
        """Map a hotspot grouping dimension to the matching findings field.

        The crypto analyzer copies asset_name / asset_type / primitive into
        finding.details, so we group findings on the same dimension as the
        asset aggregation to make the enrichment join cleanly.
        """
        if group_by == "name":
            return "$details.asset_name"
        if group_by == "primitive":
            return "$details.primitive"
        if group_by == "asset_type":
            return "$details.asset_type"
        return None

    def _cache_key(
        self,
        resolved: ResolvedScope,
        group_by: GroupBy,
        scan_ids: List[str],
        limit: int,
    ) -> tuple:
        fingerprint = hashlib.sha256("|".join(sorted(scan_ids)).encode()).hexdigest()[:16]
        return (
            "hotspots",
            resolved.scope,
            resolved.scope_id,
            group_by,
            fingerprint,
            limit,
        )
