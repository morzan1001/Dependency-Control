"""
CryptoTrendService — time-bucketed crypto finding + asset aggregations.
"""

from datetime import datetime, timedelta
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.cache import scope_digest
from app.models.finding import CRYPTO_FINDING_TYPES
from app.schemas.analytics import Bucket, Metric, TrendPoint, TrendSeries
from app.services.analytics.cache import get_analytics_cache
from app.services.analytics.scopes import ResolvedScope

_MAX_RANGE = timedelta(days=730)

_METRIC_FILTER: dict[str, dict[str, Any]] = {
    "total_crypto_findings": {"type": {"$in": sorted(CRYPTO_FINDING_TYPES)}},
    "quantum_vulnerable_findings": {"type": "crypto_quantum_vulnerable"},
    "weak_algo_findings": {"type": "crypto_weak_algorithm"},
    "weak_key_findings": {"type": "crypto_weak_key"},
    "cert_expiring_soon": {"type": "crypto_cert_expiring_soon"},
    "cert_expired": {"type": "crypto_cert_expired"},
}


def auto_bucket(delta: timedelta) -> Bucket:
    if delta <= timedelta(days=14):
        return "day"
    if delta <= timedelta(days=90):
        return "week"
    return "month"


class CryptoTrendService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.cache = get_analytics_cache()

    async def trend(
        self,
        *,
        resolved: ResolvedScope,
        metric: Metric,
        bucket: Bucket,
        range_start: datetime,
        range_end: datetime,
    ) -> TrendSeries:
        if range_end - range_start > _MAX_RANGE:
            raise ValueError(f"requested range exceeds 2-year cap ({_MAX_RANGE.days}d)")
        if range_end < range_start:
            raise ValueError("range_end must be after range_start")

        # scope="user" carries no scope_id, so the project set is what keeps two tenants apart.
        key = (
            "crypto-trends",
            resolved.scope,
            resolved.scope_id,
            metric,
            bucket,
            range_start,
            range_end,
            scope_digest(resolved.project_ids),
        )
        return await self.cache.get_or_compute(
            key, lambda: self._build(resolved, metric, bucket, range_start, range_end)
        )

    async def _build(
        self, resolved: ResolvedScope, metric: Metric, bucket: Bucket, range_start: datetime, range_end: datetime
    ) -> TrendSeries:
        if metric in _METRIC_FILTER:
            points = await self._finding_buckets(
                resolved,
                metric,
                bucket,
                range_start,
                range_end,
            )
        elif metric == "unique_algorithms":
            points = await self._asset_distinct_buckets(
                resolved,
                bucket,
                range_start,
                range_end,
                asset_type="algorithm",
                field="name",
            )
        elif metric == "unique_cipher_suites":
            points = await self._asset_distinct_buckets(
                resolved,
                bucket,
                range_start,
                range_end,
                asset_type="protocol",
                field="cipher_suites",
                unwind_field="$cipher_suites",
            )
        else:
            raise ValueError(f"unsupported metric: {metric!r}")

        return TrendSeries(
            scope=resolved.scope,
            scope_id=resolved.scope_id,
            metric=metric,
            bucket=bucket,
            points=points,
            range_start=range_start,
            range_end=range_end,
        )

    async def _finding_buckets(
        self,
        resolved: ResolvedScope,
        metric: Metric,
        bucket: Bucket,
        range_start: datetime,
        range_end: datetime,
    ) -> list[TrendPoint]:
        match: dict[str, Any] = dict(_METRIC_FILTER[metric])
        match["scan_created_at"] = {"$gte": range_start, "$lte": range_end}
        # Exclude waived/accepted findings (a risk decision, not current posture).
        match["waived"] = {"$ne": True}
        if resolved.project_ids is not None:
            match["project_id"] = {"$in": resolved.project_ids}
        trunc = {"$dateTrunc": {"date": "$scan_created_at", "unit": bucket}}
        # Per bucket we count the latest scan per project regardless of scan status;
        # a partial/failed latest scan may under-report, accepted since failed scans
        # typically write no crypto findings.
        pipeline = [
            {"$match": match},
            # Carry project/bucket as fields so later stages don't depend on composite-_id sub-paths.
            {
                "$group": {
                    "_id": {"project": "$project_id", "bucket": trunc, "scan": "$scan_id"},
                    "project": {"$first": "$project_id"},
                    "bucket": {"$first": trunc},
                    "scan_created_at": {"$max": "$scan_created_at"},
                    "cnt": {"$sum": 1},
                }
            },
            # Pick the latest scan per (project, bucket) so re-scans in one bucket
            # (e.g. CI + nightly) count a persistent issue once, not per scan.
            {"$sort": {"scan_created_at": -1}},
            {
                "$group": {
                    "_id": {"project": "$project", "bucket": "$bucket"},
                    "bucket": {"$first": "$bucket"},
                    "value": {"$first": "$cnt"},
                }
            },
            # Sum the per-project latest-scan counts into one value per bucket.
            {"$group": {"_id": "$bucket", "value": {"$sum": "$value"}}},
            {"$sort": {"_id": 1}},
        ]
        return [
            TrendPoint(timestamp=row["_id"], metric=metric, value=float(row["value"]))
            async for row in self.db.findings.aggregate(pipeline)
        ]

    async def _asset_distinct_buckets(
        self,
        resolved: ResolvedScope,
        bucket: Bucket,
        range_start: datetime,
        range_end: datetime,
        *,
        asset_type: str,
        field: str,
        unwind_field: str | None = None,
    ) -> list[TrendPoint]:
        match: dict[str, Any] = {
            "asset_type": asset_type,
            "created_at": {"$gte": range_start, "$lte": range_end},
        }
        if resolved.project_ids is not None:
            match["project_id"] = {"$in": resolved.project_ids}

        pipeline: list[dict[str, Any]] = [{"$match": match}]
        if unwind_field:
            pipeline.append({"$unwind": unwind_field})
        field_ref = f"${field}"
        pipeline.extend(
            [
                {
                    "$group": {
                        "_id": {
                            "bucket": {
                                "$dateTrunc": {
                                    "date": "$created_at",
                                    "unit": bucket,
                                }
                            },
                            "value": field_ref,
                        },
                    }
                },
                {"$group": {"_id": "$_id.bucket", "value": {"$sum": 1}}},
                {"$sort": {"_id": 1}},
            ]
        )
        metric_name = "unique_algorithms" if asset_type == "algorithm" else "unique_cipher_suites"
        return [
            TrendPoint(timestamp=row["_id"], metric=metric_name, value=float(row["value"]))
            async for row in self.db.crypto_assets.aggregate(pipeline)
        ]
