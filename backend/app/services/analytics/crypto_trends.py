"""
CryptoTrendService — time-bucketed crypto finding + asset aggregations.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.schemas.analytics import TrendPoint, TrendSeries
from app.services.analytics.cache import get_analytics_cache
from app.services.analytics.scopes import ResolvedScope

Bucket = Literal["day", "week", "month"]
Metric = Literal[
    "total_crypto_findings",
    "quantum_vulnerable_findings",
    "weak_algo_findings",
    "weak_key_findings",
    "cert_expiring_soon",
    "cert_expired",
    "unique_algorithms",
    "unique_cipher_suites",
]

_MAX_RANGE = timedelta(days=730)

_METRIC_FILTER: Dict[str, Dict[str, Any]] = {
    "total_crypto_findings": {"type": {"$regex": "^crypto_"}},
    "quantum_vulnerable_findings": {"type": "crypto_quantum_vulnerable"},
    "weak_algo_findings": {"type": "crypto_weak_algorithm"},
    "weak_key_findings": {"type": "crypto_weak_key"},
    "cert_expiring_soon": {"type": "crypto_cert_expiring_soon"},
    "cert_expired": {"type": "crypto_cert_expired"},
}


def _auto_bucket(delta: timedelta) -> Bucket:
    if delta <= timedelta(days=14):
        return "day"
    if delta <= timedelta(days=90):
        return "week"
    return "month"


def _dateTrunc_unit(bucket: Bucket) -> str:
    return {"day": "day", "week": "week", "month": "month"}[bucket]


class CryptoTrendService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.cache = get_analytics_cache()

    async def trend(
        self, *, resolved: ResolvedScope, metric: Metric, bucket: Bucket,
        range_start: datetime, range_end: datetime,
    ) -> TrendSeries:
        if range_end - range_start > _MAX_RANGE:
            raise ValueError(f"requested range exceeds 2-year cap ({_MAX_RANGE.days}d)")
        if range_end < range_start:
            raise ValueError("range_end must be after range_start")

        cache_key = self._cache_key(resolved, metric, bucket, range_start, range_end)
        hit, cached = self.cache.get(cache_key)
        if hit:
            cached_resp = TrendSeries.model_validate(cached)
            cached_resp.cache_hit = True
            return cached_resp

        if metric in _METRIC_FILTER:
            points = await self._finding_buckets(
                resolved, metric, bucket, range_start, range_end,
            )
        elif metric == "unique_algorithms":
            points = await self._asset_distinct_buckets(
                resolved, bucket, range_start, range_end,
                asset_type="algorithm", field="name",
            )
        elif metric == "unique_cipher_suites":
            points = await self._asset_distinct_buckets(
                resolved, bucket, range_start, range_end,
                asset_type="protocol", field="cipher_suites",
                unwind_field="$cipher_suites",
            )
        else:
            raise ValueError(f"unsupported metric: {metric!r}")

        series = TrendSeries(
            scope=resolved.scope,
            scope_id=resolved.scope_id,
            metric=metric,
            bucket=bucket,
            points=points,
            range_start=range_start,
            range_end=range_end,
        )
        self.cache.set(cache_key, series.model_dump())
        return series

    async def _finding_buckets(
        self, resolved: ResolvedScope, metric: Metric, bucket: Bucket,
        range_start: datetime, range_end: datetime,
    ) -> List[TrendPoint]:
        match: Dict[str, Any] = dict(_METRIC_FILTER[metric])
        match["scan_created_at"] = {"$gte": range_start, "$lte": range_end}
        if resolved.project_ids is not None:
            match["project_id"] = {"$in": resolved.project_ids}
        pipeline = [
            {"$match": match},
            {"$group": {
                "_id": {"$dateTrunc": {
                    "date": "$scan_created_at", "unit": _dateTrunc_unit(bucket),
                }},
                "value": {"$sum": 1},
            }},
            {"$sort": {"_id": 1}},
        ]
        out: List[TrendPoint] = []
        async for row in self.db.findings.aggregate(pipeline):
            out.append(TrendPoint(
                timestamp=row["_id"],
                metric=metric,
                value=float(row["value"]),
            ))
        return out

    async def _asset_distinct_buckets(
        self, resolved: ResolvedScope, bucket: Bucket,
        range_start: datetime, range_end: datetime,
        *, asset_type: str, field: str, unwind_field: Optional[str] = None,
    ) -> List[TrendPoint]:
        match: Dict[str, Any] = {
            "asset_type": asset_type,
            "created_at": {"$gte": range_start, "$lte": range_end},
        }
        if resolved.project_ids is not None:
            match["project_id"] = {"$in": resolved.project_ids}

        pipeline: List[Dict[str, Any]] = [{"$match": match}]
        if unwind_field:
            pipeline.append({"$unwind": unwind_field})
        field_ref = f"${field}"
        pipeline.extend([
            {"$group": {
                "_id": {
                    "bucket": {"$dateTrunc": {
                        "date": "$created_at", "unit": _dateTrunc_unit(bucket),
                    }},
                    "value": field_ref,
                },
            }},
            {"$group": {"_id": "$_id.bucket", "value": {"$sum": 1}}},
            {"$sort": {"_id": 1}},
        ])
        metric_name = (
            "unique_algorithms" if asset_type == "algorithm" else "unique_cipher_suites"
        )
        out: List[TrendPoint] = []
        async for row in self.db.crypto_assets.aggregate(pipeline):
            out.append(TrendPoint(
                timestamp=row["_id"],
                metric=metric_name,
                value=float(row["value"]),
            ))
        return out

    def _cache_key(
        self, resolved: ResolvedScope, metric: Metric, bucket: Bucket,
        range_start: datetime, range_end: datetime,
    ) -> tuple:
        rs = range_start.isoformat()
        re = range_end.isoformat()
        fingerprint = hashlib.sha256(f"{rs}|{re}".encode()).hexdigest()[:16]
        return (
            "trends",
            resolved.scope,
            resolved.scope_id,
            metric,
            bucket,
            fingerprint,
        )
