import bisect
from datetime import datetime, timedelta, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.cache import scope_digest
from app.core.constants import FINDINGS_SCAN_TYPE_INDEX
from app.models.finding import CRYPTO_FINDING_TYPES
from app.repositories.scans import ScanRepository
from app.schemas.analytics import Bucket, Metric, TrendPoint, TrendSeries
from app.services.analytics.cache import get_analytics_cache
from app.services.analytics.scopes import ResolvedScope, read_scope_projects

_MAX_RANGE = timedelta(days=730)

_METRIC_FILTER: dict[str, dict[str, Any]] = {
    "total_crypto_findings": {"type": {"$in": sorted(CRYPTO_FINDING_TYPES)}},
    "quantum_vulnerable_findings": {"type": "crypto_quantum_vulnerable"},
    "weak_algo_findings": {"type": "crypto_weak_algorithm"},
    "weak_key_findings": {"type": "crypto_weak_key"},
    "cert_expiring_soon": {"type": "crypto_cert_expiring_soon"},
    "cert_expired": {"type": "crypto_cert_expired"},
}

# (asset_type, field) of the distinct values an asset metric counts.
_ASSET_METRICS: dict[str, tuple[str, str]] = {
    "unique_algorithms": ("algorithm", "name"),
    "unique_cipher_suites": ("protocol", "cipher_suites"),
}


def auto_bucket(delta: timedelta) -> Bucket:
    if delta <= timedelta(days=14):
        return "day"
    if delta <= timedelta(days=90):
        return "week"
    return "month"


def _bucket_start(at: datetime, bucket: Bucket) -> datetime:
    """$dateTrunc's bucket in UTC, whose weeks start on Sunday."""
    day = at.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    if bucket == "week":
        return day - timedelta(days=(day.weekday() + 1) % 7)
    if bucket == "month":
        return day.replace(day=1)
    return day


def _next_bucket(start: datetime, bucket: Bucket) -> datetime:
    if bucket == "month":
        return (start + timedelta(days=32)).replace(day=1)
    return start + (timedelta(weeks=1) if bucket == "week" else timedelta(days=1))


def _bucket_starts(range_start: datetime, range_end: datetime, bucket: Bucket) -> list[datetime]:
    starts: list[datetime] = []
    start = _bucket_start(range_start, bucket)
    while start < range_end:
        starts.append(start)
        start = _next_bucket(start, bucket)
    return starts


def _heads_before(timelines: dict[str, list[tuple[datetime, str]]], end: datetime) -> list[str]:
    heads = []
    for events in timelines.values():
        index = bisect.bisect_left(events, end, key=lambda event: event[0])
        if index:
            heads.append(events[index - 1][1])
    return heads


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
        if metric not in _METRIC_FILTER and metric not in _ASSET_METRICS:
            raise ValueError(f"unsupported metric: {metric!r}")
        projects = resolved.projects
        if projects is None:
            query = {} if resolved.project_ids is None else {"_id": {"$in": resolved.project_ids}}
            projects = await read_scope_projects(self.db, query)
        timelines = await ScanRepository(self.db).head_timelines(projects, range_start, range_end)
        starts = _bucket_starts(range_start, range_end, bucket)
        # A project counts in every bucket with its head analysis at the bucket's end, until its next scan.
        heads = [_heads_before(timelines, _next_bucket(start, bucket)) for start in starts]
        scan_ids = sorted({scan_id for bucket_heads in heads for scan_id in bucket_heads})
        if metric in _METRIC_FILTER:
            counts = await self._finding_counts(metric, scan_ids)
            values = [sum(counts.get(scan_id, 0) for scan_id in bucket_heads) for bucket_heads in heads]
        else:
            per_scan = await self._asset_values(metric, list(timelines), scan_ids)
            values = [
                len(set().union(*(per_scan.get(scan_id, set()) for scan_id in bucket_heads))) for bucket_heads in heads
            ]

        return TrendSeries(
            scope=resolved.scope,
            scope_id=resolved.scope_id,
            metric=metric,
            bucket=bucket,
            points=[
                TrendPoint(timestamp=start, metric=metric, value=float(value))
                for start, bucket_heads, value in zip(starts, heads, values, strict=True)
                if bucket_heads
            ],
            range_start=range_start,
            range_end=range_end,
        )

    async def _finding_counts(self, metric: Metric, scan_ids: list[str]) -> dict[str, int]:
        # Waived findings are a risk decision, not posture.
        match = {**_METRIC_FILTER[metric], "scan_id": {"$in": scan_ids}, "waived": {"$ne": True}}
        pipeline = [{"$match": match}, {"$group": {"_id": "$scan_id", "count": {"$sum": 1}}}]
        cursor = self.db.findings.aggregate(pipeline, hint=FINDINGS_SCAN_TYPE_INDEX)
        return {row["_id"]: row["count"] async for row in cursor}

    async def _asset_values(self, metric: Metric, project_ids: list[str], scan_ids: list[str]) -> dict[str, set[str]]:
        asset_type, field = _ASSET_METRICS[metric]
        pipeline: list[dict[str, Any]] = [
            {"$match": {"project_id": {"$in": project_ids}, "scan_id": {"$in": scan_ids}, "asset_type": asset_type}},
            # A cipher-suite list unwinds to its suites, a name to itself.
            {"$unwind": f"${field}"},
            {"$group": {"_id": "$scan_id", "values": {"$addToSet": f"${field}"}}},
        ]
        return {row["_id"]: set(row["values"]) async for row in self.db.crypto_assets.aggregate(pipeline)}
