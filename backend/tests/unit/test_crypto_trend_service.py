from datetime import datetime, timedelta, timezone

import pytest

from app.services.analytics.crypto_trends import CryptoTrendService, _auto_bucket
from app.services.analytics.scopes import ResolvedScope


def test_auto_bucket_week_for_90d():
    assert _auto_bucket(timedelta(days=90)) == "week"


def test_auto_bucket_day_for_14d():
    assert _auto_bucket(timedelta(days=14)) == "day"


def test_auto_bucket_month_for_long():
    assert _auto_bucket(timedelta(days=300)) == "month"


@pytest.mark.asyncio
async def test_trend_returns_empty_points_on_no_data(db):
    resolved = ResolvedScope(scope="project", scope_id="p", project_ids=["p"])
    now = datetime.now(timezone.utc)
    series = await CryptoTrendService(db).trend(
        resolved=resolved,
        metric="total_crypto_findings",
        bucket="week",
        range_start=now - timedelta(days=30),
        range_end=now,
    )
    assert series.points == []
    assert series.scope == "project"


def _crypto_finding(_id, scan_id, scan_created_at, *, project_id="p", waived=False, ftype="crypto_weak_key"):
    return {
        "_id": _id,
        "finding_id": _id,
        "type": ftype,
        "project_id": project_id,
        "scan_id": scan_id,
        "scan_created_at": scan_created_at,
        "waived": waived,
        "component": "pkg",
        "version": "1.0.0",
        "severity": "HIGH",
        "details": {},
    }


async def _seed_findings(db, findings):
    for f in findings:
        await db.findings.insert_one(f)


@pytest.mark.asyncio
async def test_trend_excludes_waived_findings(db):
    """Waived/accepted crypto findings must not inflate the trend (audit #11)."""
    now = datetime.now(timezone.utc)
    ts = now - timedelta(days=2)
    resolved = ResolvedScope(scope="project", scope_id="p", project_ids=["p"])
    await _seed_findings(
        db,
        [
            _crypto_finding("a1", "scanA", ts, waived=False),
            _crypto_finding("a2", "scanA", ts, waived=False),
            _crypto_finding("a3", "scanA", ts, waived=True),  # must be excluded
        ],
    )
    points = await CryptoTrendService(db)._finding_buckets(
        resolved, "total_crypto_findings", "day", now - timedelta(days=7), now
    )
    assert sum(p.value for p in points) == 2.0


@pytest.mark.asyncio
async def test_trend_dedups_rescans_in_same_bucket(db):
    """Two scans of the same project in one bucket must not double-count the same
    persistent issue — count the latest scan, not every scan (audit #11)."""
    now = datetime.now(timezone.utc)
    ts = now - timedelta(days=2)
    resolved = ResolvedScope(scope="project", scope_id="p", project_ids=["p"])
    await _seed_findings(
        db,
        [
            _crypto_finding("s1", "scanA", ts),
            _crypto_finding("s2", "scanB", ts),  # re-scan of the same issue
        ],
    )
    points = await CryptoTrendService(db)._finding_buckets(
        resolved, "total_crypto_findings", "day", now - timedelta(days=7), now
    )
    assert sum(p.value for p in points) == 1.0


@pytest.mark.asyncio
async def test_trend_buckets_by_month_and_latest_scan_wins(db):
    """Discriminating end-to-end check (audit SC#2): two scans in the same month
    must collapse to the LATEST scan's count, and different months must produce
    distinct buckets. Requires FakeMongo to actually truncate $dateTrunc."""
    resolved = ResolvedScope(scope="project", scope_id="p", project_ids=["p"])
    jan_old = datetime(2026, 1, 10, tzinfo=timezone.utc)
    jan_new = datetime(2026, 1, 20, tzinfo=timezone.utc)
    feb = datetime(2026, 2, 15, tzinfo=timezone.utc)
    await _seed_findings(
        db,
        [
            # January, older scan: 2 findings
            _crypto_finding("jo1", "jold", jan_old),
            _crypto_finding("jo2", "jold", jan_old),
            # January, newer scan: 1 finding (the latest scan in the Jan bucket)
            _crypto_finding("jn1", "jnew", jan_new),
            # February: 3 findings
            _crypto_finding("f1", "feb", feb),
            _crypto_finding("f2", "feb", feb),
            _crypto_finding("f3", "feb", feb),
        ],
    )
    points = await CryptoTrendService(db)._finding_buckets(
        resolved, "total_crypto_findings", "month", datetime(2025, 12, 1, tzinfo=timezone.utc), datetime(2026, 3, 1, tzinfo=timezone.utc)
    )
    assert len(points) == 2  # exactly one bucket per month, not one per scan
    by_month = {p.timestamp.month: p.value for p in points}
    assert by_month == {1: 1.0, 2: 3.0}  # Jan = latest scan (1), not 2 or 3; Feb = 3


@pytest.mark.asyncio
async def test_trend_rejects_excessive_range(db):
    resolved = ResolvedScope(scope="project", scope_id="p", project_ids=["p"])
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        await CryptoTrendService(db).trend(
            resolved=resolved,
            metric="total_crypto_findings",
            bucket="week",
            range_start=now - timedelta(days=1000),
            range_end=now,
        )
