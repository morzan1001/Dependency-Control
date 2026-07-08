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
    """Waived crypto findings must not inflate the trend."""
    now = datetime.now(timezone.utc)
    ts = now - timedelta(days=2)
    resolved = ResolvedScope(scope="project", scope_id="p", project_ids=["p"])
    await _seed_findings(
        db,
        [
            _crypto_finding("a1", "scanA", ts, waived=False),
            _crypto_finding("a2", "scanA", ts, waived=False),
            _crypto_finding("a3", "scanA", ts, waived=True),
        ],
    )
    points = await CryptoTrendService(db)._finding_buckets(
        resolved, "total_crypto_findings", "day", now - timedelta(days=7), now
    )
    assert sum(p.value for p in points) == 2.0


@pytest.mark.asyncio
async def test_trend_dedups_rescans_in_same_bucket(db):
    """Two scans in one bucket count the latest scan, not every scan."""
    now = datetime.now(timezone.utc)
    ts = now - timedelta(days=2)
    resolved = ResolvedScope(scope="project", scope_id="p", project_ids=["p"])
    await _seed_findings(
        db,
        [
            _crypto_finding("s1", "scanA", ts),
            _crypto_finding("s2", "scanB", ts),
        ],
    )
    points = await CryptoTrendService(db)._finding_buckets(
        resolved, "total_crypto_findings", "day", now - timedelta(days=7), now
    )
    assert sum(p.value for p in points) == 1.0


@pytest.mark.asyncio
async def test_trend_buckets_by_month_and_latest_scan_wins(db):
    """Two scans in a month collapse to the latest scan's count; distinct months stay separate."""
    resolved = ResolvedScope(scope="project", scope_id="p", project_ids=["p"])
    jan_old = datetime(2026, 1, 10, tzinfo=timezone.utc)
    jan_new = datetime(2026, 1, 20, tzinfo=timezone.utc)
    feb = datetime(2026, 2, 15, tzinfo=timezone.utc)
    await _seed_findings(
        db,
        [
            _crypto_finding("jo1", "jold", jan_old),
            _crypto_finding("jo2", "jold", jan_old),
            # jnew is the latest scan in the January bucket.
            _crypto_finding("jn1", "jnew", jan_new),
            _crypto_finding("f1", "feb", feb),
            _crypto_finding("f2", "feb", feb),
            _crypto_finding("f3", "feb", feb),
        ],
    )
    points = await CryptoTrendService(db)._finding_buckets(
        resolved,
        "total_crypto_findings",
        "month",
        datetime(2025, 12, 1, tzinfo=timezone.utc),
        datetime(2026, 3, 1, tzinfo=timezone.utc),
    )
    assert len(points) == 2  # one bucket per month, not one per scan
    by_month = {p.timestamp.month: p.value for p in points}
    assert by_month == {1: 1.0, 2: 3.0}  # Jan = latest scan count (1); Feb = 3


def test_cache_key_distinguishes_users_under_user_scope(db):
    """User-scope keys must differ by project_ids so the shared cache can't leak across tenants."""
    svc = CryptoTrendService(db)
    now = datetime.now(timezone.utc)
    rs, re = now - timedelta(days=30), now
    user_a = ResolvedScope(scope="user", scope_id=None, project_ids=["p1", "p2"])
    user_b = ResolvedScope(scope="user", scope_id=None, project_ids=["p3", "p4"])
    key_a = svc._cache_key(user_a, "total_crypto_findings", "week", rs, re)
    key_b = svc._cache_key(user_b, "total_crypto_findings", "week", rs, re)
    assert key_a != key_b


def test_cache_key_stable_regardless_of_project_order(db):
    """The project fingerprint is order-independent so an equivalent set still hits the cache."""
    svc = CryptoTrendService(db)
    now = datetime.now(timezone.utc)
    rs, re = now - timedelta(days=30), now
    a = ResolvedScope(scope="user", scope_id=None, project_ids=["p1", "p2"])
    b = ResolvedScope(scope="user", scope_id=None, project_ids=["p2", "p1"])
    assert svc._cache_key(a, "total_crypto_findings", "week", rs, re) == svc._cache_key(
        b, "total_crypto_findings", "week", rs, re
    )


def test_cache_key_global_none_distinct_from_empty(db):
    """Global scope (project_ids=None) must not alias an empty project set."""
    svc = CryptoTrendService(db)
    now = datetime.now(timezone.utc)
    rs, re = now - timedelta(days=30), now
    glob = ResolvedScope(scope="global", scope_id=None, project_ids=None)
    empty = ResolvedScope(scope="user", scope_id=None, project_ids=[])
    assert svc._cache_key(glob, "total_crypto_findings", "week", rs, re) != svc._cache_key(
        empty, "total_crypto_findings", "week", rs, re
    )


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
