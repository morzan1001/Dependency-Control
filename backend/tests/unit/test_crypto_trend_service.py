import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from app.services.analytics.crypto_trends import CryptoTrendService, auto_bucket
from app.services.analytics.scopes import ResolvedScope


def test_auto_bucket_week_for_90d():
    assert auto_bucket(timedelta(days=90)) == "week"


def test_auto_bucket_day_for_14d():
    assert auto_bucket(timedelta(days=14)) == "day"


def test_auto_bucket_month_for_long():
    assert auto_bucket(timedelta(days=300)) == "month"


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


@pytest.mark.asyncio
async def test_a_project_scoped_trend_counts_only_that_projects_findings(db):
    """The scoped project list is the tenant boundary: another project's crypto findings stay out."""
    now = datetime.now(timezone.utc)
    ts = now - timedelta(days=2)
    await _seed_findings(
        db,
        [
            _crypto_finding("m1", "scanMine", ts, project_id="mine"),
            _crypto_finding("m2", "scanMine", ts, project_id="mine"),
            _crypto_finding("o1", "scanOther", ts, project_id="other"),
            _crypto_finding("o2", "scanOther", ts, project_id="other"),
            _crypto_finding("o3", "scanOther", ts, project_id="other"),
        ],
    )
    resolved = ResolvedScope(scope="project", scope_id="mine", project_ids=["mine"])
    points = await CryptoTrendService(db)._finding_buckets(
        resolved, "total_crypto_findings", "day", now - timedelta(days=7), now
    )
    assert sum(p.value for p in points) == 2.0


@pytest.mark.asyncio
async def test_a_global_trend_counts_every_project(db):
    """Global scope carries no project list and must query the estate rather than an empty set."""
    now = datetime.now(timezone.utc)
    ts = now - timedelta(days=2)
    await _seed_findings(
        db,
        [
            _crypto_finding("m1", "scanMine", ts, project_id="mine"),
            _crypto_finding("m2", "scanMine", ts, project_id="mine"),
            _crypto_finding("o1", "scanOther", ts, project_id="other"),
        ],
    )
    resolved = ResolvedScope(scope="global", scope_id=None, project_ids=None)
    points = await CryptoTrendService(db)._finding_buckets(
        resolved, "total_crypto_findings", "day", now - timedelta(days=7), now
    )
    assert sum(p.value for p in points) == 3.0


@pytest.mark.asyncio
async def test_a_second_bucket_over_the_same_range_is_not_served_the_first_buckets_series(db):
    """bucket is an independent query parameter, so day and month over one range are two answers."""
    resolved = ResolvedScope(scope="project", scope_id="p", project_ids=["p"])
    await _seed_findings(
        db,
        [
            _crypto_finding("j1", "sjan-early", datetime(2026, 1, 10, tzinfo=timezone.utc)),
            _crypto_finding("j2", "sjan-late", datetime(2026, 1, 20, tzinfo=timezone.utc)),
            _crypto_finding("f1", "sfeb", datetime(2026, 2, 15, tzinfo=timezone.utc)),
        ],
    )
    svc = CryptoTrendService(db)
    query = {
        "resolved": resolved,
        "metric": "total_crypto_findings",
        "range_start": datetime(2025, 12, 1, tzinfo=timezone.utc),
        "range_end": datetime(2026, 3, 1, tzinfo=timezone.utc),
    }
    monthly = await svc.trend(bucket="month", **query)
    daily = await svc.trend(bucket="day", **query)

    assert daily.bucket == "day"
    assert len(monthly.points) == 2
    assert len(daily.points) == 3


@pytest.mark.asyncio
async def test_two_users_under_user_scope_are_not_served_each_others_series(db):
    """scope="user" carries no scope_id, so only the project set keeps the shared cache from leaking across tenants."""
    now = datetime.now(timezone.utc)
    await _seed_findings(
        db,
        [
            _crypto_finding("a1", "sa", now - timedelta(days=1), project_id="pa"),
            _crypto_finding("b1", "sb", now - timedelta(days=1), project_id="pb"),
            _crypto_finding("b2", "sb", now - timedelta(days=1), project_id="pb"),
        ],
    )
    svc = CryptoTrendService(db)
    query = {
        "metric": "total_crypto_findings",
        "bucket": "week",
        "range_start": now - timedelta(days=7),
        "range_end": now,
    }

    user_a = await svc.trend(resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["pa"]), **query)
    user_b = await svc.trend(resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["pb"]), **query)

    assert sum(p.value for p in user_a.points) == 1
    assert sum(p.value for p in user_b.points) == 2


@pytest.mark.asyncio
async def test_concurrent_callers_of_one_series_share_one_computation(db):
    runs = 0

    async def _finding_buckets(*_args):
        nonlocal runs
        runs += 1
        await asyncio.sleep(0)
        return []

    resolved = ResolvedScope(scope="project", scope_id="p", project_ids=["p"])
    now = datetime.now(timezone.utc)
    svc = CryptoTrendService(db)
    query = {
        "metric": "total_crypto_findings",
        "bucket": "week",
        "range_start": now - timedelta(days=7),
        "range_end": now,
    }
    with patch.object(svc, "_finding_buckets", new=_finding_buckets):
        await asyncio.gather(*(svc.trend(resolved=resolved, **query) for _ in range(3)))

    assert runs == 1


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


@pytest.mark.asyncio
async def test_distinct_cipher_suites_are_counted_once_per_bucket(db):
    now = datetime.now(timezone.utc)
    ts = now - timedelta(days=2)
    resolved = ResolvedScope(scope="project", scope_id="p", project_ids=["p"])
    for _id, suites in (("c1", ["TLS_A", "TLS_B"]), ("c2", ["TLS_B", "TLS_C"])):
        await db.crypto_assets.insert_one(
            {"_id": _id, "asset_type": "protocol", "project_id": "p", "created_at": ts, "cipher_suites": suites}
        )

    points = await CryptoTrendService(db)._asset_distinct_buckets(
        resolved,
        "day",
        now - timedelta(days=7),
        now,
        asset_type="protocol",
        field="cipher_suites",
        unwind_field="$cipher_suites",
    )

    assert [(p.metric, p.value) for p in points] == [("unique_cipher_suites", 3.0)]
