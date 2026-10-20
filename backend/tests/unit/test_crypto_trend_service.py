import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from app.services.analytics.crypto_trends import CryptoTrendService, auto_bucket
from app.services.analytics.scopes import ResolvedScope

_DAY = timedelta(days=1)
_START = datetime(2026, 3, 1, tzinfo=timezone.utc)
_END = _START + 7 * _DAY


def test_auto_bucket_week_for_90d():
    assert auto_bucket(timedelta(days=90)) == "week"


def test_auto_bucket_day_for_14d():
    assert auto_bucket(timedelta(days=14)) == "day"


def test_auto_bucket_month_for_long():
    assert auto_bucket(timedelta(days=300)) == "month"


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


async def _project(db, project_id="p", default_branch="main", deleted_branches=()):
    await db.projects.insert_one(
        {
            "_id": project_id,
            "name": project_id,
            "default_branch": default_branch,
            "deleted_branches": list(deleted_branches),
        }
    )


async def _scan(db, scan_id, at, *, project_id="p", branch="main", findings=0, waived=0, **fields):
    await db.scans.insert_one(
        {"_id": scan_id, "project_id": project_id, "branch": branch, "status": "completed", "created_at": at, **fields}
    )
    for index in range(findings + waived):
        finding = _crypto_finding(f"{scan_id}-{index}", scan_id, at, project_id=project_id, waived=index >= findings)
        await db.findings.insert_one(finding)


def _resolved(*project_ids):
    if len(project_ids) == 1:
        return ResolvedScope(scope="project", scope_id=project_ids[0], project_ids=list(project_ids))
    return ResolvedScope(scope="user", scope_id=None, project_ids=list(project_ids))


async def _series(db, *project_ids, metric="total_crypto_findings", bucket="day", start=_START, end=_END):
    series = await CryptoTrendService(db).trend(
        resolved=_resolved(*(project_ids or ("p",))), metric=metric, bucket=bucket, range_start=start, range_end=end
    )
    return [(point.timestamp, point.value) for point in series.points]


def _days(*values, first=_START):
    return [(first + index * _DAY, float(value)) for index, value in enumerate(values)]


@pytest.mark.asyncio
async def test_trend_returns_empty_points_on_no_data(db):
    await _project(db)

    series = await CryptoTrendService(db).trend(
        resolved=_resolved("p"), metric="total_crypto_findings", bucket="week", range_start=_START, range_end=_END
    )

    assert series.points == []
    assert series.scope == "project"


@pytest.mark.asyncio
async def test_trend_excludes_waived_findings(db):
    await _project(db)
    await _scan(db, "s", _START + 5 * _DAY, findings=2, waived=1)

    assert await _series(db) == _days(2, 2, first=_START + 5 * _DAY)


@pytest.mark.asyncio
async def test_the_latest_scan_of_a_bucket_counts_for_it(db):
    await _project(db)
    await _scan(db, "early", _START + 5 * _DAY, findings=3)
    await _scan(db, "late", _START + 5 * _DAY + timedelta(hours=2), findings=1)

    assert await _series(db) == _days(1, 1, first=_START + 5 * _DAY)


@pytest.mark.asyncio
async def test_trend_buckets_by_month_and_latest_scan_wins(db):
    await _project(db)
    await _scan(db, "jold", datetime(2026, 1, 10, tzinfo=timezone.utc), findings=2)
    await _scan(db, "jnew", datetime(2026, 1, 20, tzinfo=timezone.utc), findings=1)
    await _scan(db, "feb", datetime(2026, 2, 15, tzinfo=timezone.utc), findings=3)

    points = await _series(
        db,
        bucket="month",
        start=datetime(2025, 12, 1, tzinfo=timezone.utc),
        end=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )

    assert [(at.month, value) for at, value in points] == [(1, 1.0), (2, 3.0)]


@pytest.mark.asyncio
async def test_a_project_scoped_trend_counts_only_that_projects_findings(db):
    """The scoped project list is the tenant boundary: another project's crypto findings stay out."""
    for project_id, findings in (("mine", 2), ("other", 3)):
        await _project(db, project_id)
        await _scan(db, f"s-{project_id}", _START + 5 * _DAY, project_id=project_id, findings=findings)

    assert await _series(db, "mine") == _days(2, 2, first=_START + 5 * _DAY)


@pytest.mark.asyncio
async def test_a_global_trend_counts_every_project(db):
    """Global scope carries no project list and must query the estate rather than an empty set."""
    for project_id, findings in (("mine", 2), ("other", 1)):
        await _project(db, project_id)
        await _scan(db, f"s-{project_id}", _START + 5 * _DAY, project_id=project_id, findings=findings)

    series = await CryptoTrendService(db).trend(
        resolved=ResolvedScope(scope="global", scope_id=None, project_ids=None),
        metric="total_crypto_findings",
        bucket="day",
        range_start=_START,
        range_end=_END,
    )

    assert [point.value for point in series.points] == [3.0, 3.0]


@pytest.mark.asyncio
async def test_each_bucket_sums_the_projects_heads_at_its_end(db):
    await _project(db, "pa")
    await _project(db, "pb")
    await _scan(db, "sa", _START + 1 * _DAY, project_id="pa", findings=2)
    await _scan(db, "sb", _START + 3 * _DAY, project_id="pb", findings=3)

    assert await _series(db, "pa", "pb") == _days(2, 2, 5, 5, 5, 5, first=_START + 1 * _DAY)


@pytest.mark.asyncio
async def test_a_project_without_a_new_scan_carries_its_last_count_forward(db):
    await _project(db)
    await _scan(db, "s", _START + 1 * _DAY, findings=2)

    assert await _series(db) == _days(2, 2, 2, 2, 2, 2, first=_START + 1 * _DAY)


@pytest.mark.asyncio
async def test_the_last_scan_before_the_range_counts_from_its_start(db):
    await _project(db)
    await _scan(db, "before", _START - 20 * _DAY, findings=4)
    await _scan(db, "within", _START + 4 * _DAY, findings=1)

    assert await _series(db) == _days(4, 4, 4, 4, 1, 1, 1)


@pytest.mark.asyncio
async def test_a_scan_without_crypto_findings_brings_its_bucket_to_zero(db):
    await _project(db)
    await _scan(db, "dirty", _START + 1 * _DAY, findings=3)
    await _scan(db, "clean", _START + 3 * _DAY)
    await _scan(db, "waived", _START + 5 * _DAY, waived=2)

    assert await _series(db) == _days(3, 3, 0, 0, 0, 0, first=_START + 1 * _DAY)


@pytest.mark.asyncio
async def test_a_feature_branch_scan_does_not_move_the_default_branchs_posture(db):
    await _project(db)
    await _scan(db, "main", _START + 1 * _DAY, findings=2)
    await _scan(db, "feature", _START + 3 * _DAY, branch="feature/x", findings=5)

    assert await _series(db) == _days(2, 2, 2, 2, 2, 2, first=_START + 1 * _DAY)


@pytest.mark.asyncio
async def test_without_a_default_branch_the_latest_build_of_any_live_branch_counts(db):
    await _project(db, default_branch=None, deleted_branches=["gone"])
    await _scan(db, "dev", _START + 1 * _DAY, branch="dev", findings=2)
    await _scan(db, "deleted", _START + 3 * _DAY, branch="gone", findings=5)
    await _scan(db, "tag", _START + 4 * _DAY, branch="v1", commit_tag="v1", findings=7)
    await _scan(db, "feature", _START + 5 * _DAY, branch="feature/x", findings=1)

    assert await _series(db) == _days(2, 2, 2, 2, 1, 1, first=_START + 1 * _DAY)


@pytest.mark.asyncio
async def test_a_rescan_counts_from_when_it_reanalysed_the_head_build(db):
    await _project(db)
    await _scan(db, "old", _START, findings=7)
    await _scan(db, "build", _START + 2 * _DAY, findings=2)
    await _scan(db, "rescan", _START + 4 * _DAY, findings=5, is_rescan=True, original_scan_id="build")
    await _scan(db, "old-rescan", _START + 5 * _DAY, findings=9, is_rescan=True, original_scan_id="old")

    assert await _series(db) == _days(7, 7, 2, 2, 5, 5, 5)


@pytest.mark.asyncio
async def test_unique_algorithms_count_the_head_scans_assets_whenever_they_were_written(db):
    await _project(db)
    await _scan(db, "s1", _START + 1 * _DAY)
    await _scan(db, "feature", _START + 3 * _DAY, branch="feature/x")
    for _id, scan_id, name in (("a1", "s1", "AES"), ("a2", "s1", "RSA"), ("a3", "s1", "AES"), ("f1", "feature", "MD5")):
        await db.crypto_assets.insert_one(
            {
                "_id": _id,
                "project_id": "p",
                "scan_id": scan_id,
                "asset_type": "algorithm",
                "name": name,
                "created_at": _START - 30 * _DAY,
            }
        )

    assert await _series(db, metric="unique_algorithms") == _days(2, 2, 2, 2, 2, 2, first=_START + 1 * _DAY)


@pytest.mark.asyncio
async def test_distinct_cipher_suites_are_counted_once_per_bucket(db):
    await _project(db)
    await _scan(db, "s", _START + 5 * _DAY)
    for _id, suites in (("c1", ["TLS_A", "TLS_B"]), ("c2", ["TLS_B", "TLS_C"])):
        await db.crypto_assets.insert_one(
            {"_id": _id, "asset_type": "protocol", "project_id": "p", "scan_id": "s", "cipher_suites": suites}
        )

    points = await _series(db, metric="unique_cipher_suites")

    assert points == _days(3, 3, first=_START + 5 * _DAY)


@pytest.mark.asyncio
async def test_a_second_bucket_over_the_same_range_is_not_served_the_first_buckets_series(db):
    """bucket is an independent query parameter, so day and month over one range are two answers."""
    await _project(db)
    await _scan(db, "sjan", datetime(2026, 1, 10, tzinfo=timezone.utc), findings=1)
    await _scan(db, "sfeb", datetime(2026, 2, 15, tzinfo=timezone.utc), findings=1)
    query = {"start": datetime(2025, 12, 1, tzinfo=timezone.utc), "end": datetime(2026, 3, 1, tzinfo=timezone.utc)}

    monthly = await _series(db, bucket="month", **query)
    daily = await _series(db, bucket="day", **query)

    assert (len(monthly), len(daily)) == (2, 50)


@pytest.mark.asyncio
async def test_two_users_under_user_scope_are_not_served_each_others_series(db):
    """scope="user" carries no scope_id, so only the project set keeps the shared cache from leaking across tenants."""
    for project_id, findings in (("pa", 1), ("pb", 2)):
        await _project(db, project_id)
        await _scan(db, f"s-{project_id}", _START + 5 * _DAY, project_id=project_id, findings=findings)
    svc = CryptoTrendService(db)
    query = {"metric": "total_crypto_findings", "bucket": "week", "range_start": _START, "range_end": _END}

    user_a = await svc.trend(resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["pa"]), **query)
    user_b = await svc.trend(resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["pb"]), **query)

    assert [point.value for point in user_a.points] == [1.0]
    assert [point.value for point in user_b.points] == [2.0]


@pytest.mark.asyncio
async def test_concurrent_callers_of_one_series_share_one_computation(db):
    runs = 0

    async def _build(*_args):
        nonlocal runs
        runs += 1
        await asyncio.sleep(0)

    svc = CryptoTrendService(db)
    query = {"metric": "total_crypto_findings", "bucket": "week", "range_start": _START, "range_end": _END}
    with patch.object(svc, "_build", new=_build):
        await asyncio.gather(*(svc.trend(resolved=_resolved("p"), **query) for _ in range(3)))

    assert runs == 1


@pytest.mark.asyncio
async def test_trend_rejects_excessive_range(db):
    with pytest.raises(ValueError):
        await CryptoTrendService(db).trend(
            resolved=_resolved("p"),
            metric="total_crypto_findings",
            bucket="week",
            range_start=_END - timedelta(days=1000),
            range_end=_END,
        )
