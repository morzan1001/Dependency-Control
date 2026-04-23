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
