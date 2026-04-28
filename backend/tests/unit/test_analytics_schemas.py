from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.analytics import (
    HotspotEntry,
    HotspotResponse,
    ScanDelta,
    TrendPoint,
    TrendSeries,
)


def test_hotspot_entry_minimal():
    e = HotspotEntry(
        key="RSA-1024",
        grouping_dimension="name",
        asset_count=3,
        finding_count=2,
        severity_mix={"HIGH": 2},
        locations=["/a", "/b"],
        project_ids=["p1"],
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    assert e.asset_count == 3
    assert e.severity_mix["HIGH"] == 2


def test_hotspot_response_requires_scope_enum():
    with pytest.raises(ValidationError):
        HotspotResponse(
            scope="invalid-scope",
            scope_id=None,
            grouping_dimension="name",
            items=[],
            total=0,
            generated_at=datetime.now(timezone.utc),
            cache_hit=False,
        )


def test_trend_series_roundtrip():
    now = datetime.now(timezone.utc)
    series = TrendSeries(
        scope="project",
        scope_id="p",
        metric="total_crypto_findings",
        bucket="week",
        points=[TrendPoint(timestamp=now, metric="total_crypto_findings", value=5.0)],
        range_start=now,
        range_end=now,
    )
    assert len(series.points) == 1


def test_scan_delta_shape():
    delta = ScanDelta(
        from_scan_id="s1",
        to_scan_id="s2",
        added=[],
        removed=[],
        unchanged_count=10,
    )
    assert delta.unchanged_count == 10
