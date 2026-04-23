from datetime import datetime, timedelta, timezone

import pytest

from app.services.pqc_migration.mappings_loader import Timeline, load_mappings
from app.services.pqc_migration.scoring import (
    EXPOSURE_WEIGHT,
    KEY_WEAKNESS_WEIGHT,
    DEADLINE_WEIGHT,
    COUNT_WEIGHT,
    priority_score,
    status_from_score,
)


class _A:
    def __init__(self, asset_type="algorithm", certificate_format=None,
                 detection_context=None, key_size_bits=None, name="RSA"):
        self.asset_type = asset_type
        self.certificate_format = certificate_format
        self.detection_context = detection_context
        self.key_size_bits = key_size_bits
        self.name = name


def test_weights_sum_to_one():
    total = EXPOSURE_WEIGHT + KEY_WEAKNESS_WEIGHT + DEADLINE_WEIGHT + COUNT_WEIGHT
    assert abs(total - 1.0) < 1e-6


def test_score_is_between_0_and_100():
    now = datetime.now(timezone.utc)
    timelines = [
        Timeline(name="t", deadline=now + timedelta(days=365 * 5), applies_to=["RSA"]),
    ]
    score = priority_score(
        asset=_A(name="RSA", key_size_bits=2048),
        source_family="RSA",
        timelines=timelines, now=now, asset_count=1,
    )
    assert 0 <= score <= 100


def test_short_key_bumps_weakness():
    now = datetime.now(timezone.utc)
    timelines = [Timeline(name="t", deadline=now + timedelta(days=365 * 5), applies_to=["RSA"])]
    weak = priority_score(
        asset=_A(name="RSA", key_size_bits=1024),
        source_family="RSA", timelines=timelines, now=now, asset_count=1,
    )
    strong = priority_score(
        asset=_A(name="RSA", key_size_bits=4096),
        source_family="RSA", timelines=timelines, now=now, asset_count=1,
    )
    assert weak > strong


def test_imminent_deadline_raises_priority():
    now = datetime.now(timezone.utc)
    soon = [Timeline(name="t", deadline=now + timedelta(days=180), applies_to=["RSA"])]
    far = [Timeline(name="t", deadline=now + timedelta(days=365 * 10), applies_to=["RSA"])]
    s_soon = priority_score(asset=_A(), source_family="RSA", timelines=soon, now=now, asset_count=1)
    s_far = priority_score(asset=_A(), source_family="RSA", timelines=far, now=now, asset_count=1)
    assert s_soon > s_far


def test_many_occurrences_bump_count():
    now = datetime.now(timezone.utc)
    timelines = [Timeline(name="t", deadline=now + timedelta(days=365), applies_to=["RSA"])]
    s1 = priority_score(asset=_A(), source_family="RSA", timelines=timelines, now=now, asset_count=1)
    s100 = priority_score(asset=_A(), source_family="RSA", timelines=timelines, now=now, asset_count=100)
    assert s100 > s1


def test_certificate_asset_bumps_exposure():
    now = datetime.now(timezone.utc)
    timelines = [Timeline(name="t", deadline=now + timedelta(days=365), applies_to=["RSA"])]
    cert = priority_score(
        asset=_A(asset_type="certificate", certificate_format="X.509"),
        source_family="RSA", timelines=timelines, now=now, asset_count=1,
    )
    internal = priority_score(
        asset=_A(detection_context="binary"),
        source_family="RSA", timelines=timelines, now=now, asset_count=1,
    )
    assert cert > internal


def test_status_buckets():
    assert status_from_score(95) == "migrate_now"
    assert status_from_score(80) == "migrate_now"
    assert status_from_score(60) == "migrate_soon"
    assert status_from_score(50) == "migrate_soon"
    assert status_from_score(30) == "plan_migration"
    assert status_from_score(10) == "monitor"
    assert status_from_score(0) == "monitor"
