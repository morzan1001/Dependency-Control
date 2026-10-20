from datetime import datetime, timedelta, timezone

from app.services.pqc_migration.scoring import (
    COUNT_WEIGHT,
    DEADLINE_WEIGHT,
    EXPOSURE_WEIGHT,
    KEY_WEAKNESS_WEIGHT,
    priority_score,
    status_from_score,
)


class _A:
    def __init__(
        self, asset_type="algorithm", certificate_format=None, detection_context=None, key_size_bits=None, name="RSA"
    ):
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
    deadline = now + timedelta(days=365 * 5)
    score = priority_score(
        asset=_A(name="RSA", key_size_bits=2048),
        source_family="RSA",
        deadline=deadline,
        now=now,
        asset_count=1,
    )
    assert 0 <= score <= 100


def test_short_key_bumps_weakness():
    now = datetime.now(timezone.utc)
    deadline = now + timedelta(days=365 * 5)
    weak = priority_score(
        asset=_A(name="RSA", key_size_bits=1024),
        source_family="RSA",
        deadline=deadline,
        now=now,
        asset_count=1,
    )
    strong = priority_score(
        asset=_A(name="RSA", key_size_bits=4096),
        source_family="RSA",
        deadline=deadline,
        now=now,
        asset_count=1,
    )
    assert weak > strong


def test_imminent_deadline_raises_priority():
    now = datetime.now(timezone.utc)
    soon = now + timedelta(days=180)
    far = now + timedelta(days=365 * 10)
    s_soon = priority_score(asset=_A(), source_family="RSA", deadline=soon, now=now, asset_count=1)
    s_far = priority_score(asset=_A(), source_family="RSA", deadline=far, now=now, asset_count=1)
    assert s_soon > s_far


def test_many_occurrences_bump_count():
    now = datetime.now(timezone.utc)
    deadline = now + timedelta(days=365)
    s1 = priority_score(asset=_A(), source_family="RSA", deadline=deadline, now=now, asset_count=1)
    s100 = priority_score(asset=_A(), source_family="RSA", deadline=deadline, now=now, asset_count=100)
    assert s100 > s1


def test_certificate_asset_bumps_exposure():
    now = datetime.now(timezone.utc)
    deadline = now + timedelta(days=365)
    cert = priority_score(
        asset=_A(asset_type="certificate", certificate_format="X.509"),
        source_family="RSA",
        deadline=deadline,
        now=now,
        asset_count=1,
    )
    internal = priority_score(
        asset=_A(detection_context="binary"),
        source_family="RSA",
        deadline=deadline,
        now=now,
        asset_count=1,
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


def test_single_asset_still_contributes_to_count_score():
    from app.services.pqc_migration.scoring import _score_count

    assert _score_count(1) > 0.0
    assert _score_count(10) > _score_count(1)
    assert _score_count(100) > _score_count(10)


def test_count_score_capped_at_100():
    from app.services.pqc_migration.scoring import _score_count

    assert _score_count(10_000) <= 100.0
    assert _score_count(1_000_000) <= 100.0


def test_count_score_zero_for_non_positive():
    from app.services.pqc_migration.scoring import _score_count

    assert _score_count(0) == 0.0
    assert _score_count(-1) == 0.0


def test_key_weakness_ratio_at_and_above_minimum():
    """An at-minimum key (ratio 1.0) scores 50.0; stronger ratios score lower, undersized 100.0."""
    from app.services.pqc_migration.scoring import _score_key_weakness

    at_min = _score_key_weakness(_A(key_size_bits=2048), "RSA")
    just_above = _score_key_weakness(_A(key_size_bits=2049), "RSA")
    mid = _score_key_weakness(_A(key_size_bits=3072), "RSA")  # ratio 1.5
    strong = _score_key_weakness(_A(key_size_bits=4096), "RSA")  # ratio 2.0
    undersized = _score_key_weakness(_A(key_size_bits=1024), "RSA")

    assert at_min == 50.0
    assert just_above == 50.0
    assert mid == 30.0
    assert strong == 20.0
    assert undersized == 100.0


def test_an_eddsa_key_is_weighed_against_the_elliptic_curve_minimum():
    from app.services.pqc_migration.scoring import _score_key_weakness

    assert _score_key_weakness(_A(key_size_bits=256), "EdDSA") == 50.0
    assert _score_key_weakness(_A(key_size_bits=128), "EdDSA") == 100.0


def test_exposure_constants_are_module_level():
    from app.services.pqc_migration import scoring

    assert hasattr(scoring, "EXPOSURE_CERTIFICATE")
    assert hasattr(scoring, "EXPOSURE_RELATED_MATERIAL")
    assert hasattr(scoring, "EXPOSURE_BINARY")
    assert hasattr(scoring, "EXPOSURE_SOURCE")
    assert hasattr(scoring, "EXPOSURE_DEFAULT")
    assert scoring.EXPOSURE_CERTIFICATE > scoring.EXPOSURE_RELATED_MATERIAL
    assert scoring.EXPOSURE_RELATED_MATERIAL > scoring.EXPOSURE_DEFAULT
    assert scoring.EXPOSURE_DEFAULT > scoring.EXPOSURE_BINARY


def test_binary_detection_is_the_least_exposed_classification():
    from app.services.pqc_migration.scoring import _score_exposure

    binary = _score_exposure(_A(detection_context="binary"))
    assert binary < _score_exposure(_A())
    assert binary < _score_exposure(_A(detection_context="source"))
    assert binary < _score_exposure(_A(asset_type="related-crypto-material"))


def test_a_binary_detected_asset_is_prioritised_below_an_unclassified_one():
    now = datetime.now(timezone.utc)
    deadline = now + timedelta(days=365 * 5)
    binary = priority_score(
        asset=_A(detection_context="binary"),
        source_family="RSA",
        deadline=deadline,
        now=now,
        asset_count=1,
    )
    unclassified = priority_score(
        asset=_A(),
        source_family="RSA",
        deadline=deadline,
        now=now,
        asset_count=1,
    )
    assert binary < unclassified
