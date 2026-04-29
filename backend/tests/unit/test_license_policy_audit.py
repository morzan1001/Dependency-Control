"""Unit tests for the license-policy change-summary helper."""

from app.services.audit.history import compute_license_policy_change_summary


def test_initial_policy_summary():
    s = compute_license_policy_change_summary(
        old=None, new={"distribution_model": "distributed"}
    )
    assert "Initial license policy" in s


def test_cleared_policy_summary():
    s = compute_license_policy_change_summary(
        old={"distribution_model": "distributed"}, new={}
    )
    assert s == "License policy cleared"


def test_field_transition_summary():
    s = compute_license_policy_change_summary(
        old={"allow_strong_copyleft": False, "distribution_model": "distributed"},
        new={"allow_strong_copyleft": True, "distribution_model": "distributed"},
    )
    assert "allow_strong_copyleft: False -> True" in s


def test_multiple_field_transitions():
    s = compute_license_policy_change_summary(
        old={"distribution_model": "distributed", "library_usage": "mixed"},
        new={"distribution_model": "internal_only", "library_usage": "unmodified"},
    )
    assert "distribution_model: distributed -> internal_only" in s
    assert "library_usage: mixed -> unmodified" in s


def test_added_field_summary():
    s = compute_license_policy_change_summary(
        old={"distribution_model": "distributed"},
        new={"distribution_model": "distributed", "allow_strong_copyleft": True},
    )
    assert "added allow_strong_copyleft=True" in s


def test_removed_field_summary():
    s = compute_license_policy_change_summary(
        old={"distribution_model": "distributed", "allow_strong_copyleft": True},
        new={"distribution_model": "distributed"},
    )
    assert "removed allow_strong_copyleft" in s


def test_no_effective_change_returns_marker():
    s = compute_license_policy_change_summary(
        old={"distribution_model": "distributed"},
        new={"distribution_model": "distributed"},
    )
    assert s == "No effective changes"


def test_summary_is_capped_at_200_chars():
    old = {}
    new = {f"extra_field_{i}": f"value_{i}" for i in range(50)}
    s = compute_license_policy_change_summary(old=old, new=new)
    assert len(s) <= 200
