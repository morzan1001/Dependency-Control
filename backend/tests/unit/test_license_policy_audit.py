"""Unit tests for the license-policy change-summary helper, which diffs two resolved policies."""

import pytest

from app.schemas.policy_audit import PolicyAuditAction
from app.schemas.project import LicensePolicySchema
from app.services.audit.history import compute_license_policy_change_summary, record_license_policy_change


def _policy(**fields):
    return LicensePolicySchema(**fields).model_dump()


def test_field_transition_summary():
    s = compute_license_policy_change_summary(old=_policy(), new=_policy(allow_strong_copyleft=True))
    assert s == "allow_strong_copyleft: False -> True"


def test_multiple_field_transitions():
    s = compute_license_policy_change_summary(
        old=_policy(), new=_policy(distribution_model="internal_only", library_usage="unmodified")
    )
    assert s == "distribution_model: distributed -> internal_only, library_usage: mixed -> unmodified"


def test_the_flags_the_scan_reads_are_compared():
    s = compute_license_policy_change_summary(old=_policy(), new=_policy(ignore_transitive=True))
    assert s == "ignore_transitive: False -> True"


@pytest.mark.asyncio
async def test_restating_a_default_records_nothing(db):
    entry = await record_license_policy_change(
        db,
        project_id="p",
        old_policy=_policy(),
        new_policy=_policy(distribution_model="distributed"),
        action=PolicyAuditAction.UPDATE,
        actor=None,
    )

    assert entry is None
    assert await db.crypto_policy_history.count_documents({}) == 0


def test_summary_is_capped_at_200_chars():
    new = _policy(
        distribution_model="internal_only",
        deployment_model="cli_batch",
        library_usage="unmodified",
        allow_strong_copyleft=True,
        allow_network_copyleft=True,
        ignore_dev_dependencies=False,
        ignore_transitive=True,
    )
    s = compute_license_policy_change_summary(old=_policy(), new=new)
    assert len(s) == 200
