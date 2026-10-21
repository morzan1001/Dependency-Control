import pytest

from app.models.policy_audit_entry import PolicyAuditAction
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.schemas.project import LicensePolicySchema
from app.services.audit.history import compute_license_policy_change_summary, record_license_policy_change
from tests.helpers.auth import make_admin
from tests.mocks.fake_mongo import FakeDatabase


def _policy(**fields):
    return LicensePolicySchema(**fields).model_dump()


def test_multiple_field_transitions():
    s = compute_license_policy_change_summary(
        old=_policy(), new=_policy(distribution_model="internal_only", library_usage="unmodified")
    )
    assert s == "distribution_model: distributed -> internal_only, library_usage: mixed -> unmodified"


def test_the_flags_the_scan_reads_are_compared():
    s = compute_license_policy_change_summary(old=_policy(), new=_policy(ignore_transitive=True))
    assert s == "ignore_transitive: False -> True"


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


_PROJECT = "p-license"


async def _record(db, old_entry, new_entry):
    return await record_license_policy_change(
        db, project_id=_PROJECT, old_entry=old_entry, new_entry=new_entry, actor=make_admin()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("old_entry", "action"),
    [
        pytest.param(None, PolicyAuditAction.CREATE, id="new-project"),
        pytest.param({}, PolicyAuditAction.CREATE, id="empty-entry"),
        pytest.param({"library_usage": "mixed"}, PolicyAuditAction.UPDATE, id="stored-entry"),
    ],
)
async def test_the_first_stored_entry_creates_the_policy_and_later_ones_update_it(old_entry, action):
    entry = await _record(FakeDatabase(), old_entry, {"distribution_model": "internal_only"})

    assert (entry.version, entry.action, entry.snapshot) == (1, action, _policy(distribution_model="internal_only"))


@pytest.mark.asyncio
async def test_an_unchanged_resolved_policy_is_not_audited():
    db = FakeDatabase()

    assert await _record(db, None, {"distribution_model": "distributed"}) is None
    assert await db.crypto_policy_history.count_documents({}) == 0


@pytest.mark.asyncio
async def test_an_unreadable_audit_history_leaves_the_project_write_standing(monkeypatch):
    async def _unavailable(*_args, **_kwargs):
        raise RuntimeError("audit history unavailable")

    monkeypatch.setattr(PolicyAuditRepository, "max_version", _unavailable)

    assert await _record(FakeDatabase(), None, {"distribution_model": "internal_only"}) is None
