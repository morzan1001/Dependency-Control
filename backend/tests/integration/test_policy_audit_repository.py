from datetime import datetime, timedelta, timezone

import pytest

from app.models.policy_audit_entry import PolicyAuditEntry
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.schemas.policy_audit import PolicyAuditAction

_OLDER_VERSION = 4
_NEWER_VERSION = 5
_LIST_LIMIT = 10


def _entry(version=1, policy_scope="system", project_id=None, ts=None, action=PolicyAuditAction.UPDATE):
    return PolicyAuditEntry(
        policy_scope=policy_scope,
        project_id=project_id,
        version=version,
        action=action,
        actor_user_id="u1",
        actor_display_name="alice",
        timestamp=ts or datetime.now(timezone.utc),
        snapshot={"version": version},
        change_summary=f"version {version}",
        comment=None,
    )


@pytest.mark.asyncio
async def test_insert_and_list(db):
    repo = PolicyAuditRepository(db)
    await repo.create(_entry(version=1))
    await repo.create(_entry(version=2))
    entries = await repo.list(policy_scope="system", policy_type="crypto", limit=10)
    assert len(entries) == 2


@pytest.mark.asyncio
async def test_list_respects_project_id_filter(db):
    repo = PolicyAuditRepository(db)
    await repo.create(_entry(policy_scope="project", project_id="p1", version=1))
    await repo.create(_entry(policy_scope="project", project_id="p2", version=1))
    p1_entries = await repo.list(policy_scope="project", policy_type="crypto", project_id="p1", limit=10)
    assert len(p1_entries) == 1
    assert p1_entries[0].project_id == "p1"


@pytest.mark.asyncio
async def test_get_by_version(db):
    repo = PolicyAuditRepository(db)
    await repo.create(_entry(version=7))
    hit = await repo.get_by_version(policy_scope="system", policy_type="crypto", project_id=None, version=7)
    assert hit is not None
    assert hit.version == 7

    miss = await repo.get_by_version(policy_scope="system", policy_type="crypto", project_id=None, version=99)
    assert miss is None


@pytest.mark.asyncio
async def test_entries_saved_in_one_millisecond_are_listed_newest_version_first(db):
    """Two saves can share a stored timestamp, and the revert view reads the head of this list."""
    same_instant = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    repo = PolicyAuditRepository(db)
    await repo.create(_entry(version=_OLDER_VERSION, ts=same_instant))
    await repo.create(_entry(version=_NEWER_VERSION, ts=same_instant, action=PolicyAuditAction.REVERT))

    entries = await repo.list(policy_scope="system", policy_type="crypto", limit=_LIST_LIMIT)

    assert [e.version for e in entries] == [_NEWER_VERSION, _OLDER_VERSION]


@pytest.mark.asyncio
async def test_delete_older_than(db):
    now = datetime.now(timezone.utc)
    repo = PolicyAuditRepository(db)
    await repo.create(_entry(version=1, ts=now - timedelta(days=200)))
    await repo.create(_entry(version=2, ts=now - timedelta(days=30)))
    await repo.create(_entry(version=3, ts=now))

    cutoff = now - timedelta(days=90)
    deleted = await repo.delete_older_than(
        policy_scope="system",
        policy_type="crypto",
        project_id=None,
        cutoff=cutoff,
    )
    assert deleted == 1
    remaining = await repo.list(policy_scope="system", policy_type="crypto", limit=10)
    assert {e.version for e in remaining} == {2, 3}


@pytest.mark.asyncio
async def test_delete_older_than_spares_an_entry_stamped_at_the_cutoff(db):
    """A retention cutoff derived from a timestamp the caller already holds would otherwise take
    the very entry it names with it."""
    cutoff = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    repo = PolicyAuditRepository(db)
    await repo.create(_entry(version=1, ts=cutoff - timedelta(milliseconds=1)))
    await repo.create(_entry(version=2, ts=cutoff))

    deleted = await repo.delete_older_than(policy_scope="system", policy_type="crypto", project_id=None, cutoff=cutoff)

    assert deleted == 1
    remaining = await repo.list(policy_scope="system", policy_type="crypto", limit=_LIST_LIMIT)
    assert [e.version for e in remaining] == [2]


@pytest.mark.asyncio
async def test_a_duplicated_version_resolves_to_its_newest_entry(db):
    """Older histories hold one version number twice; a revert to it means the later revision."""
    earlier = datetime(2026, 1, 1, tzinfo=timezone.utc)
    repo = PolicyAuditRepository(db)
    await repo.create(_entry(version=1, ts=earlier).model_copy(update={"comment": "oldest"}))
    await repo.create(_entry(version=1, ts=earlier + timedelta(days=1)).model_copy(update={"comment": "newest"}))

    hit = await repo.get_by_version(policy_scope="system", policy_type="crypto", project_id=None, version=1)

    assert hit is not None
    assert hit.comment == "newest"


@pytest.mark.asyncio
async def test_crypto_and_license_entries_of_one_project_are_read_and_pruned_apart(db):
    repo = PolicyAuditRepository(db)
    scope = {"policy_scope": "project", "project_id": "p1"}
    await repo.create(_entry(version=3, **scope))
    await repo.create(_entry(version=1, **scope).model_copy(update={"policy_type": "license"}))

    crypto = await repo.list(**scope, policy_type="crypto")
    licenses = await repo.list(**scope, policy_type="license")

    assert [(e.policy_type, e.version) for e in crypto] == [("crypto", 3)]
    assert [(e.policy_type, e.version) for e in licenses] == [("license", 1)]
    assert await repo.max_version(**scope, policy_type="license") == 1
    assert await repo.get_by_version(**scope, version=3, policy_type="license") is None
    tomorrow = datetime.now(timezone.utc) + timedelta(days=1)
    assert await repo.delete_older_than(**scope, cutoff=tomorrow, policy_type="license") == 1
    assert [e.version for e in await repo.list(**scope, policy_type="crypto")] == [3]
