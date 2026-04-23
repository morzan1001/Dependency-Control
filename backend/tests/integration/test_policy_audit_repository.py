from datetime import datetime, timedelta, timezone

import pytest

from app.models.policy_audit_entry import PolicyAuditEntry
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.schemas.policy_audit import PolicyAuditAction


def _entry(version=1, policy_scope="system", project_id=None,
           ts=None, action=PolicyAuditAction.UPDATE):
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
    await repo.insert(_entry(version=1))
    await repo.insert(_entry(version=2))
    entries = await repo.list(policy_scope="system", limit=10)
    assert len(entries) == 2


@pytest.mark.asyncio
async def test_list_respects_project_id_filter(db):
    repo = PolicyAuditRepository(db)
    await repo.insert(_entry(policy_scope="project", project_id="p1", version=1))
    await repo.insert(_entry(policy_scope="project", project_id="p2", version=1))
    p1_entries = await repo.list(policy_scope="project", project_id="p1", limit=10)
    assert len(p1_entries) == 1
    assert p1_entries[0].project_id == "p1"


@pytest.mark.asyncio
async def test_get_by_version(db):
    repo = PolicyAuditRepository(db)
    await repo.insert(_entry(version=7))
    hit = await repo.get_by_version(policy_scope="system", project_id=None, version=7)
    assert hit is not None
    assert hit.version == 7

    miss = await repo.get_by_version(policy_scope="system", project_id=None, version=99)
    assert miss is None


@pytest.mark.asyncio
async def test_delete_older_than(db):
    now = datetime.now(timezone.utc)
    repo = PolicyAuditRepository(db)
    await repo.insert(_entry(version=1, ts=now - timedelta(days=200)))
    await repo.insert(_entry(version=2, ts=now - timedelta(days=30)))
    await repo.insert(_entry(version=3, ts=now))

    cutoff = now - timedelta(days=90)
    deleted = await repo.delete_older_than(
        policy_scope="system", project_id=None, cutoff=cutoff,
    )
    assert deleted == 1
    remaining = await repo.list(policy_scope="system", limit=10)
    assert {e.version for e in remaining} == {2, 3}
