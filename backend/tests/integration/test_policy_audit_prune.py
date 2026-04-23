from datetime import datetime, timedelta, timezone

import pytest

from app.models.policy_audit_entry import PolicyAuditEntry
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.schemas.policy_audit import PolicyAuditAction


def _entry(version, ts):
    return PolicyAuditEntry(
        policy_scope="system",
        project_id=None,
        version=version,
        action=PolicyAuditAction.UPDATE,
        actor_user_id="u1",
        actor_display_name="alice",
        timestamp=ts,
        snapshot={"version": version},
        change_summary=f"v{version}",
        comment=None,
    )


@pytest.mark.asyncio
async def test_prune_deletes_only_older(client, db, admin_auth_headers):
    now = datetime.now(timezone.utc)
    repo = PolicyAuditRepository(db)
    await repo.insert(_entry(1, now - timedelta(days=200)))
    await repo.insert(_entry(2, now - timedelta(days=30)))
    await repo.insert(_entry(3, now))

    cutoff = now - timedelta(days=90)
    resp = await client.delete(
        f"/api/v1/crypto-policies/system/audit?before={cutoff.isoformat()}",
        headers=admin_auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 1

    remaining = await repo.list(policy_scope="system", limit=10)
    assert {e.version for e in remaining} == {2, 3}


@pytest.mark.asyncio
async def test_prune_denied_for_non_admin(client, db, member_auth_headers):
    cutoff = datetime.now(timezone.utc)
    resp = await client.delete(
        f"/api/v1/crypto-policies/system/audit?before={cutoff.isoformat()}",
        headers=member_auth_headers,
    )
    assert resp.status_code in (401, 403)
