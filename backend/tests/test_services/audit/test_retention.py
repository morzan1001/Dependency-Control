"""Unit tests for policy-audit retention pruning."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import settings
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.services.audit.retention import prune_old_audit_entries
from tests.mocks.fake_mongo import FakeDatabase

COLLECTION = PolicyAuditRepository.collection_name


def _entry(*, policy_scope, project_id, policy_type, age_days, _id):
    return {
        "_id": _id,
        "policy_scope": policy_scope,
        "project_id": project_id,
        "policy_type": policy_type,
        "timestamp": datetime.now(timezone.utc) - timedelta(days=age_days),
    }


async def _seed(db):
    docs = [
        _entry(policy_scope="system", project_id=None, policy_type="crypto", age_days=100, _id="sys-crypto-old"),
        _entry(policy_scope="system", project_id=None, policy_type="license", age_days=100, _id="sys-license-old"),
        _entry(policy_scope="system", project_id=None, policy_type="license", age_days=1, _id="sys-license-new"),
        _entry(policy_scope="project", project_id="p1", policy_type="crypto", age_days=100, _id="p1-crypto-old"),
        _entry(policy_scope="project", project_id="p1", policy_type="license", age_days=100, _id="p1-license-old"),
        # project with only a license entry — its project_id still surfaces via distinct
        _entry(policy_scope="project", project_id="p2", policy_type="license", age_days=100, _id="p2-license-old"),
        _entry(policy_scope="project", project_id="p1", policy_type="license", age_days=1, _id="p1-license-new"),
        # entry missing the discriminator — pruned as crypto
        {
            "_id": "legacy-crypto-old",
            "policy_scope": "system",
            "project_id": None,
            "timestamp": datetime.now(timezone.utc) - timedelta(days=100),
        },
    ]
    for d in docs:
        await db[COLLECTION].insert_one(d)


async def _remaining_ids(db):
    docs = await db[COLLECTION].find({}).to_list(length=1000)
    return {d["_id"] for d in docs}


@pytest.mark.asyncio
async def test_prune_removes_old_license_entries(monkeypatch):
    monkeypatch.setattr(settings, "POLICY_AUDIT_RETENTION_DAYS", 30)
    db = FakeDatabase()
    await _seed(db)

    deleted = await prune_old_audit_entries(db)

    remaining = await _remaining_ids(db)
    assert remaining == {"sys-license-new", "p1-license-new"}
    assert deleted == 6


@pytest.mark.asyncio
async def test_prune_disabled_when_retention_zero(monkeypatch):
    monkeypatch.setattr(settings, "POLICY_AUDIT_RETENTION_DAYS", 0)
    db = FakeDatabase()
    await _seed(db)

    deleted = await prune_old_audit_entries(db)

    assert deleted == 0
    assert len(await _remaining_ids(db)) == 8
