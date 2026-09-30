"""A scope the resolver read is not read again to find its head scans."""

from datetime import datetime, timezone

import pytest

from app.core.permissions import Permissions
from app.models.user import User
from app.services.analytics.crypto_hotspots import CryptoHotspotService
from app.services.analytics.scopes import ScopeResolver
from app.services.compliance.engine import ComplianceReportEngine
from app.services.pqc_migration.generator import PQCMigrationPlanGenerator

_CONSUMERS = {
    "hotspots": lambda db, resolved: CryptoHotspotService(db).hotspots(resolved=resolved, group_by="name"),
    "compliance": lambda db, resolved: ComplianceReportEngine()._pick_scan_ids(db, resolved, frozenset()),
    "pqc": lambda db, resolved: PQCMigrationPlanGenerator(db)._list_vulnerable_assets(resolved),
}


async def _seeded_db(db):
    await db.teams.insert_one({"_id": "t1", "name": "t1", "members": [{"user_id": "u1", "role": "member"}]})
    await db.projects.insert_one(
        {"_id": "p1", "name": "p1", "latest_scan_id": "s1", "team_ids": ["t1"], "members": [{"user_id": "u1"}]}
    )
    await db.scans.insert_one(
        {"_id": "s1", "project_id": "p1", "status": "completed", "created_at": datetime.now(timezone.utc)}
    )
    return db


def _count_project_reads(db) -> list[object]:
    reads: list[object] = []
    find = db.projects.find

    def counting_find(query=None, projection=None, **kwargs):
        reads.append(query)
        return find(query, projection, **kwargs)

    db.projects.find = counting_find
    return reads


@pytest.mark.asyncio
@pytest.mark.parametrize("consumer", sorted(_CONSUMERS))
@pytest.mark.parametrize(("scope", "scope_id"), [("user", None), ("team", "t1")])
async def test_head_resolution_reuses_the_projects_the_scope_read(db, consumer, scope, scope_id):
    db = await _seeded_db(db)
    user = User(
        id="u1", username="u1", email="u1@corp.com", permissions=[Permissions.PROJECT_READ, Permissions.TEAM_READ]
    )
    reads = _count_project_reads(db)

    resolved = await ScopeResolver(db, user).resolve(scope=scope, scope_id=scope_id)
    reads_by_the_scope = len(reads)
    await _CONSUMERS[consumer](db, resolved)

    assert resolved.project_ids == ["p1"]
    assert len(reads) == reads_by_the_scope
