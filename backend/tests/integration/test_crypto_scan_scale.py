"""Crypto readers over scans holding more than 50,000 assets."""

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.core.init_db import create_indexes
from app.models.project import Project, Scan
from app.services.analytics.crypto_delta import compare_crypto
from app.services.analytics.scopes import ResolvedScope
from app.services.pqc_migration.generator import PQCMigrationPlanGenerator
from tests.helpers.cbom import OLD_ASSET_CAP, cbom_of, filler_components, fixture_component, store_cbom

_PROJECT_ID = "crypto-scale-project"


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_pqc_plan_lists_a_vulnerable_asset_past_the_old_asset_cap(db):
    await create_indexes(db)
    await db.projects.insert_one(Project(id=_PROJECT_ID, name="crypto-scale").model_dump(by_alias=True))
    scan = Scan(project_id=_PROJECT_ID, branch="main", status=SCAN_STATUS_COMPLETED)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    rsa = fixture_component("legacy_crypto_mixed.json", "algo-rsa1024")
    await store_cbom(db, _PROJECT_ID, scan.id, cbom_of([*filler_components(range(OLD_ASSET_CAP)), rsa]))

    plan = await PQCMigrationPlanGenerator(db).generate(
        resolved=ResolvedScope(scope="project", scope_id=_PROJECT_ID, project_ids=[_PROJECT_ID])
    )

    assert [item.asset_bom_ref for item in plan.items] == ["algo-rsa1024"]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_crypto_delta_between_scans_past_the_old_asset_cap_counts_every_asset(db):
    await create_indexes(db)
    await store_cbom(db, _PROJECT_ID, "scan-from", cbom_of(filler_components(range(OLD_ASSET_CAP + 1))))
    await store_cbom(db, _PROJECT_ID, "scan-to", cbom_of(filler_components(range(1_000, OLD_ASSET_CAP + 1_001))))

    delta = await compare_crypto(db, project_id=_PROJECT_ID, from_scan="scan-from", to_scan="scan-to")

    assert (delta.totals.added, delta.totals.removed, delta.totals.unchanged) == (1_000, 1_000, OLD_ASSET_CAP - 999)
    assert len(delta.items) == 2_000
