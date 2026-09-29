"""Every pass re-reads the targets of every rescan-enabled project, so each read has to stay one index
seek however many rescans the scheduler itself has piled up, and return no more than a rescan needs."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.housekeeping import _rescan_targets
from app.core.init_db import create_indexes
from app.models.project import Project
from app.models.release import Release
from app.services.rescan import RESCAN_SOURCE_PROJECTION

_NOW = datetime.now(timezone.utc)
_PILED_UP_RESCANS = 200
_ENVIRONMENTS = ("dev", "staging", "production")
_PROJECT = Project(id="p1", name="p1", default_branch="main")


def _scan(scan_id: str, age: timedelta, **fields) -> dict:
    return {
        "_id": scan_id,
        "project_id": "p1",
        "branch": "main",
        "commit_hash": f"sha-{scan_id}",
        "status": "completed",
        "created_at": _NOW - age,
        "sbom_refs": [{"gridfs_id": f"gridfs-{scan_id}"}],
        "findings_summary": [{"id": "CVE-2026-0001", "severity": "HIGH"}],
        **fields,
    }


async def _scan_reads(db, call) -> tuple[list[dict], list[dict]]:
    await db.command("profile", 2)
    result = await call
    await db.command("profile", 0)
    reads = await db["system.profile"].find({"ns": f"{db.name}.scans", "op": "query"}).to_list(None)
    return result, reads


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_tip_lookup_skips_the_rescans_the_scheduler_piled_up(db):
    await create_indexes(db)
    await db.scans.insert_one(_scan("build", timedelta(days=_PILED_UP_RESCANS + 1)))
    await db.scans.insert_many(
        [
            _scan(f"rescan-{n}", timedelta(days=n), is_rescan=True, original_scan_id="build")
            for n in range(_PILED_UP_RESCANS)
        ]
    )

    targets, reads = await _scan_reads(db, _rescan_targets(_PROJECT, db))

    assert [target["_id"] for target in targets] == ["build"]
    assert [read["docsExamined"] for read in reads] == [1]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_releases_are_read_in_one_query_and_every_target_only_as_far_as_a_rescan_needs(db):
    await create_indexes(db)
    await db.scans.insert_one(_scan("build", timedelta(days=1)))
    for n, environment in enumerate(_ENVIRONMENTS):
        await db.scans.insert_one(_scan(environment, timedelta(days=n + 2)))
        release = Release(project_id="p1", environment=environment, scan_id=environment, released_at=_NOW)
        await db.releases.insert_one(release.model_dump(by_alias=True))

    targets, reads = await _scan_reads(db, _rescan_targets(_PROJECT, db))

    assert sorted(target["_id"] for target in targets) == sorted(["build", *_ENVIRONMENTS])
    assert len(reads) == 2
    assert all(set(target) <= set(RESCAN_SOURCE_PROJECTION) for target in targets)
