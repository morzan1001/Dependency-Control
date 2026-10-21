"""A waiver holds now, not for the build it was analysed under, so marking an old build released restamps it."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from app.api.v1.endpoints.releases import mark_release
from app.core.init_db import create_indexes
from app.models.waiver import Waiver
from app.schemas.release import ReleaseMarkRequest
from app.services import stats
from app.services.waivers.apply import waiver_fingerprint

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]

_PROJECT = "p-rollback"
_COMMIT = "a" * 40
_T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
_REVOKED = Waiver(project_id=_PROJECT, package_name="lib", reason="revoked since", created_by="admin")


async def _seed(db, *, stamped_with: list[Waiver]) -> None:
    await create_indexes(db)
    await db.projects.insert_one({"_id": _PROJECT, "name": "p", "default_branch": "main", "deleted_branches": []})
    await db.scans.insert_many(
        [
            {
                "_id": "build",
                "project_id": _PROJECT,
                "branch": "main",
                "commit_hash": _COMMIT,
                "status": "completed",
                "created_at": _T0,
                "latest_rescan_id": "rescan",
            },
            # The rescan holds the build's analysis, so it is the scan the release reports and the one to restamp.
            {
                "_id": "rescan",
                "project_id": _PROJECT,
                "branch": "main",
                "commit_hash": _COMMIT,
                "status": "completed",
                "created_at": _T0 + timedelta(days=1),
                "is_rescan": True,
                "original_scan_id": "build",
                "waiver_fingerprint": waiver_fingerprint(stamped_with),
            },
        ]
    )
    await db.findings.insert_one(
        {
            "_id": "rescan:lib",
            "scan_id": "rescan",
            "project_id": _PROJECT,
            "type": "quality",
            "finding_id": "QUALITY:lib:1.0",
            "component": "lib",
            "severity": "HIGH",
            "waived": True,
            "waiver_reason": _REVOKED.reason,
        }
    )


async def test_a_build_stamped_under_a_since_revoked_waiver_loses_it_when_marked_released(db):
    await _seed(db, stamped_with=[_REVOKED])

    await mark_release(_PROJECT, ReleaseMarkRequest(commit_hash=_COMMIT), db)

    assert (await db.findings.find_one({"_id": "rescan:lib"})).get("waived") is False
    rescan = await db.scans.find_one({"_id": "rescan"})
    assert rescan["waiver_fingerprint"] == waiver_fingerprint([])
    assert rescan["stats"]["high"] == 1


async def test_a_build_stamped_under_the_active_waivers_is_left_alone(db):
    await _seed(db, stamped_with=[])

    with patch.object(stats, "restamp_waivers", wraps=stats.restamp_waivers) as restamp:
        await mark_release(_PROJECT, ReleaseMarkRequest(commit_hash=_COMMIT), db)

    restamp.assert_not_called()
    assert (await db.findings.find_one({"_id": "rescan:lib"})).get("waived") is True
