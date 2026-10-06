"""A waiver written from a scan answers once that scan's findings carry it, so the page's refetch shows it waived."""

from datetime import datetime, timezone

import pytest
from fastapi import BackgroundTasks

from app.api.v1.endpoints.waivers import create_waiver
from app.core.init_db import create_indexes
from app.models.user import User
from app.models.waiver import Waiver
from app.schemas.waiver import WaiverCreate
from app.services.stats import run_waiver_recalc
from tests.helpers.permission_presets import PRESET_ADMIN

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]

_PROJECT = "p-named-scan"
_HEAD = "scan-head"
_FEATURE = "scan-feature"
_LICENSE_ID = "LIC-GPL-3.0"
_REASON = "approved by legal"
_GLOBAL_REASON = "vendored everywhere"


async def _seed(db) -> None:
    await create_indexes(db)
    now = datetime.now(timezone.utc)
    await db.projects.insert_one(
        {"_id": _PROJECT, "name": "p", "latest_scan_id": _HEAD, "default_branch": "main", "deleted_branches": []}
    )
    for scan_id, branch in ((_HEAD, "main"), (_FEATURE, "feature/x")):
        await db.scans.insert_one(
            {"_id": scan_id, "project_id": _PROJECT, "branch": branch, "status": "completed", "created_at": now}
        )
        await db.findings.insert_one(
            {
                "_id": f"{scan_id}:gpl",
                "scan_id": scan_id,
                "project_id": _PROJECT,
                "type": "license",
                "finding_id": _LICENSE_ID,
                "component": "lib",
                "severity": "HIGH",
            }
        )
    # A finding an earlier global waiver already covers on the scan the new waiver is written from.
    global_waiver = Waiver(project_id=None, package_name="vendored", reason=_GLOBAL_REASON, created_by="admin")
    await db.waivers.insert_one(global_waiver.model_dump(by_alias=True))
    await db.findings.insert_one(
        {
            "_id": f"{_FEATURE}:vendored",
            "scan_id": _FEATURE,
            "project_id": _PROJECT,
            "type": "quality",
            "finding_id": "QUALITY:vendored:1.0",
            "component": "vendored",
            "severity": "LOW",
            "waived": True,
            "waiver_reason": _GLOBAL_REASON,
        }
    )


async def test_the_named_scan_is_restamped_before_the_response(db):
    await _seed(db)
    background = BackgroundTasks()

    await create_waiver(
        waiver_in=WaiverCreate(
            project_id=_PROJECT,
            scan_id=_FEATURE,
            finding_id=_LICENSE_ID,
            finding_type="license",
            package_name="lib",
            reason=_REASON,
        ),
        background_tasks=background,
        db=db,
        current_user=User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN)),
    )

    finding = await db.findings.find_one({"_id": f"{_FEATURE}:gpl"})
    assert finding.get("waived") is True
    assert finding.get("waiver_reason") == _REASON
    scan = await db.scans.find_one({"_id": _FEATURE})
    assert scan["stats"]["high"] == 0
    assert scan["stats"]["low"] == 0
    assert scan["ignored_count"] == 2
    assert (await db.findings.find_one({"_id": f"{_FEATURE}:vendored"})).get("waived") is True
    # The other scans the waiver reaches are still left to the queued recalculation.
    assert (await db.findings.find_one({"_id": f"{_HEAD}:gpl"})).get("waived") is not True
    assert [task.func for task in background.tasks] == [run_waiver_recalc]
