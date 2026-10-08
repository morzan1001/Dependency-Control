"""get_risk_trends sums each project's last usable head build per period, newest first so truncation cuts the oldest."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_FAILED, SCAN_STATUS_PENDING
from app.models.project import Project, Scan
from app.models.stats import Stats
from app.models.user import User
from app.repositories.scans import ScanRepository
from app.services.chat.tools import ChatToolRegistry
from app.services.rescan import build_rescan
from tests.helpers.databases import DATABASES
from tests.helpers.permission_presets import PRESET_ADMIN

pytestmark = [pytest.mark.asyncio, pytest.mark.parametrize("database", DATABASES)]

_CHECKOUT = "p-checkout"
_BILLING = "p-billing"
_MAIN = "main"
_TODAY = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def _at(days_ago: int, hour: int) -> datetime:
    return _TODAY - timedelta(days=days_ago, hours=-hour)


def _period(days_ago: int) -> str:
    return (_TODAY - timedelta(days=days_ago)).date().isoformat()


async def _project(db, project_id: str, head: str) -> None:
    project = Project(id=project_id, name=project_id, default_branch=_MAIN, latest_scan_id=head)
    await db.projects.insert_one(project.model_dump(by_alias=True))


async def _build(db, scan_id: str, project_id: str, created_at: datetime, *, branch=_MAIN, status=None, **counts):
    stats = Stats(**counts) if counts else None
    scan = Scan(
        id=scan_id,
        project_id=project_id,
        branch=branch,
        status=status or SCAN_STATUS_COMPLETED,
        created_at=created_at,
        stats=stats,
    )
    await ScanRepository(db).create(scan)


async def _trend(db, **args) -> dict:
    admin = User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))
    return await ChatToolRegistry().execute_tool("get_risk_trends", args, admin, db)


async def _two_projects(db) -> None:
    await _project(db, _CHECKOUT, "checkout-head")
    await _build(db, "checkout-morning", _CHECKOUT, _at(3, 9), critical=4, high=1, risk_score=60.0)
    await _build(db, "checkout-afternoon", _CHECKOUT, _at(3, 15), critical=2, high=1, risk_score=40.0)
    await _build(db, "checkout-feature", _CHECKOUT, _at(3, 18), branch="feature/x", critical=9, risk_score=90.0)
    await _build(db, "checkout-failed", _CHECKOUT, _at(2, 12), status=SCAN_STATUS_FAILED)
    await _build(db, "checkout-head", _CHECKOUT, _at(1, 12), critical=1, risk_score=10.0)
    await _project(db, _BILLING, "billing-head")
    await _build(db, "billing-head", _BILLING, _at(3, 12), critical=3, medium=2, risk_score=20.0)
    await _build(db, "billing-queued", _BILLING, _at(1, 12), status=SCAN_STATUS_PENDING)


async def test_each_period_sums_the_last_head_branch_build_of_every_project(db, database):
    await _two_projects(db)

    result = await _trend(db, days=7)

    assert result["bucket"] == "day"
    assert result["trend"] == [
        {"period": _period(1), "critical": 1, "high": 0, "medium": 0, "low": 0, "risk_score": 10.0, "projects": 1},
        {"period": _period(3), "critical": 5, "high": 1, "medium": 2, "low": 0, "risk_score": 30.0, "projects": 2},
    ]


async def _rescan(db, source_id: str, created_at: datetime, **counts) -> None:
    source = await db.scans.find_one({"_id": source_id})
    rescan = build_rescan(source).model_copy(
        update={"status": SCAN_STATUS_COMPLETED, "created_at": created_at, "stats": Stats(**counts)}
    )
    await ScanRepository(db).create(rescan)
    await ScanRepository(db).report_rescan_run(
        source_id, source.get("sbom_generation"), {"latest_rescan_id": rescan.id}
    )


async def test_a_rescan_of_an_older_release_does_not_stand_in_for_the_head_build(db, database):
    await _project(db, _CHECKOUT, "checkout-tip")
    await _build(db, "checkout-release", _CHECKOUT, _at(5, 12), critical=50, risk_score=90.0)
    await _build(db, "checkout-tip", _CHECKOUT, _at(0, 0), critical=1, risk_score=10.0)
    await _rescan(db, "checkout-tip", _at(0, 0) + timedelta(minutes=1), critical=2, risk_score=15.0)
    await _rescan(db, "checkout-release", _at(0, 0) + timedelta(minutes=2), critical=51, risk_score=95.0)

    result = await _trend(db, days=7)

    assert [(p["period"], p["critical"]) for p in result["trend"]] == [(_period(0), 2), (_period(5), 50)]


async def test_a_project_id_charts_that_project_alone(db, database):
    await _two_projects(db)

    result = await _trend(db, project_id=_BILLING, days=7)

    assert [(p["period"], p["critical"]) for p in result["trend"]] == [(_period(3), 3)]


async def test_a_busy_window_still_reaches_today(db, database):
    await _project(db, _CHECKOUT, "checkout-head")
    await db.scans.insert_many(
        [
            Scan(
                id=f"ci-{n}",
                project_id=_CHECKOUT,
                branch=_MAIN,
                status=SCAN_STATUS_COMPLETED,
                created_at=_at(5, 0) + timedelta(minutes=n),
                stats=Stats(critical=7),
            ).model_dump(by_alias=True)
            for n in range(600)
        ]
    )
    await _build(db, "checkout-head", _CHECKOUT, _at(1, 12), critical=1)

    result = await _trend(db, days=7)

    assert [(p["period"], p["critical"]) for p in result["trend"]] == [(_period(1), 1), (_period(5), 7)]


async def test_a_quarter_is_charted_by_week(db, database):
    await _two_projects(db)

    result = await _trend(db, days=90)

    assert result["bucket"] == "week"
