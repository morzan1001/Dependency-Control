"""Version inconsistency across projects is a count over every dependency row of the compared
scans, so it is grouped in Mongo. Pushing each scan's package list to the caller and slicing it
at 100 hid any package past the hundredth of a scan, and there is no order to slice along."""

import asyncio
from datetime import datetime, timezone

import pytest

from app.api.v1.helpers.analytics import cross_project_package_pipeline
from tests.mocks.fake_mongo import FakeCollection

_MIN_PROJECTS = 2
_ROWS_PER_SCAN = 150
_LATE_PACKAGE = "late-package"


def _dep(_id, scan_id, project_id, name, version):
    return {"_id": _id, "scan_id": scan_id, "project_id": project_id, "name": name, "version": version}


def _run(col: FakeCollection, scan_ids: list[str]):
    return asyncio.run(col.aggregate(cross_project_package_pipeline(scan_ids, _MIN_PROJECTS)).to_list())


def _two_scans_with_a_late_package() -> FakeCollection:
    col = FakeCollection()
    docs = []
    for index, (scan, project) in enumerate([("s1", "p1"), ("s2", "p2")]):
        for slot in range(_ROWS_PER_SCAN):
            name = _LATE_PACKAGE if slot == _ROWS_PER_SCAN - 1 else f"filler-{slot}"
            docs.append(_dep(f"d-{scan}-{slot}", scan, project, name, f"{index + 1}.0.0"))
    col._docs = {d["_id"]: d for d in docs}
    return col


def test_a_package_past_the_hundredth_row_of_a_scan_is_still_counted():
    rows = {r["name"]: r for r in _run(_two_scans_with_a_late_package(), ["s1", "s2"])}

    assert _LATE_PACKAGE in rows
    assert rows[_LATE_PACKAGE]["version_count"] == _MIN_PROJECTS
    assert rows[_LATE_PACKAGE]["project_count"] == _MIN_PROJECTS


def test_a_package_pinned_to_one_version_everywhere_is_not_reported():
    col = FakeCollection()
    docs = [
        _dep("d1", "s1", "p1", "requests", "2.31.0"),
        _dep("d2", "s2", "p2", "requests", "2.31.0"),
    ]
    col._docs = {d["_id"]: d for d in docs}

    assert _run(col, ["s1", "s2"]) == []


def test_a_package_in_a_single_project_is_not_reported():
    col = FakeCollection()
    docs = [
        _dep("d1", "s1", "p1", "requests", "2.28.0"),
        _dep("d2", "s1", "p1", "requests", "2.31.0"),
    ]
    col._docs = {d["_id"]: d for d in docs}

    assert _run(col, ["s1", "s2"]) == []


def test_names_are_grouped_case_insensitively_as_the_recommendation_reports_them():
    col = FakeCollection()
    docs = [
        _dep("d1", "s1", "p1", "Requests", "2.28.0"),
        _dep("d2", "s2", "p2", "requests", "2.31.0"),
    ]
    col._docs = {d["_id"]: d for d in docs}

    rows = _run(col, ["s1", "s2"])

    assert [r["name"] for r in rows] == ["requests"]
    assert rows[0]["project_count"] == _MIN_PROJECTS


_ACCESSIBLE_PROJECTS = 25
_COMPARISON_LIMIT = 20


@pytest.mark.asyncio
async def test_the_payload_says_how_many_projects_the_comparison_reached(db):
    """total_projects counts what the user can see; a CVE count reported out of it claims a
    comparison that never ran."""
    from app.api.v1.helpers.analytics import gather_cross_project_data

    project_ids = [f"p{index:02d}" for index in range(_ACCESSIBLE_PROJECTS)]
    for project_id in project_ids:
        await db.projects.insert_one(
            {"_id": project_id, "name": project_id, "latest_scan_id": f"s-{project_id}", "default_branch": "main"}
        )
        await db.scans.insert_one(
            {
                "_id": f"s-{project_id}",
                "project_id": project_id,
                "branch": "main",
                "status": "completed",
                "created_at": datetime(2026, 9, 5, tzinfo=timezone.utc),
                "stats": {"critical": 0, "high": 0},
            }
        )

    data = await gather_cross_project_data(project_ids, project_ids[0], db)

    assert data is not None
    assert data["total_projects"] == _ACCESSIBLE_PROJECTS
    assert data["projects_compared"] == _COMPARISON_LIMIT
    assert len(data["projects"]) == _COMPARISON_LIMIT
