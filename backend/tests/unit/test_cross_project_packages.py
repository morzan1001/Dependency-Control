"""Version inconsistency counts every dependency row of the compared scans, so it is grouped in Mongo."""

import asyncio
from datetime import datetime, timezone

import pytest

from app.api.v1.helpers.analytics import cross_project_package_pipeline
from tests.mocks.fake_mongo import FakeCollection

_MIN_PROJECTS = 2
_ROWS_PER_SCAN = 150
_LATE_PACKAGE = "late-package"


def _dep(_id, scan_id, project_id, name, version, purl=None, group=None, component_type=None):
    return {
        "_id": _id,
        "scan_id": scan_id,
        "project_id": project_id,
        "name": name,
        "version": version,
        "purl": purl,
        "group": group,
        "type": component_type,
    }


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


def test_artifacts_sharing_a_bare_name_across_groups_are_different_packages():
    col = FakeCollection()
    docs = [
        _dep("d1", "s1", "p1", "annotations", "24.0.1", "pkg:maven/org.jetbrains/annotations@24.0.1", "org.jetbrains"),
        _dep(
            "d2",
            "s2",
            "p2",
            "annotations",
            "2.20.0",
            "pkg:maven/software.amazon.awssdk/annotations@2.20.0",
            "software.amazon.awssdk",
        ),
    ]
    col._docs = {d["_id"]: d for d in docs}

    assert _run(col, ["s1", "s2"]) == []


def test_one_purl_counts_as_one_package_whether_or_not_the_sbom_filled_group():
    col = FakeCollection()
    docs = [
        _dep("d1", "s1", "p1", "annotations", "23.0.0", "pkg:maven/org.jetbrains/annotations@23.0.0", "org.jetbrains"),
        _dep("d2", "s2", "p2", "annotations", "24.0.1", "pkg:maven/org.jetbrains/annotations@24.0.1"),
    ]
    col._docs = {d["_id"]: d for d in docs}

    [row] = _run(col, ["s1", "s2"])

    assert row["name"] == "org.jetbrains/annotations"
    assert sorted(row["versions"]) == ["23.0.0", "24.0.1"]


def test_npm_scopes_split_packages_and_both_scope_spellings_join():
    col = FakeCollection()
    docs = [
        _dep("d1", "s1", "p1", "core", "16.2.0", "pkg:npm/%40angular/core@16.2.0", "@angular"),
        _dep("d2", "s2", "p2", "@angular/core", "17.0.0", "pkg:npm/@angular/core@17.0.0"),
        _dep("d3", "s1", "p1", "core", "7.23.0", "pkg:npm/%40babel/core@7.23.0", "@babel"),
        _dep("d4", "s2", "p2", "@babel/core", "7.23.0", "pkg:npm/@babel/core@7.23.0"),
    ]
    col._docs = {d["_id"]: d for d in docs}

    assert [(r["name"], r["version_count"]) for r in _run(col, ["s1", "s2"])] == [("@angular/core", 2)]


_ACCESSIBLE_PROJECTS = 25
_COMPARISON_LIMIT = 20


@pytest.mark.asyncio
async def test_the_payload_says_how_many_projects_the_comparison_reached(db):
    """total_projects counts what the user can see, so a CVE count out of it claims a comparison never run."""
    from app.api.v1.helpers.analytics import gather_cross_project_data
    from app.services.analytics.scopes import read_scope_projects

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

    data = await gather_cross_project_data(await read_scope_projects(db, {}), project_ids[0], db)

    assert data is not None
    assert data["total_projects"] == _ACCESSIBLE_PROJECTS
    assert len(data["projects"]) == _COMPARISON_LIMIT


def test_purl_less_components_of_different_types_sharing_a_name_are_different_packages():
    col = FakeCollection()
    docs = [
        _dep("d1", "s1", "p1", "busybox", "1.36.1", component_type="application"),
        _dep("d2", "s2", "p2", "busybox", "1.35.0", component_type="operating-system"),
    ]
    col._docs = {d["_id"]: d for d in docs}

    assert _run(col, ["s1", "s2"]) == []


def test_packages_on_as_many_versions_are_listed_by_name_whatever_its_case():
    col = FakeCollection()
    docs = []
    for path in ("github.com/Masterminds/semver", "github.com/google/uuid", "github.com/Azure/go-autorest"):
        for index, (scan, project) in enumerate([("s1", "p1"), ("s2", "p2")]):
            docs.append(_dep(f"{path}-{scan}", scan, project, path, f"1.{index}.0", f"pkg:golang/{path}@1.{index}.0"))
    col._docs = {d["_id"]: d for d in docs}

    assert [r["name"] for r in _run(col, ["s1", "s2"])] == [
        "github.com/Azure/go-autorest",
        "github.com/google/uuid",
        "github.com/Masterminds/semver",
    ]


def test_projects_holding_the_same_nested_copies_are_not_reported():
    col = FakeCollection()
    docs = [
        _dep(f"d-{scan}-{version}", scan, project, "requests", version)
        for scan, project in (("s1", "p1"), ("s2", "p2"))
        for version in ("2.28.0", "2.31.0")
    ]
    col._docs = {d["_id"]: d for d in docs}

    assert _run(col, ["s1", "s2"]) == []


def test_a_project_holding_a_copy_the_other_lacks_reports_every_version():
    col = FakeCollection()
    docs = [
        _dep("d1", "s1", "p1", "requests", "2.28.0"),
        _dep("d2", "s1", "p1", "requests", "2.31.0"),
        _dep("d3", "s2", "p2", "requests", "2.31.0"),
    ]
    col._docs = {d["_id"]: d for d in docs}

    [row] = _run(col, ["s1", "s2"])

    assert (sorted(row["versions"]), row["version_count"], row["project_count"]) == (["2.28.0", "2.31.0"], 2, 2)


def test_packages_sharing_a_name_across_ecosystems_are_listed_apart_with_their_type():
    col = FakeCollection()
    docs = [
        _dep(f"d-{ecosystem}-{scan}", scan, project, "foo", version, f"pkg:{ecosystem}/foo@{version}")
        for ecosystem in ("pypi", "npm")
        for scan, project, version in (("s1", "p1", "1.0.0"), ("s2", "p2", "2.0.0"))
    ]
    col._docs = {d["_id"]: d for d in docs}

    assert sorted((r["name"], r["type"]) for r in _run(col, ["s1", "s2"])) == [("foo", "npm"), ("foo", "pypi")]
