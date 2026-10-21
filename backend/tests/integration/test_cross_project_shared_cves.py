from datetime import datetime, timezone

import pytest

from app.api.v1.helpers.analytics import gather_cross_project_data
from app.services.analytics.scopes import read_scope_projects

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_LODASH_CVE = "CVE-2021-23337"
_LODASH_GHSA = "GHSA-35jh-r3h4-6jhm"


def _finding(_id: str, project_id: str, advisories: list[dict], waived: bool = False, kind="vulnerability") -> dict:
    return {
        "_id": _id,
        "scan_id": f"s-{project_id}",
        "project_id": project_id,
        "type": kind,
        "component": "lodash",
        "waived": waived,
        "details": {"vulnerabilities": advisories},
    }


async def _projects(db, *project_ids: str) -> None:
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


async def _cves_by_project(db) -> dict[str, list[str]]:
    data = await gather_cross_project_data(await read_scope_projects(db, {}), "current", db)
    assert data is not None
    return {p["project_id"]: p["cves"] for p in data["projects"]}


async def test_a_ghsa_and_its_cve_are_one_shared_vulnerability(db):
    await _projects(db, "current", "p1", "p2")
    await db.findings.insert_many(
        [
            _finding("f1", "p1", [{"id": _LODASH_CVE}]),
            _finding("f2", "p1", [{"id": _LODASH_GHSA, "resolved_cve": _LODASH_CVE}]),
            _finding("f3", "p2", [{"id": _LODASH_GHSA, "aliases": [_LODASH_CVE]}]),
        ]
    )

    assert await _cves_by_project(db) == {"current": [], "p1": [_LODASH_CVE], "p2": [_LODASH_CVE]}


async def test_waived_advisories_and_other_findings_are_not_shared(db):
    await _projects(db, "current", "p1", "p2")
    await db.findings.insert_many(
        [
            _finding("f1", "p1", [{"id": "CVE-2026-0001"}], waived=True),
            _finding("f2", "p1", [{"id": "CVE-2026-0002", "waived": True}, {"id": _LODASH_CVE}]),
            _finding("f3", "p2", [{"id": "CVE-2026-0003"}], kind="license"),
            _finding("f4", "p2", []),
        ]
    )

    assert await _cves_by_project(db) == {"current": [], "p1": [_LODASH_CVE], "p2": []}


async def test_the_viewed_project_is_compared_even_when_20_scanned_projects_are_read_first(db):
    await _projects(db, *[f"p{i:02d}" for i in range(20)], "current")

    data = await gather_cross_project_data(await read_scope_projects(db, {}), "current", db)

    assert data is not None
    assert [p["project_id"] for p in data["projects"]] == ["current"] + [f"p{i:02d}" for i in range(19)]


async def test_only_packages_the_viewed_project_holds_are_compared(db):
    await _projects(db, "current", "p1", "p2")
    await db.dependencies.insert_many(
        [
            {"scan_id": "s-current", "project_id": "current", "name": "flask", "version": "2.0.0"},
            {"scan_id": "s-p1", "project_id": "p1", "name": "flask", "version": "3.0.0"},
            {"scan_id": "s-p1", "project_id": "p1", "name": "requests", "version": "2.28.0"},
            {"scan_id": "s-p2", "project_id": "p2", "name": "requests", "version": "2.31.0"},
        ]
    )

    data = await gather_cross_project_data(await read_scope_projects(db, {}), "current", db)

    assert data is not None
    assert [(p["name"], p["project_count"]) for p in data["shared_packages"]] == [("flask", 2)]


async def test_a_shared_package_names_the_versions_a_compared_project_holds_a_vulnerability_on(db):
    """A finding without a version cannot tell the versions apart, so it marks every one of them."""
    await _projects(db, "current", "p1", "p2")
    await db.dependencies.insert_many(
        [
            {"scan_id": "s-current", "project_id": "current", "name": "lodash", "version": "4.17.20"},
            {"scan_id": "s-p1", "project_id": "p1", "name": "lodash", "version": "4.17.15"},
            {"scan_id": "s-p2", "project_id": "p2", "name": "lodash", "version": "4.17.21"},
            {"scan_id": "s-current", "project_id": "current", "name": "flask", "version": "2.0.0"},
            {"scan_id": "s-p1", "project_id": "p1", "name": "flask", "version": "3.0.0"},
            *(
                {
                    "scan_id": f"s-{project_id}",
                    "project_id": project_id,
                    "name": package.split("/")[1],
                    "version": version,
                    "purl": f"pkg:maven/{package}@{version}",
                }
                for package in ("org.apache.logging.log4j/log4j-core", "com.fasterxml.jackson.core/jackson-databind")
                for project_id, version in (("current", "2.14.1"), ("p1", "2.17.1"))
            ),
        ]
    )
    await db.findings.insert_many(
        [
            {**_finding("f1", "p2", [{"id": _LODASH_CVE}]), "version": "v4.17.21"},
            {**_finding("f2", "p1", [{"id": "CVE-2026-0001"}], waived=True), "version": "4.17.15"},
            {**_finding("f3", "current", [{"id": "CVE-2026-0002"}]), "component": "flask"},
            # Trivy names a Maven package group:artifact, grype only its artifact.
            {
                **_finding("f4", "current", [{"id": "CVE-2021-44228"}]),
                "component": "org.apache.logging.log4j:log4j-core",
                "version": "2.14.1",
            },
            {**_finding("f5", "p1", [{"id": "CVE-2020-36518"}]), "component": "jackson-databind", "version": "2.17.1"},
        ]
    )

    data = await gather_cross_project_data(await read_scope_projects(db, {}), "current", db)

    assert data is not None
    assert {p["name"]: sorted(p["vulnerable_versions"]) for p in data["shared_packages"]} == {
        "com.fasterxml.jackson.core/jackson-databind": ["2.17.1"],
        "flask": ["2.0.0", "3.0.0"],
        "lodash": ["4.17.21"],
        "org.apache.logging.log4j/log4j-core": ["2.14.1"],
    }


async def test_the_most_recently_scanned_projects_fill_the_comparison(db):
    dormant_first = [f"p{i:02d}" for i in range(25)]
    await _projects(db, *dormant_first, "current")
    for day, project_id in enumerate(dormant_first, start=1):
        await db.projects.update_one(
            {"_id": project_id}, {"$set": {"last_scan_at": datetime(2026, 9, day, tzinfo=timezone.utc)}}
        )

    data = await gather_cross_project_data(await read_scope_projects(db, {}), "current", db)

    assert data is not None
    assert [p["project_id"] for p in data["projects"]] == ["current", *reversed(dormant_first[-19:])]
