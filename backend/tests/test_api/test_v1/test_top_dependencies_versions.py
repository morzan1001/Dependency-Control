"""The top-dependencies row lists a sample of versions beside a truthful total_occurrences, so it
has to carry the distinct-version total too: the table's "+N" badge is computed from it, and
$addToSet has no order to sample along."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.v1.endpoints.analytics.summary import _VERSION_SAMPLE, get_top_dependencies
from app.core.permissions import ALL_PERMISSIONS
from app.models.user import User
from tests.helpers.analytics_scope import projections

_SUMMARY = "app.api.v1.endpoints.analytics.summary"
_PROJECT_IDS = ["p1"]
_SCANS = ["s1"]
_LIMIT = 20
_DISTINCT_VERSIONS = 40


def _user():
    return User(id="u1", username="u1", email="u1@test.com", permissions=list(ALL_PERMISSIONS), is_active=True)


def _aggregated_row() -> dict:
    """What Mongo returns for one component: the whole distinct-version set plus its size."""
    versions = [f"1.{minor}.0" for minor in range(_DISTINCT_VERSIONS)]
    return {
        "_id": "leftpad",
        "name": "leftpad",
        "type": "npm",
        # $addToSet returns the set in no particular order; oldest-first is one such order.
        "versions": versions,
        "version_count": len(versions),
        "project_count": 1,
        "total_occurrences": _DISTINCT_VERSIONS,
    }


async def _top_dependencies() -> list:
    dep_repo = MagicMock()
    dep_repo.aggregate = AsyncMock(return_value=[_aggregated_row()])
    finding_repo = MagicMock()
    finding_repo.aggregate = AsyncMock(return_value=[])
    with (
        patch(f"{_SUMMARY}.get_user_projects", new=AsyncMock(return_value=projections(_PROJECT_IDS))),
        patch(f"{_SUMMARY}.get_latest_scan_ids", new=AsyncMock(return_value=_SCANS)),
        patch(f"{_SUMMARY}.DependencyRepository", return_value=dep_repo),
        patch(f"{_SUMMARY}.FindingRepository", return_value=finding_repo),
    ):
        return await get_top_dependencies(current_user=_user(), db=MagicMock(), limit=_LIMIT, type=None)


@pytest.mark.asyncio
async def test_the_row_reports_every_distinct_version_not_the_sample_size():
    rows = await _top_dependencies()

    assert len(rows[0].versions) == _VERSION_SAMPLE
    assert rows[0].version_count == _DISTINCT_VERSIONS


@pytest.mark.asyncio
async def test_the_sample_is_the_newest_versions_rather_than_an_arbitrary_ten():
    rows = await _top_dependencies()

    assert rows[0].versions[0] == f"1.{_DISTINCT_VERSIONS - 1}.0"
    assert rows[0].versions == sorted(rows[0].versions, key=lambda v: int(v.split(".")[1]), reverse=True)


async def _vulnerability_counts(findings: list[dict], dependency_name: str) -> int:
    from tests.mocks.fake_mongo import FakeDatabase

    db = FakeDatabase()
    await db.dependencies.insert_one(
        {"_id": "d1", "scan_id": "s1", "project_id": "p1", "name": dependency_name, "version": "1.0", "type": "maven"}
    )
    await db.findings.insert_many(findings)
    with (
        patch(f"{_SUMMARY}.get_user_projects", new=AsyncMock(return_value=projections(_PROJECT_IDS))),
        patch(f"{_SUMMARY}.get_latest_scan_ids", new=AsyncMock(return_value=_SCANS)),
    ):
        [row] = await get_top_dependencies(current_user=_user(), db=db, limit=_LIMIT, type=None)
    return row.vulnerability_count


def _vulnerability(finding_id: str, component: str) -> dict:
    return {
        "_id": finding_id,
        "scan_id": "s1",
        "project_id": "p1",
        "type": "vulnerability",
        "component": component,
        "details": {"vulnerabilities": [{"id": f"CVE-2026-{finding_id}", "severity": "HIGH"}]},
    }


@pytest.mark.asyncio
async def test_a_bare_dependency_name_counts_its_group_qualified_findings():
    findings = [_vulnerability(f"f{n}", "com.fasterxml.jackson.core:jackson-databind") for n in range(4)]

    assert await _vulnerability_counts(findings, "jackson-databind") == 4


@pytest.mark.asyncio
async def test_a_bare_name_shared_by_two_qualified_packages_counts_neither():
    findings = [_vulnerability("f1", "@angular/core"), _vulnerability("f2", "@angular-devkit/core")]

    assert await _vulnerability_counts(findings, "core") == 0


@pytest.mark.asyncio
async def test_only_the_listed_packages_advisories_are_read():
    from app.repositories.findings import FindingRepository

    findings = [
        _vulnerability("f1", "com.fasterxml.jackson.core:jackson-databind"),
        _vulnerability("f2", "unlisted-lib"),
    ]
    grouped: list = []
    original = FindingRepository.aggregate

    async def recording(self, pipeline, **kwargs):
        rows = await original(self, pipeline, **kwargs)
        grouped.extend(row["_id"]["component"] for row in rows)
        return rows

    with patch.object(FindingRepository, "aggregate", recording):
        assert await _vulnerability_counts(findings, "jackson-databind") == 1

    assert grouped == ["com.fasterxml.jackson.core:jackson-databind"]


def _dependency(doc_id: str, project_id: str, name: str, version: str, purl: str) -> dict:
    return {
        "_id": doc_id,
        "scan_id": f"s-{project_id}",
        "project_id": project_id,
        "name": name,
        "version": version,
        "purl": purl,
        "type": purl.split(":")[1].split("/")[0],
    }


_SPELLINGS_OF_ONE_PACKAGE_AND_TWO_CORES = [
    _dependency("d1", "p1", "PyYAML", "6.0.1", "pkg:pypi/PyYAML@6.0.1"),
    _dependency("d2", "p2", "pyyaml", "5.4", "pkg:pypi/pyyaml@5.4"),
    _dependency("d3", "p1", "core", "16.2.0", "pkg:npm/%40angular/core@16.2.0"),
    _dependency("d4", "p2", "core", "7.23.0", "pkg:npm/%40babel/core@7.23.0"),
]


@pytest.mark.asyncio
async def test_rows_group_by_package_identity_and_keep_a_stored_spelling():
    from app.repositories.dependencies import DependencyRepository
    from tests.mocks.fake_mongo import FakeDatabase

    db = FakeDatabase()
    await db.dependencies.insert_many(_SPELLINGS_OF_ONE_PACKAGE_AND_TWO_CORES)
    with (
        patch(f"{_SUMMARY}.get_user_projects", new=AsyncMock(return_value=projections(["p1", "p2"]))),
        patch(f"{_SUMMARY}.get_latest_scan_ids", new=AsyncMock(return_value=["s-p1", "s-p2"])),
    ):
        rows = await get_top_dependencies(current_user=_user(), db=db, limit=_LIMIT, type=None)

    by_name = {(row.name.lower(), row.version_count, row.project_count) for row in rows}
    assert by_name == {("pyyaml", 2, 2), ("core", 1, 1)} and len(rows) == 3
    assert await DependencyRepository(db).get_unique_packages(["s-p1", "s-p2"]) == len(rows)
