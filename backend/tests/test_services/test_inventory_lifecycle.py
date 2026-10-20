from datetime import datetime, timezone

import pytest

from app.models.project import Scan
from app.services.aggregation import ResultAggregator
from app.services.analyzers.outdated import OutdatedAnalyzer
from app.services.inventory.components import get_components_page
from tests.mocks.fake_mongo import FakeDatabase

_SCAN = Scan(id="s1", project_id="p1", branch="main", created_at=datetime(2026, 9, 1, tzinfo=timezone.utc))


@pytest.mark.asyncio
async def test_a_package_ahead_of_the_registry_default_is_not_outdated():
    outdated: list = []
    ahead: list = []
    analyzer = OutdatedAnalyzer()
    for name, version in (("urllib3", "1.26.0"), ("requests", "3.0.0")):
        component = {"name": name, "version": version, "purl": f"pkg:pypi/{name}@{version}"}
        analyzer._classify_version(component, {"default": "2.32.0", "stable": "2.32.0"}, outdated, ahead)
    agg = ResultAggregator()
    agg.aggregate("outdated_packages", {"outdated_dependencies": outdated, "ahead_of_default": ahead})

    db = FakeDatabase()
    for finding in agg.get_findings():
        await db.findings.insert_one({**finding.model_dump(), "scan_id": "s1"})
    for name, version in (("urllib3", "1.26.0"), ("requests", "3.0.0")):
        await db.dependencies.insert_one(
            {"scan_id": "s1", "name": name, "version": version, "purl": f"pkg:pypi/{name}@{version}"}
        )

    items, _ = await get_components_page(db, _SCAN, page=1, page_size=10, search=None, sort_by="name", direction=1)

    by_name = {item.name: item for item in items}
    assert (by_name["urllib3"].outdated, by_name["urllib3"].latest_version) == (True, "2.32.0")
    assert (by_name["requests"].outdated, by_name["requests"].latest_version) == (False, None)


@pytest.mark.asyncio
async def test_a_page_reads_the_lifecycle_findings_of_its_own_components_only(monkeypatch):
    db = FakeDatabase()
    for name in ("alpha", "beta", "gamma"):
        await db.dependencies.insert_one(
            {"scan_id": "s1", "name": name, "version": "1.0", "purl": f"pkg:npm/{name}@1.0"}
        )
        await db.findings.insert_one({"scan_id": "s1", "type": "eol", "component": name, "version": "1.0"})
    queries: list[dict] = []
    find = db.findings.find
    monkeypatch.setattr(
        db.findings, "find", lambda query, *args, **kwargs: queries.append(query) or find(query, *args, **kwargs)
    )

    items, _ = await get_components_page(db, _SCAN, page=2, page_size=1, search=None, sort_by="name", direction=1)

    assert [(item.name, item.eol) for item in items] == [("beta", True)]
    assert [query.get("component") for query in queries] == [{"$in": ["beta"]}]
