from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from app.api.v1.helpers.analytics import severity_counts_from_details
from app.repositories.findings import FindingRepository

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_SCAN = "scan-advisory-reads"
_CRITICAL_GROUPS = 5
_LOW_GROUPS = 40


def _finding(component: str, advisories: list[dict], version: str | None = "1.0.0", **fields) -> dict:
    return {
        "_id": f"{component}-{version}-{fields.get('project_id', 'p')}",
        "id": f"{component}:{version}",
        "finding_id": f"{component}:{version}",
        "scan_id": _SCAN,
        "project_id": "p",
        "type": "vulnerability",
        "severity": "HIGH",
        "component": component,
        "version": version,
        "description": "",
        "scanners": ["trivy"],
        "waived": False,
        "scan_created_at": datetime.now(timezone.utc),
        "details": {"vulnerabilities": advisories},
        **fields,
    }


@pytest_asyncio.fixture
async def scanned(db, owner_auth_headers_proj, monkeypatch):
    from app.api.v1.endpoints.analytics import risk

    monkeypatch.setattr(risk.vulnerability_enrichment_service, "enrich_cves", AsyncMock(return_value=({}, [])))
    await db.scans.insert_one(
        {
            "_id": _SCAN,
            "project_id": "p",
            "branch": "main",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )
    await db.projects.update_one({"_id": "p"}, {"$set": {"latest_scan_id": _SCAN}})
    return owner_auth_headers_proj


@pytest_asyncio.fixture
async def ranked(db, scanned):
    critical = [
        _finding(f"crit-{i}", [{"id": f"CVE-2026-1{i:03d}{n}", "severity": "CRITICAL"} for n in range(3)])
        for i in range(_CRITICAL_GROUPS)
    ]
    low = [_finding(f"low-{i:02d}", [{"id": f"CVE-2026-2{i:03d}", "severity": "LOW"}]) for i in range(_LOW_GROUPS)]
    await db.findings.insert_many([*critical, *low])
    return scanned


@pytest.fixture
def advisory_groups(monkeypatch):
    """The components of every group a findings read hands over with its advisory lists."""
    read: list[str] = []
    original = FindingRepository.aggregate

    async def recording(self, pipeline, **kwargs):
        rows = await original(self, pipeline, **kwargs)
        read.extend(row["_id"]["component"] for row in rows if "details_list" in row)
        return rows

    monkeypatch.setattr(FindingRepository, "aggregate", recording)
    return read


async def test_impact_reads_advisories_only_for_the_groups_that_can_reach_the_list(client, ranked, advisory_groups):
    resp = await client.get("/api/v1/analytics/impact", params={"limit": _CRITICAL_GROUPS}, headers=ranked)

    assert resp.status_code == 200, resp.text
    expected = [f"crit-{i}" for i in range(_CRITICAL_GROUPS)]
    assert sorted(row["component"] for row in resp.json()) == expected
    assert sorted(advisory_groups) == expected


async def test_hotspots_ranked_by_cve_count_read_advisories_only_for_the_page(client, ranked, advisory_groups):
    resp = await client.get(
        "/api/v1/analytics/hotspots", params={"sort_by": "finding_count", "limit": 3}, headers=ranked
    )

    assert resp.status_code == 200, resp.text
    assert [row["component"] for row in resp.json()] == ["crit-0", "crit-1", "crit-2"]
    assert sorted(advisory_groups) == ["crit-0", "crit-1", "crit-2"]


_TRICKY = [
    _finding(
        "aliased",
        [
            {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-0001"], "severity": "HIGH"},
            {"id": "cve-2026-0001 ", "severity": "critical"},
            {"id": "CVE-2026-0002", "aliases": ["ALAS-1", "CVE-2026-0003"], "severity": "MEDIUM"},
            {"id": "CVE-2026-0004", "severity": "CRITICAL", "waived": True},
            {"id": "GHSA-dddd-eeee-ffff", "severity": None},
            {"id": "ghsa-DDDD-eeee-ffff", "severity": "NEGLIGIBLE"},
            {"aliases": [], "severity": "HIGH"},
            {"id": "OSV-1", "resolved_cve": "CVE-2026-0005", "severity": "bogus"},
        ],
    ),
    _finding("aliased", [{"id": "CVE-2026-0002", "severity": "HIGH"}], project_id="p2"),
    _finding("all-waived", [{"id": "CVE-2026-0009", "severity": "HIGH", "waived": True}]),
    _finding("no-advisories", []),
    _finding("unversioned", [{"id": "CVE-2026-0010", "severity": "LOW"}], version=None),
]


async def test_the_cve_counts_ranked_in_mongo_are_the_counts_shown(db):
    from app.api.v1.endpoints.analytics.risk import _counted_groups, _vulnerable_groups

    await db.findings.insert_many(_TRICKY)
    repo = FindingRepository(db)

    counted = await repo.aggregate(_counted_groups([_SCAN]))
    grouped = await repo.aggregate(_vulnerable_groups({"scan_id": {"$in": [_SCAN]}}))

    def key(row: dict) -> tuple:
        return row["_id"]["component"], row["_id"].get("version")

    shown = {key(row): severity_counts_from_details(row["details_list"]) for row in grouped}
    assert {key(row): row["counts"] for row in counted} == shown
    assert {key(row): row["cve_count"] for row in counted} == {k: sum(v.values()) for k, v in shown.items()}
    assert {key(row): sorted(row["project_ids"]) for row in counted} == {
        key(row): sorted(row["project_ids"]) for row in grouped
    }
    assert shown[("aliased", "1.0.0")] == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
        "negligible": 1,
        "info": 0,
        "unknown": 1,
    }
