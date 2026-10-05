"""Hotspots and impact score each advisory's risk on its own CVSS, as scan-time enrichment does."""

from datetime import datetime, timezone

import pytest
import pytest_asyncio

from app.schemas.enrichment import EPSSData, KEVEntry
from app.services.enrichment.scoring import calculate_risk_score
from app.services.enrichment.service import vulnerability_enrichment_service

pytestmark = pytest.mark.live_mongo

_SCAN = "scan-risk"
_EPSS = 0.5


def _finding(component: str, advisory: dict) -> dict:
    return {
        "_id": component,
        "id": f"{component}:1.0.0",
        "finding_id": f"{component}:1.0.0",
        "scan_id": _SCAN,
        "project_id": "p",
        "type": "vulnerability",
        "severity": advisory["severity"],
        "component": component,
        "version": "1.0.0",
        "description": "",
        "scanners": ["trivy"],
        "waived": False,
        "scan_created_at": datetime.now(timezone.utc),
        "details": {"vulnerabilities": [{"aliases": [], **advisory}]},
    }


@pytest_asyncio.fixture
async def seeded(db, owner_auth_headers_proj, monkeypatch):
    async def _same_epss(cves):
        return {cve: EPSSData(cve=cve, epss_score=_EPSS, percentile=0.9, date="2026-10-01") for cve in cves}, True

    async def _no_kev():
        return {}

    monkeypatch.setattr(vulnerability_enrichment_service._epss_provider, "load_epss_scores", _same_epss)
    monkeypatch.setattr(vulnerability_enrichment_service._kev_provider, "load_kev_catalog", _no_kev)

    await db.scans.insert_one(
        {
            "_id": _SCAN,
            "project_id": "p",
            "status": "completed",
            "branch": "main",
            "created_at": datetime.now(timezone.utc),
        }
    )
    await db.projects.update_one({"_id": "p"}, {"$set": {"latest_scan_id": _SCAN}})
    await db.findings.insert_many(
        [
            _finding("low-cvss", {"id": "CVE-2026-0002", "severity": "LOW", "cvss_score": 3.1}),
            _finding("critical-cvss", {"id": "CVE-2026-0001", "severity": "CRITICAL", "cvss_score": 9.8}),
            _finding("ghsa-only", {"id": "GHSA-aaaa-bbbb-cccc", "severity": "HIGH", "cvss_score": 7.5}),
        ]
    )
    return owner_auth_headers_proj


_EXPECTED = [
    ("critical-cvss", calculate_risk_score(9.8, _EPSS, False, False)),
    ("low-cvss", calculate_risk_score(3.1, _EPSS, False, False)),
    ("ghsa-only", calculate_risk_score(7.5, None, False, False)),
]


@pytest.mark.asyncio
async def test_hotspots_sorted_by_risk_follow_each_advisory_s_cvss(client, seeded):
    resp = await client.get("/api/v1/analytics/hotspots", params={"sort_by": "risk"}, headers=seeded)

    assert resp.status_code == 200, resp.text
    assert [(h["component"], h["max_risk_score"]) for h in resp.json()] == _EXPECTED


@pytest.mark.asyncio
async def test_impact_risk_follows_each_advisory_s_cvss(client, seeded):
    resp = await client.get("/api/v1/analytics/impact", headers=seeded)

    assert resp.status_code == 200, resp.text
    assert sorted((r["component"], r["max_risk_score"]) for r in resp.json()) == sorted(_EXPECTED)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/v1/analytics/hotspots?sort_by=risk", "/api/v1/analytics/impact"])
async def test_a_waived_advisory_does_not_rank_the_risk(client, db, seeded, path):
    mixed = _finding("mixed", {"id": "CVE-2026-0010", "severity": "LOW", "cvss_score": 3.1})
    mixed["details"]["vulnerabilities"].insert(
        0, {"aliases": [], "id": "CVE-2026-0009", "severity": "CRITICAL", "cvss_score": 9.8, "waived": True}
    )
    await db.findings.insert_one(mixed)

    resp = await client.get(path, headers=seeded)

    assert resp.status_code == 200, resp.text
    assert [r["max_risk_score"] for r in resp.json() if r["component"] == "mixed"] == [
        calculate_risk_score(3.1, _EPSS, False, False)
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/v1/analytics/hotspots?sort_by=risk", "/api/v1/analytics/impact"])
async def test_the_kev_count_counts_each_live_kev_advisory(client, db, seeded, monkeypatch, path):
    async def _kev():
        return {
            cve: KEVEntry(cve=cve, date_added="2026-01-01", required_action="Patch", due_date="2026-12-01")
            for cve in ("CVE-2026-0020", "CVE-2026-0021", "CVE-2026-0022")
        }

    monkeypatch.setattr(vulnerability_enrichment_service._kev_provider, "load_kev_catalog", _kev)
    exploited = _finding("exploited", {"id": "CVE-2026-0020", "severity": "HIGH", "cvss_score": 7.5})
    exploited["details"]["vulnerabilities"] += [
        {"aliases": [], "id": "CVE-2026-0021", "severity": "HIGH", "cvss_score": 7.5},
        {"aliases": [], "id": "CVE-2026-0022", "severity": "HIGH", "cvss_score": 7.5, "waived": True},
    ]
    # Live in another component, the waived CVE is enriched like the others.
    elsewhere = _finding("elsewhere", {"id": "CVE-2026-0022", "severity": "HIGH", "cvss_score": 7.5})
    await db.findings.insert_many([exploited, elsewhere])

    resp = await client.get(path, headers=seeded)

    assert resp.status_code == 200, resp.text
    kev_counts = {r["component"]: r["kev_count"] for r in resp.json()}
    assert (kev_counts["exploited"], kev_counts["elsewhere"]) == (2, 1)
