"""Each vulnerability search row describes and is filtered by its own advisory, not the document it sits in."""

from datetime import datetime, timezone

import pytest
import pytest_asyncio

from app.schemas.enrichment import VulnerabilityEnrichment
from app.services.enrichment.service import apply_enrichments

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_SCAN_ID = "scan-rows"
_PATH = "/api/v1/analytics/vulnerability-search"


@pytest_asyncio.fixture
async def search(client, db, owner_auth_headers_proj):
    await db.scans.insert_one(
        {"_id": _SCAN_ID, "project_id": "p", "status": "completed", "created_at": datetime.now(timezone.utc)}
    )
    await db.projects.update_one({"_id": "p"}, {"$set": {"latest_scan_id": _SCAN_ID}})

    async def rows(details: dict, query: str = "cve-", **params) -> dict[str, dict]:
        await db.findings.replace_one(
            {"_id": "libssl3"},
            {
                "_id": "libssl3",
                "id": "libssl3:3.0.9-1",
                "finding_id": "libssl3:3.0.9-1",
                "aliases": [],
                "severity": "CRITICAL",
                "component": "libssl3",
                "version": "3.0.9-1",
                "project_id": "p",
                "scan_id": _SCAN_ID,
                "type": "vulnerability",
                "description": "",
                "waived": False,
                "scanners": ["trivy"],
                "details": details,
            },
            upsert=True,
        )
        resp = await client.get(_PATH, params={"q": query, **params}, headers=owner_auth_headers_proj)
        assert resp.status_code == 200, resp.text
        return {row["vulnerability_id"]: row for row in resp.json()["items"]}

    return rows


def _kev_and_plain():
    """A KEV, ransomware, high-EPSS CVE and a plain sibling, enriched the way ingest stores them."""
    details = {
        "vulnerabilities": [
            {"id": "CVE-2021-0001", "severity": "CRITICAL", "fixed_version": "3.0.11"},
            {"id": "CVE-2021-0002", "severity": "LOW"},
        ]
    }
    kev = VulnerabilityEnrichment(
        cve="CVE-2021-0001",
        epss_score=0.9,
        epss_percentile=99.0,
        is_kev=True,
        kev_due_date="2022-01-01",
        kev_ransomware_use=True,
        risk_score=90.0,
    )
    apply_enrichments(details, {"CVE-2021-0001": kev})
    return details


async def test_a_plain_cve_row_does_not_borrow_its_kev_siblings_threat_intel(search):
    row = (await search(_kev_and_plain()))["CVE-2021-0002"]

    assert (row["in_kev"], row["kev_ransomware"], row["kev_due_date"]) == (False, False, None)
    assert (row["epss_score"], row["epss_percentile"], row["fixed_version"]) == (None, None, None)


async def test_the_kev_filter_keeps_each_cve_by_its_own_listing(search):
    assert set(await search(_kev_and_plain(), in_kev="false")) == {"CVE-2021-0002"}
    assert set(await search(_kev_and_plain(), in_kev="true")) == {"CVE-2021-0001"}


async def test_the_fix_filter_keeps_each_cve_by_its_own_fix(search):
    assert set(await search(_kev_and_plain(), has_fix="true")) == {"CVE-2021-0001"}
    assert set(await search(_kev_and_plain(), has_fix="false")) == {"CVE-2021-0002"}


async def test_the_severity_filter_keeps_each_cve_by_its_own_severity(search):
    assert set(await search(_kev_and_plain(), severity="low")) == {"CVE-2021-0002"}


async def test_a_waived_cve_of_a_partly_waived_record_is_left_out_unless_asked_for(search):
    details = {"vulnerabilities": [{"id": "CVE-A", "waived": True}, {"id": "CVE-B"}]}

    assert set(await search(details)) == {"CVE-B"}
    assert set(await search(details, include_waived="true")) == {"CVE-A", "CVE-B"}


async def test_an_unfixed_cve_row_does_not_borrow_the_documents_fix(search):
    rows = await search(
        {
            "fixed_version": "3.0.11-1~deb12u2",
            "vulnerabilities": [
                {"id": "CVE-A", "severity": "CRITICAL"},
                {"id": "CVE-B", "severity": "LOW", "fixed_version": "3.0.11-1~deb12u2"},
            ],
        }
    )
    assert rows["CVE-A"]["fixed_version"] is None
    assert rows["CVE-B"]["fixed_version"] == "3.0.11-1~deb12u2"


async def test_a_ghsa_row_is_labelled_with_its_resolved_cve_and_keeps_the_ghsa_as_alias(search):
    rows = await search({"vulnerabilities": [{"id": "GHSA-9f52-rjqv-25qv", "resolved_cve": "CVE-2026-41852"}]}, "ghsa")

    assert list(rows) == ["CVE-2026-41852"]
    assert rows["CVE-2026-41852"]["aliases"] == ["GHSA-9f52-rjqv-25qv"]


async def test_a_search_by_the_resolved_cve_lists_the_ghsa_row(search):
    rows = await search(
        {"vulnerabilities": [{"id": "GHSA-9f52-rjqv-25qv", "resolved_cve": "CVE-2026-41852"}]}, "CVE-2026-41852"
    )

    assert list(rows) == ["CVE-2026-41852"]
    assert rows["CVE-2026-41852"]["aliases"] == ["GHSA-9f52-rjqv-25qv"]


async def test_the_kev_filter_reads_the_persisted_roll_up_of_a_finding_that_is_its_own_row(search):
    rolled_up = {"in_kev": True, "vulnerabilities": [{"id": "CVE-2021-44228"}]}

    assert set(await search(rolled_up, "libssl", in_kev="true")) == {"libssl3:3.0.9-1"}
    assert set(await search(rolled_up, "libssl", in_kev="false")) == set()
    assert set(await search({"vulnerabilities": []}, "libssl", in_kev="true")) == set()
