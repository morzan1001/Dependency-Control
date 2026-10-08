"""get_project_recommendations: access checks, scan resolution, what reaches the engine, and the summary tally."""

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import fakeredis.aioredis
import pytest

from app.api.v1.endpoints.analytics import recommendations as rec_module
from app.core.cache import CacheService
from app.core.init_db import create_indexes
from app.models.finding import Finding
from app.models.waiver import Waiver
from app.repositories.waivers import WaiverRepository
from app.schemas.finding_details import ReachabilityInfo
from app.schemas.recommendation import Priority, Recommendation, RecommendationType
from app.services.analysis.engine import _prepare_finding_records
from app.services.reachability_enrichment import store_reachability
from app.services.sbom_parser import parse_sbom
from app.services.stats import recalculate_project_stats
from tests.helpers.findings import stored_vulnerability

_NOW = datetime.now(timezone.utc)


def _path(project_id: str) -> str:
    return f"/api/v1/analytics/projects/{project_id}/recommendations"


async def _insert_scan(db, scan_id: str, project_id: str = "p", age_hours: int = 0) -> None:
    created_at = _NOW - timedelta(hours=age_hours)
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": project_id,
            "branch": "main",
            "status": "completed",
            "created_at": created_at,
            "completed_at": created_at + timedelta(minutes=5),
        }
    )


def _finding(_id: str, finding_type: str) -> dict:
    return {
        "_id": _id,
        "id": _id,
        "project_id": "p",
        "scan_id": "s",
        "finding_id": _id,
        "type": finding_type,
        "severity": "HIGH",
        "component": "lib",
        "version": "1.0",
        "description": "d",
        "details": {},
        "scanners": ["x"],
    }


def _rec(rec_type: RecommendationType, impact: dict, components: int = 0) -> Recommendation:
    return Recommendation(
        type=rec_type,
        priority=Priority.LOW,
        title=rec_type.value,
        description="d",
        impact=impact,
        affected_components=[],
        affected_components_total=components,
        action={},
    )


def _engine_returning(recommendations: list[Recommendation], seen: dict):
    def _generate(**kwargs):
        seen.update(kwargs)
        return recommendations

    return _generate


def _counting_engine(runs: list[int]):
    generate = rec_module.generate_recommendations

    def _generate(**kwargs):
        runs.append(len(kwargs["findings"]))
        time.sleep(0.05)
        return generate(**kwargs)

    return _generate


def _vulnerability_records(scan_id: str, component: str, version: str, advisories: list[dict]) -> list[dict]:
    """What the analysis engine persists for one aggregated vulnerability."""
    finding = Finding.model_validate(stored_vulnerability(component, version, advisories))
    records, _ = _prepare_finding_records([finding], scan_id, "p", None)
    return records


@pytest.fixture
def no_live_intel(monkeypatch):
    async def _enrich(_cves):
        return {}

    monkeypatch.setattr(rec_module.vulnerability_enrichment_service, "enrich_cves", _enrich)


def _card_types(resp) -> list[str]:
    return [rec["type"] for rec in resp.json()["recommendations"]]


@pytest.fixture
def redis_cache(monkeypatch):
    cache = CacheService()
    cache._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    cache._pool = object()  # non-None so get_client() short-circuits to the fake
    cache._available = True
    monkeypatch.setattr(rec_module, "cache_service", cache)
    return cache


async def _reanalyse(db, scan_id: str, finding: dict) -> None:
    """A re-ingest or a late analyzer result: the same scan id gets a new finding set and completion."""
    await db.findings.insert_one(finding)
    await db.scans.update_one({"_id": scan_id}, {"$set": {"completed_at": _NOW + timedelta(hours=1)}})


@pytest.mark.asyncio
async def test_a_reanalysed_scan_is_not_served_its_earlier_recommendations(
    client, db, owner_auth_headers_proj, monkeypatch, redis_cache
):
    await _insert_scan(db, "s")
    await db.findings.insert_one(_finding("f1", "vulnerability"))
    runs: list[int] = []
    monkeypatch.setattr(rec_module, "generate_recommendations", _counting_engine(runs))

    first = await client.get(_path("p"), headers=owner_auth_headers_proj)
    repeat = await client.get(_path("p"), headers=owner_auth_headers_proj)
    await _reanalyse(db, "s", _finding("f2", "sast"))
    after = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert first.status_code == repeat.status_code == after.status_code == 200, after.text
    assert repeat.json() == first.json()
    assert runs == [1, 2]
    assert after.json()["total_findings"] == 2
    assert after.json()["summary"]["sast_issues"] == 1


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_waiver_restamp_is_not_served_the_recommendations_from_before_it(
    client, db, owner_auth_headers_proj, redis_cache
):
    await create_indexes(db)
    await _insert_scan(db, "s")
    await db.findings.insert_many([_finding("f-live", "secret"), _finding("f-waived", "secret")])
    before = await client.get(_path("p"), headers=owner_auth_headers_proj)
    await WaiverRepository(db).create(
        Waiver(project_id="p", finding_id="f-waived", finding_type="secret", reason="test key", created_by="u")
    )

    await recalculate_project_stats("p", db)
    after = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert before.status_code == after.status_code == 200, after.text
    assert (before.json()["findings_total"], after.json()["findings_total"]) == (2, 1)


@pytest.mark.asyncio
async def test_an_archive_restored_string_completion_date_still_keys_the_cache(
    client, db, owner_auth_headers_proj, redis_cache
):
    await _insert_scan(db, "s")
    await db.scans.update_one({"_id": "s"}, {"$set": {"completed_at": _NOW.isoformat()}})

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_concurrent_views_of_one_scan_share_one_computation(
    client, db, owner_auth_headers_proj, monkeypatch, redis_cache
):
    await _insert_scan(db, "s")
    await db.findings.insert_one(_finding("f1", "vulnerability"))
    runs: list[int] = []
    monkeypatch.setattr(rec_module, "generate_recommendations", _counting_engine(runs))

    responses = await asyncio.gather(*(client.get(_path("p"), headers=owner_auth_headers_proj) for _ in range(3)))

    assert [r.status_code for r in responses] == [200, 200, 200]
    assert runs == [1]


@pytest.mark.asyncio
async def test_an_unknown_project_is_not_found(client, owner_auth_headers_proj):
    resp = await client.get(_path("absent"), headers=owner_auth_headers_proj)

    assert resp.status_code == 404
    assert "Project not found" in resp.text


@pytest.mark.asyncio
async def test_a_project_outside_the_callers_scope_is_denied(
    client, db, owner_auth_headers_proj, owner_auth_headers_proj_p2
):
    await _insert_scan(db, "s")

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj_p2)

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_a_project_without_scans_is_not_found(client, owner_auth_headers_proj):
    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 404
    assert "No scan found for this project" in resp.text


@pytest.mark.asyncio
async def test_an_explicit_scan_id_wins_over_the_latest_scan(client, db, owner_auth_headers_proj):
    await _insert_scan(db, "older", age_hours=2)
    await _insert_scan(db, "newer")

    resp = await client.get(_path("p"), params={"scan_id": "older"}, headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert resp.json()["scan_id"] == "older"


@pytest.mark.asyncio
async def test_an_explicit_scan_id_of_another_project_is_not_found(client, db, owner_auth_headers_proj):
    await _insert_scan(db, "own")
    await _insert_scan(db, "foreign", project_id="p2")

    resp = await client.get(_path("p"), params={"scan_id": "foreign"}, headers=owner_auth_headers_proj)

    assert resp.status_code == 404
    assert "No scan found for this project" in resp.text


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_base_image_card_names_the_scanned_image_rather_than_an_application_sbom(
    client, db, owner_auth_headers_proj, no_live_intel
):
    fixtures = Path(__file__).parents[1] / "fixtures" / "sbom"
    app_rows, image_rows = (
        [d.model_dump() for d in parse_sbom(json.loads((fixtures / name).read_text())).dependencies]
        for name in ("mono.trivy.cdx.json", "alpine.syft.spdx.json")
    )
    await _insert_scan(db, "s")
    await db.dependencies.insert_many(
        [row | {"_id": f"d{i}", "project_id": "p", "scan_id": "s"} for i, row in enumerate(app_rows + image_rows)]
    )
    advisory = {"id": "CVE-2024-0001", "severity": "CRITICAL", "fixed_version": "9.9.9"}
    records = [
        record for row in image_rows for record in _vulnerability_records("s", row["name"], row["version"], [advisory])
    ]
    await db.findings.insert_many(records)

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    [card] = [r for r in resp.json()["recommendations"] if r["type"] == "base_image_update"]
    assert card["action"]["current_image"] == "alpine:3.20"
    assert card["action"]["commands"][1] == "docker pull alpine:latest"


@pytest.mark.asyncio
async def test_the_live_per_cve_threat_intel_reaches_the_engine(client, db, owner_auth_headers_proj, monkeypatch):
    from app.schemas.enrichment import VulnerabilityEnrichment

    await _insert_scan(db, "s")
    finding = _finding("f1", "vulnerability")
    finding["details"] = {"vulnerabilities": [{"id": "CVE-2023-0001", "aliases": ["CVE-2023-0002"]}]}
    await db.findings.insert_one(finding)
    live = {cve: VulnerabilityEnrichment(cve=cve, risk_score=20.0) for cve in ("CVE-2023-0001", "CVE-2023-0002")}

    async def _enrich(cves):
        return {cve: live[cve] for cve in cves}

    monkeypatch.setattr(rec_module.vulnerability_enrichment_service, "enrich_cves", _enrich)
    seen: dict = {}
    monkeypatch.setattr(rec_module, "generate_recommendations", _engine_returning([], seen))

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert seen["threat_intel"] == live


@pytest.mark.asyncio
async def test_the_summary_tallies_findings_and_recommendations_into_their_buckets(
    client, db, owner_auth_headers_proj, monkeypatch
):
    await _insert_scan(db, "s")
    finding_types = [
        "vulnerability",
        "secret",
        "sast",
        "iac",
        "license",
        "quality",
        "crypto_weak_key",
        "crypto_key_management",
        "malware",
    ]
    for index, finding_type in enumerate(finding_types):
        await db.findings.insert_one(_finding(f"f{index}", finding_type))
    t = RecommendationType
    impacts = [
        (t.BASE_IMAGE_UPDATE, 1),
        (t.DIRECT_DEPENDENCY_UPDATE, 2),
        (t.TRANSITIVE_FIX_VIA_PARENT, 4),
        (t.NO_FIX_AVAILABLE, 8),
        (t.ROTATE_SECRETS, 16),
        (t.FIX_CODE_SECURITY, 64),
        (t.FIX_INFRASTRUCTURE, 128),
        (t.LICENSE_COMPLIANCE, 256),
        (t.SUPPLY_CHAIN_RISK, 512),
        (t.VERSION_FRAGMENTATION, 10),
        (t.DEV_IN_PRODUCTION, 20),
        (t.DUPLICATE_FUNCTIONALITY, 30),
        (t.DEEP_DEPENDENCY_CHAIN, 40),
        (t.RECURRING_VULNERABILITY, 999),
        (t.REGRESSION_DETECTED, 999),
        (t.CROSS_PROJECT_PATTERN, 3),
        (t.SHARED_VULNERABILITY, 5),
        (t.REPLACE_WEAK_ALGORITHM, 100),
        (t.INCREASE_KEY_SIZE, 200),
        (t.UPGRADE_PROTOCOL, 300),
        (t.PQC_MIGRATION, 400),
        (t.ROTATE_CERTIFICATE, 500),
        (t.LICENSE_DRIFT, 77),
        (t.CRITICAL_HOTSPOT, 88),
    ]
    # Hygiene cards count no findings; the summary tallies the components they cover.
    hygiene = {
        t.VERSION_FRAGMENTATION,
        t.DEV_IN_PRODUCTION,
        t.DUPLICATE_FUNCTIONALITY,
        t.DEEP_DEPENDENCY_CHAIN,
        t.SUPPLY_CHAIN_RISK,
    }
    recommendations = [
        _rec(rec_type, {"total": 0}, components=n) if rec_type in hygiene else _rec(rec_type, {"total": n})
        for rec_type, n in impacts
    ]
    recommendations.append(_rec(t.BASE_IMAGE_UPDATE, {}))
    monkeypatch.setattr(rec_module, "generate_recommendations", _engine_returning(recommendations, {}))

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_findings"] == 9
    assert body["total_vulnerabilities"] == 1
    assert body["summary"] == {
        "base_image_updates": 2,
        "direct_updates": 1,
        "transitive_updates": 1,
        "no_fix": 1,
        "total_fixable_vulns": 7,
        "total_unfixable_vulns": 8,
        "secrets_to_rotate": 16,
        "sast_issues": 64,
        "iac_issues": 128,
        "license_issues": 256,
        "quality_issues": 512,
        "crypto_issues": 1500,
        "fragmentation_issues": 100,
        "trend_alerts": 2,
        "cross_project_issues": 8,
        "finding_counts": {
            "vulnerabilities": 1,
            "secrets": 1,
            # Key-management cards are FIX_CODE_SECURITY and land in sast_issues, so their findings count there too.
            "sast": 2,
            "iac": 1,
            "license": 1,
            "quality": 1,
            "crypto": 1,
        },
    }


@pytest.mark.asyncio
async def test_a_saturated_findings_read_reports_what_the_scan_holds(client, db, owner_auth_headers_proj, monkeypatch):
    await _insert_scan(db, "s")
    for index in range(3):
        await db.findings.insert_one(_finding(f"f{index}", "vulnerability"))
    monkeypatch.setattr(rec_module, "ANALYTICS_MAX_QUERY_LIMIT", 2)
    monkeypatch.setattr(rec_module, "generate_recommendations", _engine_returning([], {}))

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert resp.json()["total_findings"] == 2
    assert resp.json()["findings_total"] == 3


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_waived_findings_do_not_reach_the_engine(client, db, owner_auth_headers_proj, monkeypatch):
    await _insert_scan(db, "s")
    waived = _finding("f-waived", "secret") | {"waived": True}
    await db.findings.insert_many([_finding("f-live", "secret"), waived])
    seen: dict = {}
    monkeypatch.setattr(rec_module, "generate_recommendations", _engine_returning([], seen))

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert [f.id for f in seen["findings"]] == ["f-live"]
    assert resp.json()["findings_total"] == 1


_CROSS_PROJECT_COMPARISON_LIMIT = 20


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_cross_project_cards_compare_the_viewed_project_first_among_projects_with_a_scan(
    client, db, owner_auth_headers_proj, monkeypatch
):
    """Unscanned projects ahead of the scanned ones used to fill every comparison slot, and the viewed
    project was never compared, so its own cards described only other projects."""
    member = [{"user_id": "ownerp", "role": "viewer"}]
    await db.projects.insert_many(
        [
            {"_id": f"unscanned-{index:02d}", "name": f"unscanned-{index:02d}", "members": member}
            for index in range(_CROSS_PROJECT_COMPARISON_LIMIT)
        ]
    )
    await db.projects.insert_one({"_id": "scanned", "name": "scanned", "members": member, "latest_scan_id": "s2"})
    await _insert_scan(db, "s2", project_id="scanned")
    await _insert_scan(db, "s")
    await db.projects.update_one({"_id": "p"}, {"$set": {"latest_scan_id": "s"}})
    seen: dict = {}
    monkeypatch.setattr(rec_module, "generate_recommendations", _engine_returning([], seen))

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert [row["project_id"] for row in seen["cross_project_data"]["projects"]] == ["p", "scanned"]


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_an_os_package_outside_the_inventory_window_still_joins_its_row(
    client, db, owner_auth_headers_proj, monkeypatch, no_live_intel
):
    sbom = json.loads((Path(__file__).parents[1] / "fixtures" / "sbom" / "rootfs.trivy.cdx.json").read_text())
    libssl = next(d.model_dump() for d in parse_sbom(sbom).dependencies if d.name == "libssl3")
    await _insert_scan(db, "s")
    filler = {"_id": "d-filler", "project_id": "p", "scan_id": "s", "name": "aaa-filler", "version": "1.0"}
    await db.dependencies.insert_many([filler, libssl | {"_id": "d-libssl", "project_id": "p", "scan_id": "s"}])
    advisory = {"id": "CVE-2024-0001", "severity": "CRITICAL", "fixed_version": "9.9.9"}
    await db.findings.insert_many(_vulnerability_records("s", "libssl3", libssl["version"], [advisory]))
    monkeypatch.setattr(rec_module, "SCAN_DEPENDENCY_READ_LIMIT", 1)

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert resp.json()["dependencies_read"] == 1
    assert "base_image_update" in _card_types(resp)
    assert "direct_dependency_update" not in _card_types(resp)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_clean_previous_build_raises_the_regression_card(client, db, owner_auth_headers_proj, no_live_intel):
    await _insert_scan(db, "s-prev", age_hours=2)
    await _insert_scan(db, "s")
    advisory = {"id": "CVE-2024-0001", "severity": "CRITICAL"}
    await db.findings.insert_many(_vulnerability_records("s", "lib", "1.0", [advisory]))

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert "regression_detected" in _card_types(resp)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_an_advisory_the_previous_build_reported_is_no_regression(
    client, db, owner_auth_headers_proj, no_live_intel
):
    await _insert_scan(db, "s-prev", age_hours=2)
    await _insert_scan(db, "s")
    advisory = {"id": "CVE-2024-0001", "severity": "CRITICAL"}
    for scan_id, version in (("s-prev", "1.0"), ("s", "1.1")):
        await db.findings.insert_many(_vulnerability_records(scan_id, "lib", version, [advisory]))

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert "regression_detected" not in _card_types(resp)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_finding_its_callgraph_proves_unreachable_counts_as_unreachable_on_its_card(
    client, db, owner_auth_headers_proj, no_live_intel
):
    await _insert_scan(db, "s")
    await db.dependencies.insert_one(
        {"_id": "d1", "project_id": "p", "scan_id": "s", "name": "lib", "version": "1.0", "direct": True}
    )
    advisory = {"id": "CVE-2024-0001", "severity": "CRITICAL", "fixed_version": "1.1"}
    [record] = _vulnerability_records("s", "lib", "1.0", [advisory])
    store_reachability(record, ReachabilityInfo(is_reachable=False, analysis_level="import"))
    await db.findings.insert_one(record)

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    [card] = [r for r in resp.json()["recommendations"] if r["type"] == "direct_dependency_update"]
    assert (card["impact"]["unreachable_count"], card["priority"]) == (1, "high")


@pytest.mark.asyncio
async def test_a_cve_the_live_refresh_has_no_data_for_keeps_its_stored_scores(
    client, db, owner_auth_headers_proj, monkeypatch
):
    service = rec_module.vulnerability_enrichment_service

    async def _kev_catalog():
        return {}

    async def _epss_outage(_cves):
        return {}, False

    monkeypatch.setattr(service._kev_provider, "load_kev_catalog", _kev_catalog)
    monkeypatch.setattr(service._epss_provider, "load_epss_scores", _epss_outage)
    await _insert_scan(db, "s")
    advisory = {"id": "CVE-2024-0001", "severity": "HIGH", "cvss_score": 7.5, "epss_score": 0.42, "risk_score": 71.5}
    await db.findings.insert_many(_vulnerability_records("s", "lib", "1.0", [advisory]))
    seen: dict = {}
    monkeypatch.setattr(rec_module, "generate_recommendations", _engine_returning([], seen))

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    [entry] = seen["findings"][0].details["vulnerabilities"]
    assert (entry["epss_score"], entry["risk_score"]) == (0.42, 71.5)


_ADVISORY_PAYLOAD = ("description", "references", "details", "cvss_vector", "ecosystem_specific")
_DEPENDENCY_PAYLOAD = ("description", "hashes", "properties", "cpes", "locations", "homepage")


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_engine_gets_findings_and_dependencies_without_the_payload_no_card_reads(
    client, db, owner_auth_headers_proj, monkeypatch, no_live_intel
):
    await _insert_scan(db, "s")
    advisory = {
        "id": "CVE-2021-23337",
        "severity": "HIGH",
        "fixed_version": "4.17.21",
        "description": "Command injection via template",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "ecosystem_specific": {"symbols": ["template"]},
    }
    [record] = _vulnerability_records("s", "lodash", "4.17.20", [advisory])
    record["related_findings"] = ["other-finding"]
    await db.findings.insert_one(record)
    await db.dependencies.insert_one(
        {
            "_id": "d1",
            "project_id": "p",
            "scan_id": "s",
            "name": "lodash",
            "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
            "type": "npm",
            "direct": True,
            "license": "MIT",
            "description": "Lodash modular utilities.",
            "hashes": {"sha512": "abc"},
            "properties": {"syft:package:foundBy": "javascript-lock-cataloger"},
            "cpes": ["cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*"],
            "locations": ["/package-lock.json"],
            "homepage": "https://lodash.com/",
        }
    )
    seen: dict = {}
    monkeypatch.setattr(rec_module, "generate_recommendations", _engine_returning([], seen))

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    [finding], [dependency] = seen["findings"], seen["dependencies"]
    [stored_advisory] = finding.details["vulnerabilities"]
    assert (stored_advisory["id"], finding.related_findings) == ("CVE-2021-23337", [])
    assert not set(_ADVISORY_PAYLOAD) & set(stored_advisory)
    assert (dependency["name"], dependency["license"]) == ("lodash", "MIT")
    assert not set(_DEPENDENCY_PAYLOAD) & set(dependency)
