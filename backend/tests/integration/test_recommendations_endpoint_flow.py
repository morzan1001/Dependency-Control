"""get_project_recommendations: access checks, scan resolution, what reaches the engine, and the summary tally."""

from datetime import datetime, timedelta, timezone

import pytest

from app.api.v1.endpoints.analytics import recommendations as rec_module
from app.schemas.recommendation import Priority, Recommendation, RecommendationType

_NOW = datetime.now(timezone.utc)


def _path(project_id: str) -> str:
    return f"/api/v1/analytics/projects/{project_id}/recommendations"


async def _insert_scan(db, scan_id: str, project_id: str = "p", age_hours: int = 0) -> None:
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": project_id,
            "branch": "main",
            "status": "completed",
            "created_at": _NOW - timedelta(hours=age_hours),
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


def _rec(rec_type: RecommendationType, impact: dict) -> Recommendation:
    return Recommendation(
        type=rec_type,
        priority=Priority.LOW,
        title=rec_type.value,
        description="d",
        impact=impact,
        affected_components=[],
        action={},
    )


def _engine_returning(recommendations: list[Recommendation], seen: dict):
    async def _generate(**kwargs):
        seen.update(kwargs)
        return recommendations

    return _generate


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


@pytest.mark.asyncio
async def test_the_first_dependency_naming_a_source_target_reaches_the_engine(
    client, db, owner_auth_headers_proj, monkeypatch
):
    await _insert_scan(db, "s")
    for index, target in enumerate([None, "registry/app:1", "registry/other:2"]):
        await db.dependencies.insert_one(
            {
                "_id": f"d{index}",
                "project_id": "p",
                "scan_id": "s",
                "name": f"dep-{index}",
                "version": "1.0",
                "source_target": target,
            }
        )
    seen: dict = {}
    monkeypatch.setattr(rec_module.recommendation_engine, "generate_recommendations", _engine_returning([], seen))

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert seen["source_target"] == "registry/app:1"
    assert resp.json()["dependencies_read"] == 3


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
    monkeypatch.setattr(rec_module.recommendation_engine, "generate_recommendations", _engine_returning([], seen))

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert seen["threat_intel"] == live


@pytest.mark.asyncio
async def test_the_summary_tallies_findings_and_recommendations_into_their_buckets(
    client, db, owner_auth_headers_proj, monkeypatch
):
    await _insert_scan(db, "s")
    finding_types = ["vulnerability", "secret", "sast", "iac", "license", "quality", "crypto_weak_key", "malware"]
    for index, finding_type in enumerate(finding_types):
        await db.findings.insert_one(_finding(f"f{index}", finding_type))
    t = RecommendationType
    impacts = [
        (t.BASE_IMAGE_UPDATE, 1),
        (t.DIRECT_DEPENDENCY_UPDATE, 2),
        (t.TRANSITIVE_FIX_VIA_PARENT, 4),
        (t.NO_FIX_AVAILABLE, 8),
        (t.ROTATE_SECRETS, 16),
        (t.REMOVE_SECRETS, 32),
        (t.FIX_CODE_SECURITY, 64),
        (t.FIX_INFRASTRUCTURE, 128),
        (t.LICENSE_COMPLIANCE, 256),
        (t.SUPPLY_CHAIN_RISK, 512),
        (t.OUTDATED_DEPENDENCY, 1024),
        (t.UNMAINTAINED_PACKAGE, 2048),
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
    recommendations = [_rec(rec_type, {"total": total}) for rec_type, total in impacts]
    recommendations.append(_rec(t.BASE_IMAGE_UPDATE, {}))
    monkeypatch.setattr(
        rec_module.recommendation_engine, "generate_recommendations", _engine_returning(recommendations, {})
    )

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_findings"] == 8
    assert body["total_vulnerabilities"] == 1
    assert body["summary"] == {
        "base_image_updates": 2,
        "direct_updates": 1,
        "transitive_updates": 1,
        "no_fix": 1,
        "total_fixable_vulns": 7,
        "total_unfixable_vulns": 8,
        "secrets_to_rotate": 48,
        "sast_issues": 64,
        "iac_issues": 128,
        "license_issues": 256,
        "quality_issues": 512,
        "crypto_issues": 1500,
        "outdated_deps": 3072,
        "fragmentation_issues": 100,
        "trend_alerts": 2,
        "cross_project_issues": 8,
        "finding_counts": {
            "vulnerabilities": 1,
            "secrets": 1,
            "sast": 1,
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
    monkeypatch.setattr(rec_module.recommendation_engine, "generate_recommendations", _engine_returning([], {}))

    resp = await client.get(_path("p"), headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert resp.json()["total_findings"] == 2
    assert resp.json()["findings_total"] == 3
