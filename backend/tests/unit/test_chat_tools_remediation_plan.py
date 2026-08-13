"""generate_remediation_plan must source targets from the stored finding shape (details.fixed_version / details.vulnerabilities[])."""

import pytest

from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN


@pytest.fixture
def admin_user():
    return User(
        id="admin-1",
        username="admin",
        email="admin@test.com",
        permissions=list(PRESET_ADMIN),
    )


def _seed_project(db, project_id="proj-1", latest_scan_id="scan-1"):
    db.projects._docs[project_id] = {
        "_id": project_id,
        "name": "P",
        "team_id": None,
        "latest_scan_id": latest_scan_id,
    }


def _seed_vuln_finding(db, fid, component, version, severity, details):
    # Mirrors the persisted shape: top-level component/version, fixes only under details.
    db.findings._docs[fid] = {
        "_id": f"uuid-{fid}",
        "finding_id": fid,
        "scan_id": "scan-1",
        "project_id": "proj-1",
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": version,
        "details": details,
    }


def _seed_dependency(db, name, version, direct=True, dep_type="npm"):
    key = f"{name}@{version}"
    db.dependencies._docs[key] = {
        "_id": key,
        "scan_id": "scan-1",
        "name": name,
        "version": version,
        "direct": direct,
        "type": dep_type,
        "purl": f"pkg:{dep_type}/{name}@{version}",
    }


async def _plan(db, user):
    result = await ChatToolRegistry()._dispatch("generate_remediation_plan", {"project_id": "proj-1"}, user, db)
    assert "plan" in result, result
    return result


class TestRemediationPlanTargets:
    @pytest.mark.asyncio
    async def test_target_from_details_fixed_version(self, db, admin_user):
        _seed_project(db)
        _seed_dependency(db, "fast-uri", "3.1.2")
        _seed_vuln_finding(
            db,
            "fast-uri:3.1.2",
            "fast-uri",
            "3.1.2",
            "HIGH",
            {
                "fixed_version": "3.1.5",
                "vulnerabilities": [
                    {
                        "id": "GHSA-4c8g-83qw-93j6",
                        "severity": "HIGH",
                        "fixed_version": "3.1.3",
                        "resolved_cve": "CVE-2026-13676",
                    },
                    {
                        "id": "CVE-2026-99999",
                        "severity": "CRITICAL",
                        "fixed_version": "3.1.5",
                    },
                ],
            },
        )

        result = await _plan(db, admin_user)
        (step,) = result["plan"]

        assert step["target_version"] == "3.1.5"
        assert step["has_fix"] is True
        assert step["current_version"] == "3.1.2"
        assert step["is_direct"] is True
        assert step["breaking_change_risk"] == "low"
        assert result["summary"]["steps_without_fix"] == 0

    @pytest.mark.asyncio
    async def test_resolved_cves_from_vulnerability_entries(self, db, admin_user):
        _seed_project(db)
        _seed_vuln_finding(
            db,
            "fast-uri:3.1.2",
            "fast-uri",
            "3.1.2",
            "CRITICAL",
            {
                "fixed_version": "3.1.5",
                "vulnerabilities": [
                    {
                        "id": "GHSA-4c8g-83qw-93j6",
                        "severity": "HIGH",
                        "fixed_version": "3.1.3",
                        "resolved_cve": "CVE-2026-13676",
                    },
                    {
                        "id": "CVE-2026-99999",
                        "severity": "CRITICAL",
                        "fixed_version": "3.1.5",
                    },
                ],
            },
        )

        result = await _plan(db, admin_user)
        (step,) = result["plan"]

        cves = {r["cve_id"] for r in step["resolves_findings"]}
        # resolved_cve preferred over the GHSA id; plain ids kept as-is.
        assert cves == {"CVE-2026-13676", "CVE-2026-99999"}
        assert step["resolves_count"] == 2
        assert step["critical_count"] == 1
        assert all(r["finding_id"] == "fast-uri:3.1.2" for r in step["resolves_findings"])

    @pytest.mark.asyncio
    async def test_comma_joined_fixed_version_split_into_candidates(self, db, admin_user):
        _seed_project(db)
        _seed_vuln_finding(
            db,
            "lib:1.2.0",
            "lib",
            "1.2.0",
            "HIGH",
            {
                "fixed_version": "1.2.6, 2.0.1",
                "vulnerabilities": [{"id": "CVE-2025-1", "severity": "HIGH", "fixed_version": "1.2.6, 2.0.1"}],
            },
        )

        result = await _plan(db, admin_user)
        (step,) = result["plan"]

        assert step["target_version"] == "2.0.1"
        assert step["breaking_change_risk"] == "high"

    @pytest.mark.asyncio
    async def test_unfixed_finding_reported_without_target(self, db, admin_user):
        _seed_project(db)
        _seed_vuln_finding(
            db,
            "left-pad:1.0.0",
            "left-pad",
            "1.0.0",
            "HIGH",
            {
                "fixed_version": None,
                "vulnerabilities": [{"id": "CVE-2025-2", "severity": "HIGH", "fixed_version": None}],
            },
        )

        result = await _plan(db, admin_user)
        (step,) = result["plan"]

        assert step["target_version"] is None
        assert step["has_fix"] is False
        assert step["resolves_findings"][0]["cve_id"] == "CVE-2025-2"
        assert result["summary"]["steps_without_fix"] == 1

    @pytest.mark.asyncio
    async def test_fixable_steps_sort_before_unfixable(self, db, admin_user):
        _seed_project(db)
        _seed_dependency(db, "fast-uri", "3.1.2")
        _seed_vuln_finding(
            db,
            "left-pad:1.0.0",
            "left-pad",
            "1.0.0",
            "CRITICAL",
            {
                "fixed_version": None,
                "vulnerabilities": [{"id": "CVE-2025-2", "severity": "CRITICAL", "fixed_version": None}],
            },
        )
        _seed_vuln_finding(
            db,
            "fast-uri:3.1.2",
            "fast-uri",
            "3.1.2",
            "HIGH",
            {
                "fixed_version": "3.1.5",
                "vulnerabilities": [{"id": "CVE-2026-99999", "severity": "HIGH", "fixed_version": "3.1.5"}],
            },
        )

        result = await _plan(db, admin_user)

        components = [s["component"] for s in result["plan"]]
        assert components == ["fast-uri", "left-pad"]
        assert [s["step"] for s in result["plan"]] == [1, 2]
