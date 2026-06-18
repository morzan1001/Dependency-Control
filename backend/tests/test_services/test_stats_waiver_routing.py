import pytest
import pytest_asyncio

from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
from app.services.stats import _is_signature_waiver

from tests.mocks.fake_mongo import FakeDatabase


def _waiver(finding_type=None, match=None, scope="finding"):
    return Waiver(reason="r", created_by="u", finding_type=finding_type, match=match, scope=scope)


class TestIsSignatureWaiver:
    def test_untyped_non_location_waiver_goes_legacy(self):
        # finding_type=None, no match -> must NOT be routed to the signature path (regression guard)
        assert _is_signature_waiver(_waiver(finding_type=None, match=None)) is False

    def test_typed_license_waiver_goes_legacy(self):
        assert _is_signature_waiver(_waiver(finding_type="license", match=None)) is False

    def test_location_typed_waiver_goes_signature(self):
        assert _is_signature_waiver(_waiver(finding_type="sast", match=None)) is True
        assert _is_signature_waiver(_waiver(finding_type="iac", match=None)) is True

    def test_waiver_with_match_goes_signature(self):
        sig = MatchSignature(rule_key="OPENGREP:r", file_key="a.py", anchor="fp1", anchor_kind="scanner_fp")
        assert _is_signature_waiver(_waiver(finding_type=None, match=sig)) is True

    def test_file_scope_location_waiver_goes_legacy(self):
        # file/rule scope keep broad legacy semantics even for location types
        assert _is_signature_waiver(_waiver(finding_type="sast", scope="file")) is False

    def test_rule_scope_location_waiver_goes_legacy(self):
        assert _is_signature_waiver(_waiver(finding_type="sast", scope="rule")) is False

    def test_finding_scope_location_waiver_goes_signature(self):
        assert _is_signature_waiver(_waiver(finding_type="sast", scope="finding")) is True


# ---------------------------------------------------------------------------
# recalculate_project_stats — unified stats pipeline (Task W4)
#
# recalc must produce the SAME authoritative Stats as
# calculate_comprehensive_stats: severity counts excluding waived findings,
# the avg-based risk_score, plus the populated adjusted_risk_score /
# threat_intel / reachability / prioritized fields. The old partial path
# (_build_stats_pipeline + _stats_from_result) left the enrichment fields at
# their defaults (0.0 / None) and computed a $sum risk_score, corrupting stats.
# ---------------------------------------------------------------------------

PROJECT_ID = "proj-w4"
SCAN_ID = "scan-w4"


def _finding(
    _id,
    severity,
    *,
    cvss_score=None,
    risk_score=None,
    epss_score=None,
    is_kev=False,
    reachable=None,
    reachability_level="unknown",
    waived=False,
):
    details = {}
    if cvss_score is not None:
        details["cvss_score"] = cvss_score
    if risk_score is not None:
        details["risk_score"] = risk_score
    if epss_score is not None:
        details["epss_score"] = epss_score
    if is_kev:
        details["in_kev"] = True
    doc = {
        "_id": _id,
        "finding_id": _id,
        "scan_id": SCAN_ID,
        "type": "vulnerability",
        "severity": severity,
        "component": "pkg",
        "version": "1.0.0",
        "details": details,
        "waived": waived,
    }
    if reachable is not None:
        doc["reachable"] = reachable
        doc["reachability_level"] = reachability_level
    return doc


@pytest_asyncio.fixture
async def seeded_db():
    """A fake DB with a project, scan, and enriched findings (one waived)."""
    db = FakeDatabase()
    await db.projects.insert_one(
        {"_id": PROJECT_ID, "name": "proj-w4", "latest_scan_id": SCAN_ID, "deleted_branches": []}
    )
    await db.scans.insert_one({"_id": SCAN_ID, "project_id": PROJECT_ID, "status": "completed"})
    findings = [
        _finding(
            "f-crit",
            "CRITICAL",
            cvss_score=9.8,
            risk_score=95.0,
            epss_score=0.8,
            is_kev=True,
            reachable=True,
            reachability_level="confirmed",
        ),
        _finding("f-high", "HIGH", cvss_score=7.5, risk_score=60.0, epss_score=0.2, reachable=False),
        _finding("f-med", "MEDIUM", cvss_score=4.0, risk_score=20.0),
        # Covered by an active finding-level waiver below -> excluded from counts/scores.
        _finding("f-waived", "CRITICAL", cvss_score=9.0, risk_score=90.0),
    ]
    for f in findings:
        await db.findings.insert_one(f)
    # Active finding-scope waiver for f-waived; recalc resets+re-applies it.
    await db.waivers.insert_one(
        {
            "_id": "w-1",
            "project_id": PROJECT_ID,
            "finding_id": "f-waived",
            "scope": "finding",
            "finding_type": "vulnerability",
            "reason": "accepted",
            "created_by": "tester",
        }
    )
    return db


class TestRecalculateUnifiedStats:
    @pytest.mark.asyncio
    async def test_recalc_matches_comprehensive_stats(self, seeded_db):
        """recalc persists the SAME Stats as calculate_comprehensive_stats."""
        from app.services.analysis.stats import calculate_comprehensive_stats
        from app.services.stats import recalculate_project_stats

        # recalc resets + re-applies waivers, then computes stats. Comparing
        # comprehensive on the SAME post-recalc state proves identical filtering.
        result = await recalculate_project_stats(PROJECT_ID, seeded_db)
        comprehensive = await calculate_comprehensive_stats(seeded_db, SCAN_ID)

        assert result is not None
        # Severity counts identical and exclude the waived CRITICAL finding.
        assert result.critical == comprehensive.critical == 1
        assert result.high == comprehensive.high == 1
        assert result.medium == comprehensive.medium == 1
        # risk_score is the avg (not a sum); identical to comprehensive.
        assert result.risk_score == comprehensive.risk_score

    @pytest.mark.asyncio
    async def test_recalc_populates_enrichment_fields(self, seeded_db):
        """The partial path left these at defaults; the unified path must populate them."""
        from app.services.stats import recalculate_project_stats

        result = await recalculate_project_stats(PROJECT_ID, seeded_db)

        assert result is not None
        assert result.adjusted_risk_score != 0.0
        assert result.threat_intel is not None
        assert result.reachability is not None
        assert result.prioritized is not None
        # KEV + reachability enrichment actually reflected.
        assert result.threat_intel.kev_count == 1
        assert result.reachability.reachable_count == 1

    @pytest.mark.asyncio
    async def test_recalc_persists_to_scan_and_project(self, seeded_db):
        """Persisted scan.stats / project.stats carry the enrichment fields, not zeros."""
        from app.services.stats import recalculate_project_stats

        await recalculate_project_stats(PROJECT_ID, seeded_db)

        scan_doc = await seeded_db.scans.find_one({"_id": SCAN_ID})
        project_doc = await seeded_db.projects.find_one({"_id": PROJECT_ID})
        assert scan_doc["stats"]["threat_intel"] is not None
        assert scan_doc["stats"]["adjusted_risk_score"] != 0.0
        assert project_doc["stats"]["reachability"] is not None
        assert scan_doc["ignored_count"] == 1
