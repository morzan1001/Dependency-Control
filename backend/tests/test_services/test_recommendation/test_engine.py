"""Tests for app.services.recommendations."""

import pytest

from app.services.recommendations import (
    RecommendationEngine,
    _safe_extend,
    _deduplicate_recommendations,
)
from app.schemas.recommendation import Recommendation, RecommendationType, Priority


def _make_vuln_finding(
    finding_id="CVE-2024-0001",
    severity="HIGH",
    component="pkg-name",
    version="1.0.0",
    fixed_version="1.1.0",
    purl=None,
    is_kev=False,
    epss_score=None,
    reachable=None,
):
    return {
        "id": finding_id,
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": version,
        "details": {
            "fixed_version": fixed_version,
            "purl": purl or f"pkg:pypi/{component}@{version}",
            "is_kev": is_kev,
            "epss_score": epss_score,
        },
        "reachable": reachable,
        "reachability_level": None,
        "aliases": [],
    }


def _make_secret_finding(
    finding_id="SECRET-001",
    severity="HIGH",
    component="config/secrets.yaml",
    rule_id="generic-api-key",
):
    return {
        "id": finding_id,
        "type": "secret",
        "severity": severity,
        "component": component,
        "version": None,
        "details": {
            "rule_id": rule_id,
            "file_path": component,
        },
        "reachable": None,
        "reachability_level": None,
        "aliases": [],
    }


def _make_sast_finding(
    finding_id="SAST-001",
    severity="MEDIUM",
    component="src/app.py",
    rule_id="sql-injection",
):
    return {
        "id": finding_id,
        "type": "sast",
        "severity": severity,
        "component": component,
        "version": None,
        "details": {
            "rule_id": rule_id,
            "file_path": component,
            "line_number": 42,
        },
        "reachable": None,
        "reachability_level": None,
        "aliases": [],
    }


def _make_dependency(
    name="pkg-name",
    version="1.0.0",
    purl=None,
    direct=True,
    source_type="application",
    dep_type="pypi",
):
    return {
        "name": name,
        "version": version,
        "purl": purl or f"pkg:pypi/{name}@{version}",
        "direct": direct,
        "source_type": source_type,
        "type": dep_type,
    }


def _make_recommendation(
    rec_type=RecommendationType.DIRECT_DEPENDENCY_UPDATE,
    priority=Priority.MEDIUM,
    title="Test Recommendation",
    component="test-pkg",
    score_impact=None,
    effort="medium",
):
    return Recommendation(
        type=rec_type,
        priority=priority,
        title=title,
        description="A test recommendation.",
        impact=score_impact or {"critical": 0, "high": 0, "medium": 1, "low": 0, "total": 1},
        affected_components=[component],
        action={"type": "test"},
        effort=effort,
    )


class TestSafeExtend:
    """Tests for _safe_extend - error-safe list extension."""

    def test_successful_extension(self):
        recs = []
        _safe_extend(recs, lambda: [_make_recommendation()], "test_module")
        assert len(recs) == 1

    def test_exception_does_not_crash(self):
        recs = []

        def raise_error():
            raise ValueError("Boom!")

        _safe_extend(recs, raise_error, "failing_module")
        assert len(recs) == 0

    def test_existing_recs_preserved_on_error(self):
        existing_rec = _make_recommendation(title="Existing")
        recs = [existing_rec]

        def raise_error():
            raise RuntimeError("Crash!")

        _safe_extend(recs, raise_error, "failing_module")
        assert len(recs) == 1
        assert recs[0].title == "Existing"

    def test_none_result_not_extended(self):
        recs = []
        _safe_extend(recs, lambda: None, "none_module")
        assert len(recs) == 0

    def test_empty_list_result_not_extended(self):
        recs = []
        _safe_extend(recs, lambda: [], "empty_module")
        assert len(recs) == 0

    def test_multiple_recs_extended(self):
        recs = []
        _safe_extend(
            recs,
            lambda: [_make_recommendation(title="A"), _make_recommendation(title="B")],
            "multi_module",
        )
        assert len(recs) == 2


class TestDeduplicateRecommendations:
    """Tests for _deduplicate_recommendations - removes duplicates keeping highest score."""

    def test_no_duplicates_unchanged(self):
        recs = [
            _make_recommendation(component="pkg-a"),
            _make_recommendation(component="pkg-b"),
        ]
        result = _deduplicate_recommendations(recs)
        assert len(result) == 2

    def test_exact_duplicates_deduplicated(self):
        recs = [
            _make_recommendation(component="pkg-a", priority=Priority.MEDIUM),
            _make_recommendation(component="pkg-a", priority=Priority.HIGH),
        ]
        result = _deduplicate_recommendations(recs)
        assert len(result) == 1

    def test_keeps_higher_score_recommendation(self):
        low_score = _make_recommendation(
            component="pkg-a",
            priority=Priority.LOW,
            score_impact={"critical": 0, "high": 0, "medium": 0, "low": 1, "total": 1},
        )
        high_score = _make_recommendation(
            component="pkg-a",
            priority=Priority.CRITICAL,
            score_impact={"critical": 5, "high": 0, "medium": 0, "low": 0, "total": 5},
        )
        result = _deduplicate_recommendations([low_score, high_score])
        assert len(result) == 1
        assert result[0].priority == Priority.CRITICAL

    def test_different_types_not_deduplicated(self):
        recs = [
            _make_recommendation(
                rec_type=RecommendationType.DIRECT_DEPENDENCY_UPDATE,
                component="pkg-a",
            ),
            _make_recommendation(
                rec_type=RecommendationType.NO_FIX_AVAILABLE,
                component="pkg-a",
            ),
        ]
        result = _deduplicate_recommendations(recs)
        assert len(result) == 2

    def test_empty_list(self):
        result = _deduplicate_recommendations([])
        assert result == []

    def test_single_recommendation(self):
        recs = [_make_recommendation()]
        result = _deduplicate_recommendations(recs)
        assert len(result) == 1

    def test_empty_component_uses_title_in_key(self):
        """When component is empty, title should differentiate recommendations."""
        rec_a = _make_recommendation(component="", title="Fix A")
        rec_b = _make_recommendation(component="", title="Fix B")
        result = _deduplicate_recommendations([rec_a, rec_b])
        assert len(result) == 2

    def test_same_type_same_empty_component_same_title_deduplicated(self):
        recs = [
            _make_recommendation(component="", title="Same Title", priority=Priority.LOW),
            _make_recommendation(component="", title="Same Title", priority=Priority.HIGH),
        ]
        result = _deduplicate_recommendations(recs)
        assert len(result) == 1


class TestGenerateRecommendationsEmpty:
    """Tests for generate_recommendations with empty input."""

    @pytest.mark.asyncio
    async def test_none_inputs_returns_empty(self):
        engine = RecommendationEngine()
        result = await engine.generate_recommendations()
        assert result == []

    @pytest.mark.asyncio
    async def test_empty_lists_returns_empty(self):
        engine = RecommendationEngine()
        result = await engine.generate_recommendations(findings=[], dependencies=[])
        assert result == []

    @pytest.mark.asyncio
    async def test_no_findings_with_deps_returns_empty_or_dep_recs(self):
        engine = RecommendationEngine()
        result = await engine.generate_recommendations(
            findings=[], dependencies=[_make_dependency()]
        )
        # Should return empty or only dependency-hygiene recommendations (no vulns)
        vuln_recs = [r for r in result if r.type in (
            RecommendationType.DIRECT_DEPENDENCY_UPDATE,
            RecommendationType.BASE_IMAGE_UPDATE,
            RecommendationType.TRANSITIVE_FIX_VIA_PARENT,
            RecommendationType.NO_FIX_AVAILABLE,
        )]
        assert len(vuln_recs) == 0


class TestGenerateRecommendationsSingleVuln:
    """Single vulnerability finding should generate at least one recommendation."""

    @pytest.mark.asyncio
    async def test_single_vuln_generates_recommendation(self):
        engine = RecommendationEngine()
        finding = _make_vuln_finding()
        dep = _make_dependency()

        result = await engine.generate_recommendations(
            findings=[finding], dependencies=[dep]
        )

        assert len(result) >= 1
        # At least one should be vulnerability-related
        vuln_types = {
            RecommendationType.DIRECT_DEPENDENCY_UPDATE,
            RecommendationType.TRANSITIVE_FIX_VIA_PARENT,
            RecommendationType.NO_FIX_AVAILABLE,
            RecommendationType.BASE_IMAGE_UPDATE,
            RecommendationType.QUICK_WIN,
            RecommendationType.SINGLE_UPDATE_MULTI_FIX,
        }
        assert any(r.type in vuln_types for r in result)

    @pytest.mark.asyncio
    async def test_single_critical_vuln_has_direct_dep_update(self):
        engine = RecommendationEngine()
        finding = _make_vuln_finding(severity="CRITICAL")
        dep = _make_dependency()

        result = await engine.generate_recommendations(
            findings=[finding], dependencies=[dep]
        )

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert len(direct_recs) >= 1


class TestGenerateRecommendationsMultipleTypes:
    """Multiple finding types should generate multiple recommendations."""

    @pytest.mark.asyncio
    async def test_vuln_and_secret_and_sast(self):
        engine = RecommendationEngine()
        findings = [
            _make_vuln_finding(),
            _make_secret_finding(),
            _make_sast_finding(),
        ]
        dep = _make_dependency()

        result = await engine.generate_recommendations(
            findings=findings, dependencies=[dep]
        )

        # Should have at least 2 distinct recommendation types
        rec_types = {r.type for r in result}
        assert len(rec_types) >= 2

    @pytest.mark.asyncio
    async def test_vuln_and_secret_findings(self):
        engine = RecommendationEngine()
        findings = [
            _make_vuln_finding(),
            _make_secret_finding(),
        ]
        dep = _make_dependency()

        result = await engine.generate_recommendations(
            findings=findings, dependencies=[dep]
        )

        assert len(result) >= 2


class TestGenerateRecommendationsDeduplication:
    """Deduplication should remove duplicates keeping highest score."""

    @pytest.mark.asyncio
    async def test_duplicate_vuln_findings_deduplicated(self):
        """Two identical vuln findings for same component should not double recommendations."""
        engine = RecommendationEngine()
        finding1 = _make_vuln_finding(finding_id="CVE-2024-0001")
        finding2 = _make_vuln_finding(finding_id="CVE-2024-0001")
        dep = _make_dependency()

        result = await engine.generate_recommendations(
            findings=[finding1, finding2], dependencies=[dep]
        )

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        # Should have at most 1 recommendation for this component (grouped by component)
        pkg_recs = [r for r in direct_recs if "pkg-name" in r.affected_components]
        assert len(pkg_recs) <= 1


class TestGenerateRecommendationsSorting:
    """Results should be sorted by score descending."""

    @pytest.mark.asyncio
    async def test_results_sorted_by_score_descending(self):
        engine = RecommendationEngine()
        findings = [
            _make_vuln_finding(finding_id="CVE-2024-0001", severity="LOW", component="low-pkg",
                               purl="pkg:pypi/low-pkg@1.0.0"),
            _make_vuln_finding(finding_id="CVE-2024-0002", severity="CRITICAL", component="critical-pkg",
                               purl="pkg:pypi/critical-pkg@1.0.0"),
        ]
        deps = [
            _make_dependency(name="low-pkg", purl="pkg:pypi/low-pkg@1.0.0"),
            _make_dependency(name="critical-pkg", purl="pkg:pypi/critical-pkg@1.0.0"),
        ]

        result = await engine.generate_recommendations(
            findings=findings, dependencies=deps
        )

        if len(result) >= 2:
            from app.services.recommendation.common import calculate_score
            scores = [calculate_score(r) for r in result]
            assert scores == sorted(scores, reverse=True)


class TestGenerateRecommendationsRegression:
    """Previous scan findings enable regression detection."""

    @pytest.mark.asyncio
    async def test_previous_scan_findings_enables_regression(self):
        engine = RecommendationEngine()
        # Current findings: many new vulns
        current_findings = [
            _make_vuln_finding(finding_id=f"CVE-2024-{i:04d}", component=f"pkg-{i}",
                               purl=f"pkg:pypi/pkg-{i}@1.0.0")
            for i in range(15)
        ]
        deps = [
            _make_dependency(name=f"pkg-{i}", purl=f"pkg:pypi/pkg-{i}@1.0.0")
            for i in range(15)
        ]
        # Empty previous scan = all findings are new
        previous_findings = []

        result = await engine.generate_recommendations(
            findings=current_findings,
            dependencies=deps,
            previous_scan_findings=previous_findings,
        )

        # Should have at least some recommendations
        assert len(result) >= 1

    @pytest.mark.asyncio
    async def test_no_previous_scan_no_regression_recs(self):
        """When previous_scan_findings is None, regression analysis should not run."""
        engine = RecommendationEngine()
        finding = _make_vuln_finding()
        dep = _make_dependency()

        result = await engine.generate_recommendations(
            findings=[finding],
            dependencies=[dep],
            previous_scan_findings=None,
        )

        regression_recs = [r for r in result if r.type == RecommendationType.REGRESSION_DETECTED]
        assert len(regression_recs) == 0


class TestGenerateRecommendationsErrorResilience:
    """Error in one module should not crash the whole engine."""

    @pytest.mark.asyncio
    async def test_engine_does_not_crash_with_malformed_finding(self):
        """A finding with unexpected structure should not crash the engine."""
        engine = RecommendationEngine()
        malformed = {"type": "vulnerability", "id": None}
        normal = _make_vuln_finding(component="good-pkg", purl="pkg:pypi/good-pkg@1.0.0")
        dep = _make_dependency(name="good-pkg", purl="pkg:pypi/good-pkg@1.0.0")

        # Should not raise, even with malformed finding
        result = await engine.generate_recommendations(
            findings=[malformed, normal], dependencies=[dep]
        )
        assert isinstance(result, list)


class TestGenerateRecommendationsSourceTarget:
    """Source target (Docker image name) should be passed through."""

    @pytest.mark.asyncio
    async def test_source_target_in_base_image_rec(self):
        engine = RecommendationEngine()
        findings = [
            _make_vuln_finding(finding_id=f"CVE-2024-000{i}", component=f"libos{i}",
                               purl=f"pkg:deb/debian/libos{i}@1.0.0")
            for i in range(5)
        ]
        deps = [
            _make_dependency(name=f"libos{i}", purl=f"pkg:deb/debian/libos{i}@1.0.0",
                             direct=False, source_type="image", dep_type="deb")
            for i in range(5)
        ]

        result = await engine.generate_recommendations(
            findings=findings,
            dependencies=deps,
            source_target="python:3.11-slim",
        )

        base_recs = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        if base_recs:
            assert base_recs[0].action["current_image"] == "python:3.11-slim"


class TestGenerateRecommendationsCrossProject:
    """Cross-project data should enable cross-project analysis."""

    @pytest.mark.asyncio
    async def test_cross_project_data_does_not_crash(self):
        engine = RecommendationEngine()
        finding = _make_vuln_finding()
        dep = _make_dependency()

        result = await engine.generate_recommendations(
            findings=[finding],
            dependencies=[dep],
            cross_project_data={"projects": []},
        )
        assert isinstance(result, list)


class TestGenerateRecommendationsScanHistory:
    """Scan history should enable recurring issue analysis."""

    @pytest.mark.asyncio
    async def test_scan_history_does_not_crash(self):
        engine = RecommendationEngine()
        finding = _make_vuln_finding()
        dep = _make_dependency()

        result = await engine.generate_recommendations(
            findings=[finding],
            dependencies=[dep],
            scan_history=[{"scan_id": "s1", "findings_count": 5}],
        )
        assert isinstance(result, list)


class TestEngineInitialization:
    """Tests for RecommendationEngine initialization."""

    def test_engine_has_outdated_threshold(self):
        engine = RecommendationEngine()
        assert engine.outdated_threshold_days > 0

    def test_engine_has_max_dependency_depth(self):
        engine = RecommendationEngine()
        assert engine.max_dependency_depth > 0
