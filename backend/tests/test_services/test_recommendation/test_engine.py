"""Tests for app.services.recommendations."""

from app.schemas.recommendation import Effort, Priority, Recommendation, RecommendationType
from app.services.aggregation import ResultAggregator
from app.services.recommendation import risks
from app.services.recommendation.trends import PreviousScan
from app.services.recommendations import (
    RecommendationEngine,
    _deduplicate_recommendations,
    _safe_extend,
)


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
            "in_kev": is_kev,
            "epss_score": epss_score,
            "vulnerabilities": [
                {
                    "id": finding_id,
                    "severity": severity,
                    "fixed_version": fixed_version,
                    "in_kev": is_kev,
                    "epss_score": epss_score,
                }
            ],
            "reachability": {"is_reachable": reachable},
        },
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
    effort=Effort.MEDIUM,
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
    def test_successful_extension(self):
        recs = []
        _safe_extend(recs, lambda: [_make_recommendation()], "test_module")
        assert len(recs) == 1

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
        _safe_extend(recs, list, "empty_module")
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

    def test_same_type_component_different_titles_not_deduplicated(self):
        # Same type + first component but different titles must both survive.
        rec_a = _make_recommendation(
            rec_type=RecommendationType.SUPPLY_CHAIN_RISK,
            component="pkg-a",
            title="Replace Unmaintained Dependencies",
        )
        rec_b = _make_recommendation(
            rec_type=RecommendationType.SUPPLY_CHAIN_RISK,
            component="pkg-a",
            title="Review Low-Quality Dependencies",
        )
        result = _deduplicate_recommendations([rec_a, rec_b])
        assert len(result) == 2

    def test_same_type_component_title_different_action_not_deduplicated(self):
        # Same title + component but differing action['finding_type'] must not be merged.
        rec_a = _make_recommendation(
            rec_type=RecommendationType.ROTATE_CERTIFICATE,
            component="cert.pem",
            title="Rotate or fix certificate: cert.pem",
        )
        rec_a.action = {"finding_type": "crypto_cert_expired", "asset_name": "cert.pem"}
        rec_b = _make_recommendation(
            rec_type=RecommendationType.ROTATE_CERTIFICATE,
            component="cert.pem",
            title="Rotate or fix certificate: cert.pem",
        )
        rec_b.action = {"finding_type": "crypto_cert_self_signed", "asset_name": "cert.pem"}
        result = _deduplicate_recommendations([rec_a, rec_b])
        assert len(result) == 2

    def test_true_duplicates_still_merged(self):
        rec_a = _make_recommendation(
            rec_type=RecommendationType.ROTATE_CERTIFICATE,
            component="cert.pem",
            title="Rotate or fix certificate: cert.pem",
            priority=Priority.LOW,
        )
        rec_a.action = {"finding_type": "crypto_cert_expired", "asset_name": "cert.pem"}
        rec_b = _make_recommendation(
            rec_type=RecommendationType.ROTATE_CERTIFICATE,
            component="cert.pem",
            title="Rotate or fix certificate: cert.pem",
            priority=Priority.CRITICAL,
        )
        rec_b.action = {"finding_type": "crypto_cert_expired", "asset_name": "cert.pem"}
        result = _deduplicate_recommendations([rec_a, rec_b])
        assert len(result) == 1
        assert result[0].priority == Priority.CRITICAL


class TestGenerateRecommendationsEmpty:
    def test_none_inputs_returns_empty(self):
        engine = RecommendationEngine()
        result = engine.generate_recommendations()
        assert result == []

    def test_empty_lists_returns_empty(self):
        engine = RecommendationEngine()
        result = engine.generate_recommendations(findings=[], dependencies=[])
        assert result == []

    def test_no_findings_with_deps_returns_empty_or_dep_recs(self):
        engine = RecommendationEngine()
        result = engine.generate_recommendations(findings=[], dependencies=[_make_dependency()])
        vuln_recs = [
            r
            for r in result
            if r.type
            in (
                RecommendationType.DIRECT_DEPENDENCY_UPDATE,
                RecommendationType.BASE_IMAGE_UPDATE,
                RecommendationType.TRANSITIVE_FIX_VIA_PARENT,
                RecommendationType.NO_FIX_AVAILABLE,
            )
        ]
        assert len(vuln_recs) == 0


class TestGenerateRecommendationsSingleVuln:
    def test_single_vuln_generates_recommendation(self):
        engine = RecommendationEngine()
        finding = _make_vuln_finding()
        dep = _make_dependency()

        result = engine.generate_recommendations(findings=[finding], dependencies=[dep], join_dependencies=[dep])

        assert len(result) >= 1
        vuln_types = {
            RecommendationType.DIRECT_DEPENDENCY_UPDATE,
            RecommendationType.TRANSITIVE_FIX_VIA_PARENT,
            RecommendationType.NO_FIX_AVAILABLE,
            RecommendationType.BASE_IMAGE_UPDATE,
            RecommendationType.QUICK_WIN,
            RecommendationType.SINGLE_UPDATE_MULTI_FIX,
        }
        assert any(r.type in vuln_types for r in result)

    def test_single_critical_vuln_has_direct_dep_update(self):
        engine = RecommendationEngine()
        finding = _make_vuln_finding(severity="CRITICAL")
        dep = _make_dependency()

        result = engine.generate_recommendations(findings=[finding], dependencies=[dep], join_dependencies=[dep])

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        assert len(direct_recs) >= 1


class TestGenerateRecommendationsMultipleTypes:
    def test_vuln_and_secret_and_sast(self):
        engine = RecommendationEngine()
        findings = [
            _make_vuln_finding(),
            _make_secret_finding(),
            _make_sast_finding(),
        ]
        dep = _make_dependency()

        result = engine.generate_recommendations(findings=findings, dependencies=[dep], join_dependencies=[dep])

        rec_types = {r.type for r in result}
        assert len(rec_types) >= 2

    def test_vuln_and_secret_findings(self):
        engine = RecommendationEngine()
        findings = [
            _make_vuln_finding(),
            _make_secret_finding(),
        ]
        dep = _make_dependency()

        result = engine.generate_recommendations(findings=findings, dependencies=[dep], join_dependencies=[dep])

        assert len(result) >= 2


class TestGenerateRecommendationsDeduplication:
    def test_duplicate_vuln_findings_deduplicated(self):
        engine = RecommendationEngine()
        finding1 = _make_vuln_finding(finding_id="CVE-2024-0001")
        finding2 = _make_vuln_finding(finding_id="CVE-2024-0001")
        dep = _make_dependency()

        result = engine.generate_recommendations(
            findings=[finding1, finding2], dependencies=[dep], join_dependencies=[dep]
        )

        direct_recs = [r for r in result if r.type == RecommendationType.DIRECT_DEPENDENCY_UPDATE]
        pkg_recs = [r for r in direct_recs if "pkg-name" in r.affected_components]
        assert len(pkg_recs) <= 1


class TestGenerateRecommendationsSorting:
    def test_results_sorted_by_score_descending(self):
        engine = RecommendationEngine()
        findings = [
            _make_vuln_finding(
                finding_id="CVE-2024-0001", severity="LOW", component="low-pkg", purl="pkg:pypi/low-pkg@1.0.0"
            ),
            _make_vuln_finding(
                finding_id="CVE-2024-0002",
                severity="CRITICAL",
                component="critical-pkg",
                purl="pkg:pypi/critical-pkg@1.0.0",
            ),
        ]
        deps = [
            _make_dependency(name="low-pkg", purl="pkg:pypi/low-pkg@1.0.0"),
            _make_dependency(name="critical-pkg", purl="pkg:pypi/critical-pkg@1.0.0"),
        ]

        result = engine.generate_recommendations(findings=findings, dependencies=deps, join_dependencies=deps)

        if len(result) >= 2:
            from app.services.recommendation.common import calculate_score

            scores = [calculate_score(r) for r in result]
            assert scores == sorted(scores, reverse=True)


class TestGenerateRecommendationsRegression:
    def test_a_clean_previous_scan_raises_the_regression_card(self):
        finding = _make_vuln_finding(severity="CRITICAL")

        result = RecommendationEngine().generate_recommendations(findings=[finding], previous_scan=PreviousScan())

        assert RecommendationType.REGRESSION_DETECTED in {r.type for r in result}

    def test_no_previous_scan_no_regression_recs(self):
        finding = _make_vuln_finding(severity="CRITICAL")

        result = RecommendationEngine().generate_recommendations(findings=[finding], previous_scan=None)

        assert RecommendationType.REGRESSION_DETECTED not in {r.type for r in result}


class TestPackageRiskIsolation:
    def test_a_failing_toxic_card_keeps_the_hotspot_card(self, monkeypatch):
        def _fail(_packages):
            raise RuntimeError("toxic card failed")

        monkeypatch.setattr(risks, "detect_toxic_dependencies", _fail)
        finding = _make_vuln_finding(severity="CRITICAL", is_kev=True)

        result = RecommendationEngine().generate_recommendations(findings=[finding])

        assert RecommendationType.CRITICAL_HOTSPOT in {r.type for r in result}


class TestGenerateRecommendationsErrorResilience:
    def test_engine_does_not_crash_with_malformed_finding(self):
        engine = RecommendationEngine()
        malformed = {"type": "vulnerability", "id": None}
        normal = _make_vuln_finding(component="good-pkg", purl="pkg:pypi/good-pkg@1.0.0")
        dep = _make_dependency(name="good-pkg", purl="pkg:pypi/good-pkg@1.0.0")

        result = engine.generate_recommendations(
            findings=[malformed, normal], dependencies=[dep], join_dependencies=[dep]
        )
        assert (RecommendationType.DIRECT_DEPENDENCY_UPDATE, ["good-pkg@1.0.0"]) in [
            (r.type, r.affected_components) for r in result
        ]


class TestGenerateRecommendationsBaseImage:
    def test_the_image_rows_name_the_base_image(self):
        engine = RecommendationEngine()
        findings = [
            _make_vuln_finding(
                finding_id=f"CVE-2024-000{i}", component=f"libos{i}", purl=f"pkg:deb/debian/libos{i}@1.0.0"
            )
            for i in range(5)
        ]
        deps = [
            _make_dependency(
                name=f"libos{i}",
                purl=f"pkg:deb/debian/libos{i}@1.0.0",
                direct=False,
                source_type="image",
                dep_type="deb",
            )
            | {"source_target": "python:3.11-slim"}
            for i in range(5)
        ]

        result = engine.generate_recommendations(findings=findings, dependencies=deps, join_dependencies=deps)

        [base_rec] = [r for r in result if r.type == RecommendationType.BASE_IMAGE_UPDATE]
        assert base_rec.action["current_image"] == "python:3.11-slim"


class TestGenerateRecommendationsTyposquatting:
    # Typosquat findings are malware with details.imitated_package and produce TYPOSQUAT_DETECTED recs.

    @staticmethod
    def _make_typosquat_finding(component="reqeusts", imitated="requests", similarity=0.95):
        return {
            "id": f"TYPO-{component}",
            "type": "malware",
            "severity": "CRITICAL",
            "component": component,
            "version": "1.0.0",
            "details": {"imitated_package": imitated, "similarity": similarity},
            "aliases": [],
        }

    def test_malware_with_imitated_package_generates_typosquat_rec(self):
        engine = RecommendationEngine()
        finding = self._make_typosquat_finding()

        result = engine.generate_recommendations(findings=[finding], dependencies=[])

        typo_recs = [r for r in result if r.type == RecommendationType.TYPOSQUAT_DETECTED]
        assert len(typo_recs) == 1
        assert "reqeusts (looks like: requests)" in typo_recs[0].affected_components

    def test_plain_malware_does_not_generate_typosquat_rec(self):
        engine = RecommendationEngine()
        finding = {
            "id": "MAL-001",
            "type": "malware",
            "severity": "CRITICAL",
            "component": "evil-pkg",
            "version": "1.0.0",
            "details": {},
            "aliases": [],
        }

        result = engine.generate_recommendations(findings=[finding], dependencies=[])

        typo_recs = [r for r in result if r.type == RecommendationType.TYPOSQUAT_DETECTED]
        assert len(typo_recs) == 0
        assert any(r.type == RecommendationType.MALWARE_DETECTED for r in result)


def _produced(**analyzer_results):
    aggregator = ResultAggregator()
    for analyzer, result in analyzer_results.items():
        aggregator.aggregate(analyzer, result)
    return [f.model_dump() for f in aggregator.get_findings()]


_HASH_ISSUE = {
    "component": "left-pad",
    "version": "1.3.0",
    "registry": "npm",
    "algorithm": "SHA-512",
    "sbom_hash": "3f1a",
    "expected_hashes": ["9c2e"],
    "severity": "CRITICAL",
    "message": "Hash mismatch detected! Package may be tampered.",
}
_MALWARE_ISSUE = {
    "component": "evil-pkg",
    "version": "1.0.0",
    "severity": "CRITICAL",
    "malware_info": {"malicious": True, "threats": ["credential-theft"], "description": "Exfiltrates npm tokens"},
}
_EOL_ISSUE = {
    "component": "evil-pkg",
    "version": "1.0.0",
    "product": "evil-pkg",
    "severity": "HIGH",
    "eol_info": {"cycle": "1", "eol": "2020-01-01", "latest": "1.9.0"},
    "distro_build": False,
}
_TYPOSQUAT_ISSUE = {
    "component": "reqeusts",
    "version": "2.31.0",
    "imitated_package": "requests",
    "similarity": 0.92,
    "severity": "HIGH",
    "message": "Possible typosquatting detected! 'reqeusts' is 92.0% similar to popular package 'requests'",
}


class TestMalwareSignalsGetTheirOwnCards:
    def test_a_failed_hash_check_is_an_integrity_card_not_malware(self):
        findings = _produced(hash_verification={"hash_issues": [_HASH_ISSUE]})

        types = {r.type for r in RecommendationEngine().generate_recommendations(findings=findings)}

        assert RecommendationType.HASH_MISMATCH in types
        assert RecommendationType.MALWARE_DETECTED not in types
        assert RecommendationType.CRITICAL_HOTSPOT not in types

    def test_a_typosquat_is_not_reported_as_known_malware(self):
        findings = _produced(typosquatting={"typosquatting_issues": [_TYPOSQUAT_ISSUE]})

        types = {r.type for r in RecommendationEngine().generate_recommendations(findings=findings)}

        assert RecommendationType.TYPOSQUAT_DETECTED in types
        assert RecommendationType.MALWARE_DETECTED not in types
        assert RecommendationType.CRITICAL_HOTSPOT not in types

    def test_a_malware_package_gets_one_playbook_and_no_toxic_card(self):
        findings = _produced(os_malware={"malware_issues": [_MALWARE_ISSUE]}, end_of_life={"eol_issues": [_EOL_ISSUE]})

        by_type = {r.type: r for r in RecommendationEngine().generate_recommendations(findings=findings)}

        assert RecommendationType.TOXIC_DEPENDENCY not in by_type
        malware, hotspot = by_type[RecommendationType.MALWARE_DETECTED], by_type[RecommendationType.CRITICAL_HOTSPOT]
        assert malware.action["steps"] == hotspot.action["steps"]
        assert malware.effort == hotspot.effort == "low"


def test_every_generated_card_carries_an_effort_member():
    findings = [
        *_produced(
            hash_verification={"hash_issues": [_HASH_ISSUE]},
            os_malware={"malware_issues": [_MALWARE_ISSUE]},
            end_of_life={"eol_issues": [_EOL_ISSUE]},
            typosquatting={"typosquatting_issues": [_TYPOSQUAT_ISSUE]},
        ),
        _make_vuln_finding(),
        _make_secret_finding(),
        _make_sast_finding(),
    ]
    dep = _make_dependency()

    result = RecommendationEngine().generate_recommendations(
        findings=findings, dependencies=[dep], join_dependencies=[dep]
    )

    assert len({r.type for r in result}) >= 6
    assert {type(r.effort) for r in result} == {Effort}


class TestTyposquatCollection:
    """The typosquatting analyzer stores the imitated name under details.imitated_package
    (2,572 production findings; zero carry a details.similar_to)."""

    @staticmethod
    def _malware_finding(component, imitated_package=None):
        details = {"info": {"id": "MAL-2026-1"}}
        if imitated_package:
            details["imitated_package"] = imitated_package
        return {"type": "malware", "severity": "CRITICAL", "component": component, "details": details}

    def test_imitated_package_reaches_the_recommendation(self):
        engine = RecommendationEngine()
        findings = [self._malware_finding("loadsh", imitated_package="lodash")]

        recs = engine.generate_recommendations(findings=findings)

        typosquat = next(r for r in recs if r.type == RecommendationType.TYPOSQUAT_DETECTED)
        assert "loadsh (looks like: lodash)" in typosquat.affected_components

    def test_plain_malware_raises_no_typosquat_recommendation(self):
        engine = RecommendationEngine()

        recs = engine.generate_recommendations(findings=[self._malware_finding("evil-pkg")])

        assert not [r for r in recs if r.type == RecommendationType.TYPOSQUAT_DETECTED]


class TestOnePackageAcrossCardTypes:
    @staticmethod
    def _dep(name, version, direct):
        return {"name": name, "version": version, "purl": f"pkg:npm/{name}@{version}", "direct": direct}

    def test_two_installed_versions_survive_deduplication_as_two_update_cards(self):
        findings = [
            _make_vuln_finding("CVE-1", component="minimist", version="0.0.8", fixed_version="0.2.1"),
            _make_vuln_finding("CVE-2", component="minimist", version="1.2.0", fixed_version="1.2.6"),
        ]
        deps = [self._dep("minimist", "0.0.8", False), self._dep("minimist", "1.2.0", False)]

        result = RecommendationEngine().generate_recommendations(
            findings=findings, dependencies=deps, join_dependencies=deps
        )

        transitive = [r for r in result if r.type == RecommendationType.TRANSITIVE_FIX_VIA_PARENT]
        assert sorted(r.affected_components[0] for r in transitive) == ["minimist@0.0.8", "minimist@1.2.0"]

    def test_unreachable_criticals_put_the_hotspot_and_the_update_on_one_tier(self):
        findings = [
            _make_vuln_finding(f"CVE-{v}", severity="CRITICAL", component="lib", version=v, reachable=False)
            for v in ("1.0.0", "1.1.0", "1.2.0")
        ]
        deps = [self._dep("lib", v, True) for v in ("1.0.0", "1.1.0", "1.2.0")]

        result = RecommendationEngine().generate_recommendations(
            findings=findings, dependencies=deps, join_dependencies=deps
        )

        tiers = {
            r.priority
            for r in result
            if r.type in (RecommendationType.CRITICAL_HOTSPOT, RecommendationType.DIRECT_DEPENDENCY_UPDATE)
        }
        assert tiers == {Priority.HIGH}


def test_the_kev_card_names_the_cve_the_live_threat_intel_marks():
    from app.schemas.enrichment import VulnerabilityEnrichment

    finding = _make_vuln_finding(component="openssl-libs", is_kev=True)
    finding["details"]["vulnerabilities"] = [
        {"id": "CVE-2023-0001", "aliases": ["ALAS2-2023-2001", "CVE-2023-0002"], "in_kev": True}
    ]
    threat_intel = {
        "CVE-2023-0001": VulnerabilityEnrichment(cve="CVE-2023-0001", risk_score=20.0),
        "CVE-2023-0002": VulnerabilityEnrichment(cve="CVE-2023-0002", risk_score=40.0, is_kev=True),
    }

    result = RecommendationEngine().generate_recommendations(findings=[finding], threat_intel=threat_intel)

    [kev_card] = [r for r in result if r.type == RecommendationType.KNOWN_EXPLOIT]
    assert kev_card.action["cves"] == ["CVE-2023-0002"]
