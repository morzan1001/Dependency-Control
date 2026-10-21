from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import NON_RUNTIME_SCOPES
from app.schemas.recommendation import Effort, Priority, RecommendationType
from app.services.aggregation import ResultAggregator
from app.services.analyzers.end_of_life import EndOfLifeAnalyzer
from app.services.analyzers.outdated import OutdatedAnalyzer
from app.services.recommendation.dependencies import (
    analyze_dev_in_production,
    analyze_end_of_life,
    analyze_outdated_dependencies,
    analyze_version_fragmentation,
)
from tests.helpers.findings import stored_vulnerability


def _dep(name="requests", version="2.28.0", direct=True, scope=None, **extra):
    d = {
        "name": name,
        "version": version,
        "direct": direct,
        **extra,
    }
    if scope is not None:
        d["scope"] = scope
    return d


def _eol_finding(
    component="node",
    version="16.0.0",
    eol_date="2023-09-11",
    finding_id="eol1",
):
    details = {}
    if eol_date is not None:
        details["eol_date"] = eol_date
    return {
        "type": "eol",
        "severity": "HIGH",
        "component": component,
        "version": version,
        "details": details,
        "id": finding_id,
    }


class TestAnalyzeVersionFragmentationEmpty:
    def test_empty_returns_empty(self):
        assert analyze_version_fragmentation([]) == []


class TestAnalyzeVersionFragmentationSignificant:
    def test_three_versions_produces_recommendation(self):
        deps = [
            _dep(name="lodash", version="4.17.15"),
            _dep(name="lodash", version="4.17.20"),
            _dep(name="lodash", version="4.17.21"),
        ]
        result = analyze_version_fragmentation(deps)
        assert len(result) == 1

    def test_three_versions_type(self):
        deps = [_dep(name="lodash", version=f"4.17.{15 + i}") for i in range(3)]
        rec = analyze_version_fragmentation(deps)[0]
        assert rec.type == RecommendationType.VERSION_FRAGMENTATION

    def test_affected_components_name_the_package_and_the_action_counts_its_versions(self):
        deps = [_dep(name="lodash", version=f"4.17.{15 + i}") for i in range(3)]
        rec = analyze_version_fragmentation(deps)[0]
        assert rec.affected_components == ["lodash"]
        assert rec.action["packages"][0]["version_count"] == 3


class TestAnalyzeVersionFragmentationCuts:
    @staticmethod
    def _fragmented(packages: int, versions: int) -> list:
        return [_dep(name=f"pkg-{p}", version=f"1.0.{v}") for p in range(packages) for v in range(versions)]

    @pytest.mark.parametrize(("packages", "priority"), [(3, Priority.LOW), (4, Priority.MEDIUM)])
    def test_more_than_three_fragmented_packages_raise_the_priority(self, packages, priority):
        (rec,) = analyze_version_fragmentation(self._fragmented(packages, 3))
        assert rec.priority == priority

    def test_the_card_counts_packages_rather_than_findings(self):
        (rec,) = analyze_version_fragmentation(self._fragmented(2, 5))
        assert rec.impact == {"total": 0}
        assert rec.action["packages_total"] == 2


class TestAnalyzeVersionFragmentationBelowThreshold:
    def test_two_versions_no_recommendation(self):
        deps = [
            _dep(name="lodash", version="4.17.15"),
            _dep(name="lodash", version="4.17.20"),
        ]
        result = analyze_version_fragmentation(deps)
        assert len(result) == 0


class TestAnalyzeVersionFragmentationDifferentPackages:
    def test_different_packages_no_fragmentation(self):
        deps = [
            _dep(name="lodash", version="4.17.15"),
            _dep(name="express", version="4.18.0"),
            _dep(name="react", version="18.2.0"),
        ]
        result = analyze_version_fragmentation(deps)
        assert len(result) == 0


class TestAnalyzeVersionFragmentationCaseInsensitive:
    def test_case_insensitive_grouping(self):
        deps = [
            _dep(name="Lodash", version="4.17.15"),
            _dep(name="lodash", version="4.17.20"),
            _dep(name="LODASH", version="4.17.21"),
        ]
        result = analyze_version_fragmentation(deps)
        assert len(result) == 1


_NPM_DEDUPE = ["# For npm: npm dedupe", "# For yarn: yarn dedupe", "# For pnpm: pnpm dedupe"]
_MAVEN_PIN = "# For Maven/Gradle: pin one version in dependencyManagement or a dependency constraint"
_PIP_PIN = "# For pip: pin one version in a constraints file (pip install -c constraints.txt)"


class TestAnalyzeVersionFragmentationEcosystems:
    @staticmethod
    def _fragmented(*purl_types: str) -> list:
        return [
            _dep(name="foo", version=f"1.0.{v}", purl=f"pkg:{purl_type}/foo@1.0.{v}")
            for purl_type in purl_types
            for v in range(3)
        ]

    def test_each_package_names_its_ecosystem(self):
        [rec] = analyze_version_fragmentation(self._fragmented("npm", "pypi"))

        assert sorted((p["name"], p["type"]) for p in rec.action["packages"]) == [("foo", "npm"), ("foo", "pypi")]

    def test_same_named_packages_of_two_ecosystems_count_as_two_components(self):
        [rec] = analyze_version_fragmentation(self._fragmented("npm", "pypi"))

        assert (sorted(rec.affected_components), rec.affected_components_total) == (["foo (npm)", "foo (pypi)"], 2)

    @pytest.mark.parametrize(
        ("purl_types", "commands"),
        [
            pytest.param(("npm",), _NPM_DEDUPE, id="npm"),
            pytest.param(("maven",), [_MAVEN_PIN], id="maven"),
            pytest.param(("pypi",), [_PIP_PIN], id="pypi"),
            pytest.param(("pypi", "golang", "npm"), [*_NPM_DEDUPE, _PIP_PIN], id="mixed"),
        ],
    )
    def test_the_commands_follow_the_ecosystems_of_the_fragmented_packages(self, purl_types, commands):
        [rec] = analyze_version_fragmentation(self._fragmented(*purl_types))

        assert rec.action["commands"] == commands

    def test_an_ecosystem_without_a_dedupe_tool_gets_no_commands(self):
        [rec] = analyze_version_fragmentation(self._fragmented("golang", "deb"))

        assert "commands" not in rec.action


class TestAnalyzeDevInProductionEmpty:
    def test_empty_returns_empty(self):
        assert analyze_dev_in_production([]) == []


class TestAnalyzeDevInProductionFlagged:
    @pytest.mark.parametrize(
        ("name", "version"),
        [
            ("jest", "29.0.0"),
            ("mocha", "10.0.0"),
            ("eslint", "8.0.0"),
            ("prettier", "3.0.0"),
            ("@types/node", "20.0.0"),
            ("cypress", "13.0.0"),
            ("@playwright/test", "1.47.0"),
            ("@jest/globals", "29.0.0"),
            ("@cypress/webpack-preprocessor", "6.0.0"),
            ("@vitest/coverage-v8", "2.1.0"),
        ],
    )
    def test_a_dev_package_outside_a_dev_scope_is_flagged(self, name, version):
        rec = analyze_dev_in_production([_dep(name=name, version=version, type="npm")])

        assert len(rec) == 1
        assert rec[0].type == RecommendationType.DEV_IN_PRODUCTION

    def test_multiple_dev_deps_single_recommendation(self):
        deps = [
            _dep(name="jest", version="29.0.0", type="npm"),
            _dep(name="eslint", version="8.0.0", type="npm"),
        ]
        result = analyze_dev_in_production(deps)
        assert len(result) == 1
        assert result[0].impact == {"total": 0}
        assert result[0].affected_components_total == 2

    def test_a_scoped_package_split_into_group_and_name_is_flagged(self):
        # cdxgen writes @types/node as group "@types", name "node".
        rec = analyze_dev_in_production([_dep(name="node", group="@types", version="20.0.0", type="npm")])

        assert rec[0].action["packages"] == ["@types/node"]


class TestAnalyzeDevInProductionNotFlagged:
    @pytest.mark.parametrize("scope", sorted(NON_RUNTIME_SCOPES))
    def test_a_dev_package_inside_a_non_runtime_scope_is_not_flagged(self, scope):
        assert analyze_dev_in_production([_dep(name="jest", version="29.0.0", scope=scope, type="npm")]) == []

    @pytest.mark.parametrize(
        "name",
        [
            "langchain",
            "@langchain/openai",
            "keychain",
            "blockchain",
            "chainlit",
            "toolchain",
            "majestic",
            "eslint-scope",
        ],
    )
    def test_a_runtime_package_that_merely_contains_a_dev_tool_name_is_not_flagged(self, name):
        assert analyze_dev_in_production([_dep(name=name, version="1.0.0", type="npm")]) == []

    def test_a_package_outside_npm_is_not_checked(self):
        assert analyze_dev_in_production([_dep(name="pytest-mocha", version="1.0.0", type="pypi")]) == []

    def test_a_runtime_package_is_not_flagged(self):
        assert analyze_dev_in_production([_dep(name="express", version="4.18.0", type="npm")]) == []


class TestAnalyzeEndOfLifeEmpty:
    def test_empty_returns_empty(self):
        assert analyze_end_of_life([]) == []


def _graded_eol_findings(*days_past_eol):
    analyzer = EndOfLifeAnalyzer()
    issues = [
        analyzer._create_eol_issue(
            f"runtime-{i}",
            "1.0.0",
            f"runtime-{i}",
            {"cycle": "1", "eol": (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()},
            None,
            False,
        )
        for i, days in enumerate(days_past_eol)
    ]
    aggregator = ResultAggregator()
    aggregator.aggregate("end_of_life", {"eol_issues": issues})
    return [f.model_dump() for f in aggregator.get_findings()]


class TestAnalyzeEndOfLifePriority:
    def test_a_runtime_long_past_eol_ranks_the_card_high(self):
        rec = analyze_end_of_life(_graded_eol_findings(800))[0]
        assert rec.type == RecommendationType.EOL_DEPENDENCY
        assert rec.impact["high"] == 1
        assert rec.priority == Priority.HIGH

    @pytest.mark.parametrize("days_past_eol", [pytest.param(200, id="medium"), pytest.param(30, id="low")])
    def test_without_a_high_eol_finding_the_card_ranks_medium(self, days_past_eol):
        rec = analyze_end_of_life(_graded_eol_findings(days_past_eol))[0]
        assert rec.priority == Priority.MEDIUM


class TestAnalyzeEndOfLifeAffectedComponents:
    def test_eol_date_included_in_components(self):
        findings = [_eol_finding(component="node", version="16.0.0", eol_date="2023-09-11")]
        rec = analyze_end_of_life(findings)[0]
        assert "node@16.0.0 (EOL: 2023-09-11)" in rec.affected_components

    @pytest.mark.parametrize(
        "eol_date",
        [
            pytest.param(None, id="missing_date"),
            pytest.param("", id="empty_date"),
            pytest.param(True, id="undated_eol"),
        ],
    )
    def test_eol_without_a_date_is_just_name_version(self, eol_date):
        findings = [_eol_finding(component="node", version="16.0.0", eol_date=eol_date)]
        rec = analyze_end_of_life(findings)[0]
        assert rec.affected_components == ["node@16.0.0"]


class TestAnalyzeEndOfLifeMultiple:
    def test_multiple_eol_counted(self):
        findings = [
            _eol_finding(component="node", version="14.0.0", finding_id="eol1"),
            _eol_finding(component="python", version="3.7.0", finding_id="eol2"),
        ]
        rec = analyze_end_of_life(findings)[0]
        assert rec.impact["total"] == 2

    def test_one_high_finding_among_lower_ones_ranks_the_card_high(self):
        rec = analyze_end_of_life(_graded_eol_findings(30, 200, 800))[0]
        assert rec.priority == Priority.HIGH


class TestAnalyzeVersionFragmentationPackageIdentity:
    def test_scoped_packages_sharing_a_bare_name_are_not_one_fragmented_package(self):
        deps = [
            {**_dep(name="core", version="16.2.0"), "purl": "pkg:npm/%40angular/core@16.2.0"},
            {**_dep(name="core", version="7.23.0"), "purl": "pkg:npm/%40babel/core@7.23.0"},
            {**_dep(name="core", version="10.0.0"), "purl": "pkg:npm/%40nestjs/core@10.0.0"},
        ]

        assert analyze_version_fragmentation(deps) == []

    def test_the_card_names_the_qualified_package(self):
        deps = [
            {**_dep(name="core", version=version), "purl": f"pkg:npm/%40angular/core@{version}"}
            for version in ("15.0.0", "16.0.0", "17.0.0")
        ]

        rec = analyze_version_fragmentation(deps)[0]

        assert rec.action["packages"][0]["name"] == "@angular/core"


class TestHygieneCardsMatchTheQualifiedName:
    def test_a_scope_kept_in_the_purl_matches_a_scoped_dev_pattern(self):
        dep = {"name": "node", "version": "18.0.0", "purl": "pkg:npm/%40types/node@18.0.0"}

        [rec] = analyze_dev_in_production([dep])

        assert rec.affected_components == ["@types/node@18.0.0"]


def _outdated(*installs):
    analyzer = OutdatedAnalyzer()
    outdated, ahead = [], []
    for name, version, default in installs:
        component = {"name": name, "version": version, "purl": f"pkg:npm/{name}@{version}"}
        analyzer._classify_version(component, {"default": default, "stable": default}, outdated, ahead)
    aggregator = ResultAggregator()
    aggregator.aggregate("outdated_packages", {"outdated_dependencies": outdated, "ahead_of_default": ahead})
    return [f.model_dump() for f in aggregator.get_findings()]


class TestAnalyzeOutdatedDependencies:
    def test_an_outdated_direct_dependency_is_upgraded_to_the_registry_default(self):
        findings = _outdated(("express", "4.17.1", "4.21.2"))

        [rec] = analyze_outdated_dependencies(findings, [], [_dep("express", "4.17.1", direct=True)])

        assert (rec.type, rec.priority, rec.effort) == (
            RecommendationType.OUTDATED_DEPENDENCY,
            Priority.MEDIUM,
            Effort.MEDIUM,
        )
        assert rec.title == "Upgrade 1 outdated direct dependencies"
        assert (rec.affected_components, rec.impact["total"]) == (["express@4.17.1"], 1)
        assert rec.action == {
            "type": "upgrade_outdated",
            "packages": [{"name": "express", "current_version": "4.17.1", "latest_version": "4.21.2"}],
            "packages_total": 1,
        }

    def test_the_packages_are_listed_by_name_whatever_order_the_findings_are_read_in(self):
        installs = [("zod", "3.0.0", "3.24.1"), ("Zustand", "4.0.0", "5.0.2"), ("chalk", "4.1.2", "5.4.1")]
        findings = _outdated(*installs)
        dependencies = [_dep(name, version, direct=True) for name, version, _ in installs]

        [rec] = analyze_outdated_dependencies(findings[::-1], [], dependencies)

        assert [p["name"] for p in rec.action["packages"]] == ["chalk", "zod", "Zustand"]

    @pytest.mark.parametrize(("count", "cards"), [(3, 0), (4, 1)])
    def test_outdated_transitive_dependencies_earn_a_low_card_only_past_three(self, count, cards):
        findings = _outdated(*((f"sub-{i}", "1.0.0", "2.0.0") for i in range(count)))
        dependencies = [_dep(f"sub-{i}", "1.0.0", direct=False) for i in range(count)]

        recs = analyze_outdated_dependencies(findings, [], dependencies)

        assert [(r.priority, r.effort, r.title) for r in recs] == [
            (Priority.LOW, Effort.LOW, f"{count} transitive dependencies are outdated")
        ][:cards]

    def test_an_install_without_an_inventory_row_counts_as_transitive(self):
        findings = _outdated(*((f"sub-{i}", "1.0.0", "2.0.0") for i in range(4)))

        [rec] = analyze_outdated_dependencies(findings, [], [])

        assert rec.priority == Priority.LOW

    def test_an_install_newer_than_the_registry_default_is_not_outdated(self):
        findings = _outdated(("urllib3", "2.3.0", "2.2.3"))

        assert findings
        assert analyze_outdated_dependencies(findings, [], [_dep("urllib3", "2.3.0", direct=True)]) == []

    @pytest.mark.parametrize(
        "upgrading",
        [
            pytest.param(
                stored_vulnerability("org.yaml:snakeyaml", "1.33", [{"id": "CVE-2022-1471", "fixed_version": "2.0"}]),
                id="vulnerability",
            ),
            pytest.param(_eol_finding(component="snakeyaml", version="1.33"), id="end-of-life"),
        ],
    )
    def test_a_package_another_card_upgrades_is_left_to_that_card(self, upgrading):
        findings = _outdated(("snakeyaml", "1.33", "2.3"), ("jackson-core", "2.13.0", "2.18.2"))
        dependencies = [_dep("snakeyaml", "1.33", direct=True), _dep("jackson-core", "2.13.0", direct=True)]

        [rec] = analyze_outdated_dependencies(findings, [upgrading], dependencies)

        assert rec.affected_components == ["jackson-core@2.13.0"]

    def test_a_vulnerability_in_another_installed_version_leaves_this_one_outdated(self):
        findings = _outdated(("lodash", "4.17.15", "4.17.21"))
        vulnerable = stored_vulnerability("lodash", "4.17.10", [{"id": "CVE-2019-10744", "fixed_version": "4.17.12"}])

        [rec] = analyze_outdated_dependencies(findings, [vulnerable], [_dep("lodash", "4.17.15", direct=True)])

        assert rec.affected_components == ["lodash@4.17.15"]
