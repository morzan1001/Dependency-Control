"""Vulnerability findings must be keyed by package identity, not by the bare artifact name.

Fixtures mirror real prod shapes: npm components arrive scoped from trivy/grype
(``@angular/core``) and bare from the OSV path (the CycloneDX ``name`` field with the
``group`` split off), Maven components arrive as ``group:artifact`` from trivy and bare
from grype.
"""

import pytest

from app.models.finding import Finding, FindingType, Severity
from app.services.aggregation import ResultAggregator


def _vuln(component: str, version: str, vuln_id: str, scanner: str, severity=Severity.HIGH) -> Finding:
    return Finding(
        id=vuln_id,
        type=FindingType.VULNERABILITY,
        severity=severity,
        component=component,
        version=version,
        description=f"{vuln_id} in {component}",
        scanners=[scanner],
        details={"fixed_version": None, "references": []},
    )


def _components(aggregator: ResultAggregator) -> dict[str, list[str]]:
    """{component: [entry ids]} of the aggregated vulnerability findings."""
    return {
        f.component: sorted(v["id"] for v in f.details.get("vulnerabilities", []))
        for f in aggregator.get_findings()
        if f.type == FindingType.VULNERABILITY
    }


class TestDistinctPackagesStaySeparate:
    def test_two_npm_scopes_sharing_a_last_segment(self):
        """@angular/core and @angular-devkit/core at the same version are different packages."""
        agg = ResultAggregator()
        agg.add_finding(_vuln("@angular/core", "21.1.5", "CVE-2026-50557", "trivy"))
        agg.add_finding(_vuln("@angular-devkit/core", "21.1.5", "CVE-2026-11111", "trivy"))

        assert _components(agg) == {
            "@angular/core": ["CVE-2026-50557"],
            "@angular-devkit/core": ["CVE-2026-11111"],
        }

    def test_two_maven_groups_sharing_an_artifact_id(self):
        agg = ResultAggregator()
        agg.add_finding(_vuln("com.fasterxml.jackson.core:jackson-databind", "3.1.4", "CVE-2026-1", "trivy"))
        agg.add_finding(_vuln("tools.jackson.core:jackson-databind", "3.1.4", "CVE-2026-2", "trivy"))

        assert _components(agg) == {
            "com.fasterxml.jackson.core:jackson-databind": ["CVE-2026-1"],
            "tools.jackson.core:jackson-databind": ["CVE-2026-2"],
        }

    def test_bare_name_is_not_guessed_onto_one_of_several_scopes(self):
        """Three prod packages are all named 'core'; an unqualified report must stay on its own."""
        agg = ResultAggregator()
        agg.add_finding(_vuln("@angular/core", "21.1.5", "CVE-2026-50557", "trivy"))
        agg.add_finding(_vuln("@messageformat/core", "21.1.5", "CVE-2026-22222", "trivy"))
        agg.add_finding(_vuln("core", "21.1.5", "CVE-2026-33333", "osv"))

        assert _components(agg) == {
            "@angular/core": ["CVE-2026-50557"],
            "@messageformat/core": ["CVE-2026-22222"],
            "core": ["CVE-2026-33333"],
        }

    def test_unrelated_packages_are_not_cross_linked(self):
        agg = ResultAggregator()
        agg.add_finding(_vuln("@angular/core", "21.1.5", "CVE-2026-50557", "trivy"))
        agg.add_finding(_vuln("@angular-devkit/core", "21.1.5", "CVE-2026-11111", "trivy"))

        for finding in agg.get_findings():
            assert finding.related_findings == []

    @pytest.mark.parametrize(
        ("first", "second"),
        [
            ("src/a/util.js", "src/b/util.js"),
            ("util.js", "src/util.js"),
            ("Dockerfile", "deploy/Dockerfile"),
            ("Dockerfile", "dockerfile"),
        ],
    )
    def test_same_named_files_stay_unlinked(self, first, second):
        """File-anchored findings carry a path; two paths are two files, whatever they end in."""
        agg = ResultAggregator()
        agg.add_finding(_file_finding("SECRET-a", FindingType.SECRET, first))
        agg.add_finding(_file_finding("IAC-b", FindingType.IAC, second))

        for finding in agg.get_findings():
            assert finding.related_findings == []
            assert "additional_finding_types" not in finding.details

    def test_a_package_and_a_vendored_file_of_the_same_name_stay_unlinked(self):
        agg = ResultAggregator()
        agg.add_finding(_vuln("chart.js", "2.9.3", "CVE-2020-7746", "trivy"))
        agg.add_finding(_file_finding("SECRET-v", FindingType.SECRET, "static/vendor/chart.js"))

        for finding in agg.get_findings():
            assert finding.related_findings == []

    def test_the_same_file_links_across_file_anchored_types(self):
        agg = ResultAggregator()
        agg.add_finding(_file_finding("SECRET-a", FindingType.SECRET, "app/config.py"))
        agg.add_finding(_file_finding("IAC-a", FindingType.IAC, "app/config.py"))

        secret = next(f for f in agg.get_findings() if f.type == FindingType.SECRET)
        assert secret.related_findings == ["IAC-a"]


def _file_finding(finding_id: str, finding_type: FindingType, path: str) -> Finding:
    return Finding(
        id=finding_id,
        type=finding_type,
        severity=Severity.HIGH,
        component=path,
        version="",
        description="file finding",
        scanners=["scanner"],
    )


class TestMostQualifiedNameWins:
    def test_maven_coordinates_survive_the_bare_artifact_id(self):
        agg = ResultAggregator()
        agg.add_finding(_vuln("postgresql", "42.7.3", "CVE-2024-1597", "grype"))
        agg.add_finding(_vuln("org.postgresql:postgresql", "42.7.3", "CVE-2024-1597", "trivy"))

        findings = [f for f in agg.get_findings() if f.type == FindingType.VULNERABILITY]
        assert len(findings) == 1
        assert findings[0].component == "org.postgresql:postgresql"
        assert "postgresql:42.7.3" in findings[0].aliases

    def test_related_findings_still_link_across_qualification(self):
        """An outdated finding on the bare dependency name links to the qualified vulnerability."""
        agg = ResultAggregator()
        agg.add_finding(_vuln("org.postgresql:postgresql", "42.7.3", "CVE-2024-1597", "trivy"))
        agg.add_finding(_outdated("postgresql", "42.7.3", "42.7.4"))

        findings = agg.get_findings()
        vuln = next(f for f in findings if f.type == FindingType.VULNERABILITY)
        outdated = next(f for f in findings if f.type == FindingType.OUTDATED)
        assert outdated.id in vuln.related_findings
        assert vuln.id in outdated.related_findings

    def test_a_type_definition_package_is_not_linked_to_its_runtime_package(self):
        agg = ResultAggregator()
        agg.add_finding(_vuln("lodash", "4.17.15", "CVE-2020-8203", "trivy"))
        agg.add_finding(_outdated("lodash", "4.17.15", "4.17.21"))
        agg.add_finding(_outdated("@types/lodash", "4.14.100", "4.17.20"))

        findings = agg.get_findings()
        vuln = next(f for f in findings if f.type == FindingType.VULNERABILITY)
        types_outdated = next(f for f in findings if f.component == "@types/lodash")
        assert vuln.details["outdated_info"]["current_version"] == "4.17.15"
        assert types_outdated.id not in vuln.related_findings
        assert "vulnerability_info" not in types_outdated.details


def _outdated(component: str, version: str, latest: str) -> Finding:
    return Finding(
        id=f"OUTDATED-{component}",
        type=FindingType.OUTDATED,
        severity=Severity.INFO,
        component=component,
        version=version,
        description="outdated",
        scanners=["outdated_packages"],
        details={"current_version": version, "latest_version": latest, "fixed_version": latest},
    )


class TestPackageNameWaiverTargetsOnePackage:
    def test_waiver_query_hits_the_qualified_component_only(self):
        """A waiver created from an @angular/core finding must not waive @angular-devkit/core."""
        import asyncio

        from app.models.waiver import Waiver
        from app.repositories.findings import FindingRepository
        from app.services.stats import _build_waiver_query
        from tests.mocks.fake_mongo import FakeDatabase

        agg = ResultAggregator()
        agg.add_finding(_vuln("core", "21.1.5", "CVE-2026-50557", "osv"))
        agg.add_finding(_vuln("@angular/core", "21.1.5", "CVE-2026-50557", "trivy"))
        agg.add_finding(_vuln("@angular-devkit/core", "21.1.5", "CVE-2026-11111", "trivy"))

        db = FakeDatabase()
        for finding in agg.get_findings():
            record = finding.model_dump()
            record["_id"] = f"{finding.component}:{finding.version}"
            record["scan_id"] = "scan-1"
            record["finding_id"] = finding.id
            record["waived"] = False
            asyncio.run(db.findings.insert_one(record))

        waiver = Waiver(
            reason="reviewed",
            created_by="u",
            finding_type="vulnerability",
            package_name="@angular/core",
            package_version="21.1.5",
        )
        repo = FindingRepository(db)
        modified = asyncio.run(
            repo.apply_finding_waiver("scan-1", _build_waiver_query(waiver), waived=True, waiver_reason="reviewed")
        )

        assert modified == 1
        waived = asyncio.run(db.findings.find({"scan_id": "scan-1", "waived": True}).to_list(None))
        assert [d["component"] for d in waived] == ["@angular/core"]


class TestVersionSpellingDoesNotSplitAFinding:
    def test_an_outdated_finding_with_and_without_a_v_prefix_is_one_finding(self):
        agg = ResultAggregator()
        for version in ("v1.2.3", "1.2.3"):
            agg.add_finding(_outdated("github.com/x/y", version, "1.3.0"))

        assert [f.version for f in agg.get_findings()] == ["v1.2.3"]
