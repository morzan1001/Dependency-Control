"""One SPDX expression grammar from SBOM licence entries to the licence verdict."""

import asyncio
import time
from typing import Any

import pytest

from app.models.finding import Severity
from app.models.license import LicenseCategory
from app.services.aggregation.aggregator import ResultAggregator
from app.services.analyzers.license_compliance import LicenseAnalyzer, normalizer
from app.services.analyzers.license_compliance.compatibility import check_license_compatibility, partition_or_groups
from app.services.inventory.licenses import license_ids
from app.services.sbom_parser import parse_sbom

_GPL_AND_CHOICE = "GPL-3.0-only AND (MIT OR Apache-2.0)"


def _parsed(sbom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {dep.name: dep.model_dump() for dep in parse_sbom(sbom).dependencies}


def _analyze(components: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = asyncio.run(LicenseAnalyzer().analyze({}, parsed_components=components))
    return result


def _issues(result: dict[str, Any], category: LicenseCategory) -> list[dict[str, Any]]:
    return [issue for issue in result["license_issues"] if issue["category"] == category.value]


def _cyclonedx(components: list[dict[str, Any]]) -> dict[str, Any]:
    """Shaped like syft's and cyclonedx-npm's CycloneDX 1.5 JSON output."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:0b9d5b3e-7a3c-4a55-9b8e-2f0d8c1e6a11",
        "version": 1,
        "metadata": {
            "timestamp": "2026-09-01T10:00:00Z",
            "tools": {
                "components": [{"type": "application", "author": "anchore", "name": "syft", "version": "1.14.0"}]
            },
            "component": {"bom-ref": "root", "type": "file", "name": "/src"},
        },
        "components": components,
    }


_CYCLONEDX = _cyclonedx(
    [
        {
            "bom-ref": "pkg:pypi/mixed-lib@1.0?package-id=aa11",
            "type": "library",
            "name": "mixed-lib",
            "version": "1.0",
            # syft puts a plain id in license.id and an expression beside it
            "licenses": [{"license": {"id": "GPL-3.0-only"}}, {"expression": "MIT OR Apache-2.0"}],
            "purl": "pkg:pypi/mixed-lib@1.0",
        },
        {
            "bom-ref": "pkg:rpm/redhat/libchoice@2.1?package-id=bb22",
            "type": "library",
            "name": "libchoice",
            "version": "2.1",
            "licenses": [{"expression": _GPL_AND_CHOICE}],
            "purl": "pkg:rpm/redhat/libchoice@2.1",
        },
        {
            "bom-ref": "jquery@1.8.3",
            "type": "library",
            "name": "jquery",
            "version": "1.8.3",
            # cyclonedx-npm writes one entry per element of a legacy package.json licenses array
            "licenses": [{"license": {"id": "MIT"}}, {"license": {"id": "GPL-2.0-only"}}],
            "purl": "pkg:npm/jquery@1.8.3",
        },
        {
            "bom-ref": "pkg:pypi/twice-mit@3.0?package-id=cc33",
            "type": "library",
            "name": "twice-mit",
            "version": "3.0",
            "licenses": [{"license": {"id": "MIT"}}, {"expression": "MIT"}],
            "purl": "pkg:pypi/twice-mit@3.0",
        },
        {
            "bom-ref": "pkg:npm/private-app@0.1.0",
            "type": "library",
            "name": "private-app",
            "version": "0.1.0",
            "licenses": [{"license": {"name": "UNLICENSED"}}],
            "purl": "pkg:npm/private-app@0.1.0",
        },
    ]
)


def _syft_licence(value: str, spdx: str = "", urls: list[str] | None = None) -> dict[str, Any]:
    return {
        "value": value,
        "spdxExpression": spdx,
        "type": "declared",
        "urls": urls or [],
        "locations": [{"path": "/app/lib/pkg.jar", "annotations": {"evidence": "primary"}}],
    }


def _syft_artifact(name: str, purl: str, licenses: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": f"{name}-id",
        "name": name,
        "version": "1.0",
        "type": "java-archive",
        "foundBy": "java-archive-cataloger",
        "locations": [{"path": f"/app/lib/{name}.jar"}],
        "licenses": licenses,
        "language": "java",
        "cpes": [],
        "purl": purl,
    }


_SYFT = {
    "descriptor": {"name": "syft", "version": "1.14.0"},
    "schema": {"version": "16.0.18"},
    "source": {"type": "directory", "target": "/app"},
    "artifactRelationships": [],
    "artifacts": [
        _syft_artifact(
            "commons-io",
            "pkg:maven/commons-io/commons-io@1.0",
            [_syft_licence("Apache License, Version 2.0", urls=["https://www.apache.org/licenses/LICENSE-2.0.txt"])],
        ),
        _syft_artifact(
            "jnr-posix",
            "pkg:maven/com.github.jnr/jnr-posix@1.0",
            [
                _syft_licence("Eclipse Public License - v 2.0", "EPL-2.0"),
                _syft_licence("GNU General Public License Version 2", "GPL-2.0-only"),
                _syft_licence("GNU Lesser General Public License Version 2.1", "LGPL-2.1-only"),
            ],
        ),
        _syft_artifact(
            "url-only",
            "pkg:maven/org.example/url-only@1.0",
            [_syft_licence("", urls=["https://www.apache.org/licenses/LICENSE-2.0.txt"])],
        ),
        _syft_artifact("no-licence-data", "pkg:maven/org.example/no-licence-data@1.0", [_syft_licence("")]),
        {
            **_syft_artifact(
                "libc6",
                "pkg:deb/debian/libc6@1.0?arch=amd64",
                [_syft_licence("GPL-2.0-only", "GPL-2.0-only"), _syft_licence("LGPL-2.1-only", "LGPL-2.1-only")],
            ),
            "type": "deb",
        },
    ],
}


def _spdx_package(spdx_id: str, name: str, declared: str) -> dict[str, Any]:
    return {
        "name": name,
        "SPDXID": spdx_id,
        "versionInfo": "2.6",
        "supplier": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": declared,
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:maven/{name}/{name}@2.6",
            }
        ],
    }


_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "/app",
    "documentNamespace": "https://anchore.com/syft/dir/app-5c1f",
    "creationInfo": {
        "creators": ["Organization: Anchore, Inc", "Tool: syft-1.14.0"],
        "created": "2026-09-01T10:00:00Z",
    },
    "packages": [
        # syft: the id is the sanitised name, extractedText the name itself
        _spdx_package("SPDXRef-Package-1", "commons-lang", "LicenseRef-The-Apache-Software-License--Version-2.0"),
        _spdx_package("SPDXRef-Package-2", "compound", "MIT AND LicenseRef-BSD-3-Clause-License"),
        # trivy: a hashed id, the name in `name`, a sentence in extractedText
        _spdx_package("SPDXRef-Package-3", "trivy-style", "LicenseRef-8a1d1e2b5f6c3a4b"),
        _spdx_package("SPDXRef-Package-4", "vendor-lib", "LicenseRef-Acme-EULA"),
    ],
    "hasExtractedLicensingInfos": [
        {
            "licenseId": "LicenseRef-The-Apache-Software-License--Version-2.0",
            "extractedText": "The Apache Software License, Version 2.0",
        },
        {"licenseId": "LicenseRef-BSD-3-Clause-License", "extractedText": "BSD 3-Clause License"},
        {
            "licenseId": "LicenseRef-8a1d1e2b5f6c3a4b",
            "name": "Apache License 2.0",
            "extractedText": 'This component is licensed under "Apache License 2.0"',
        },
        {"licenseId": "LicenseRef-Acme-EULA", "extractedText": "Acme End User Licence Agreement"},
    ],
    "relationships": [],
}


class TestParseLicenseExpression:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (_GPL_AND_CHOICE, [["GPL-3.0-only", "MIT"], ["GPL-3.0-only", "Apache-2.0"]]),
            ("(MIT OR Apache-2.0) AND GPL-3.0-only", [["MIT", "GPL-3.0-only"], ["Apache-2.0", "GPL-3.0-only"]]),
            (
                "(GPL-2.0-only WITH Classpath-exception-2.0) AND (MIT OR Apache-2.0)",
                [
                    ["GPL-2.0-only WITH Classpath-exception-2.0", "MIT"],
                    ["GPL-2.0-only WITH Classpath-exception-2.0", "Apache-2.0"],
                ],
            ),
            ("((MIT OR (ISC AND Apache-2.0)))", [["MIT"], ["ISC", "Apache-2.0"]]),
            ("MIT OR MIT", [["MIT"]]),
            ("mit AND gpl-2.0+", [["MIT", "GPL-2.0-or-later"]]),
            ("Apache License, Version 2.0", [["Apache-2.0"]]),
            ("MIT, ISC", [["MIT", "ISC"]]),
            ("MIT AND NOASSERTION", [["MIT"]]),
            ("(MIT OR NOASSERTION) AND ISC", [["MIT", "ISC"]]),
            ("NOASSERTION", []),
            ("", []),
            ("UNLICENSED", [["UNLICENSED"]]),
            (
                "GPL-2.0-only AND Common Development and Distribution License (CDDL) v1.0",
                [["GPL-2.0-only", "Common Development and Distribution License (CDDL) v1.0"]],
            ),
            ("(Eclipse Distribution License (EDL) OR MIT)", [["Eclipse Distribution License (EDL)"], ["MIT"]]),
            ("MIT OR (Apache-2.0", [["MIT OR (Apache-2.0"]]),
            ("MIT AND OR ISC", [["MIT AND OR ISC"]]),
        ],
    )
    def test_the_expression_reads_as_its_alternatives(self, raw, expected):
        assert normalizer.parse_license_expression(raw) == expected

    def test_an_expansion_past_the_bound_reads_as_one_term(self):
        raw = " AND ".join(f"(MIT OR Apache-{i})" for i in range(30))
        started = time.perf_counter()
        groups = normalizer.parse_license_expression(raw)
        assert time.perf_counter() - started < 1.0
        assert groups == [[raw]]

    def test_deep_nesting_reads_as_one_term_instead_of_raising(self):
        raw = "(" * 5000 + "MIT" + ")" * 5000
        assert normalizer.parse_license_expression(raw) == [[raw]]

    def test_a_long_whitespace_run_parses_in_linear_time(self):
        raw = "MIT" + " " * 50_000 + "OR" + " " * 50_000 + "Apache-2.0"
        started = time.perf_counter()
        groups = normalizer.parse_license_expression(raw)
        assert time.perf_counter() - started < 1.0
        assert groups == [["MIT"], ["Apache-2.0"]]


def test_the_or_partition_returns_the_ids_it_checked():
    groups = normalizer.parse_license_expression("(gpl-2.0-only WITH Classpath-exception-2.0) OR mit OR Acme-1.0")
    assert partition_or_groups(groups) == ([["GPL-2.0-only"], ["MIT"]], ["Acme-1.0"])


def test_inventory_keeps_a_with_exception_on_its_licence():
    assert license_ids("(MIT OR Apache-2.0) AND LGPL-2.1-or-later WITH GCC-exception-2.0") == [
        "MIT",
        "LGPL-2.1-or-later WITH GCC-exception-2.0",
        "Apache-2.0",
    ]


def test_a_deps_dev_expression_with_an_exception_stays_plausible():
    value = "GPL-2.0-only WITH Classpath-exception-2.0"
    assert ResultAggregator._sanitize_deps_dev_license(value) == value


class TestCycloneDX:
    def setup_method(self):
        self.deps = _parsed(_CYCLONEDX)

    def test_separate_entries_join_as_spdx_and_keeping_the_expression_whole(self):
        assert self.deps["mixed-lib"]["license"] == "GPL-3.0-only AND (MIT OR Apache-2.0)"

    def test_the_licences_an_npm_package_lists_are_alternatives(self):
        assert self.deps["jquery"]["license"] == "MIT OR GPL-2.0-only"

    def test_a_licence_declared_twice_is_stored_once(self):
        assert self.deps["twice-mit"]["license"] == "MIT"

    @pytest.mark.parametrize("name", ["mixed-lib", "libchoice"])
    def test_a_mandatory_gpl_term_beside_a_choice_keeps_its_finding(self, name):
        result = _analyze([self.deps[name]])
        copyleft = _issues(result, LicenseCategory.STRONG_COPYLEFT)
        assert [issue["severity"] for issue in copyleft] == [Severity.HIGH.value]
        assert sorted(entry["license"] for entry in result["component_licenses"]) == ["GPL-3.0-only", "MIT"]

    def test_a_dual_licensed_npm_package_takes_the_permissive_choice(self):
        result = _analyze([self.deps["jquery"]])
        assert _issues(result, LicenseCategory.STRONG_COPYLEFT) == []
        assert [entry["license"] for entry in result["component_licenses"]] == ["MIT"]

    def test_a_licence_declared_twice_counts_once(self):
        assert _analyze([self.deps["twice-mit"]])["summary"]["permissive"] == 1

    def test_an_explicit_unlicensed_declaration_is_named_in_the_finding(self):
        [issue] = _issues(_analyze([self.deps["private-app"]]), LicenseCategory.UNKNOWN)
        assert "The SBOM declares UNLICENSED" in issue["explanation"]

    def test_the_mandatory_gpl_term_still_reaches_the_conflict_check(self):
        gpl2 = {**self.deps["mixed-lib"], "name": "gpl2-lib", "license": "GPL-2.0-only AND (MIT OR Apache-2.0)"}
        issues = check_license_compatibility([gpl2, self.deps["mixed-lib"]], ignore_dev=True)
        assert [issue["license"] for issue in issues] == ["GPL-2.0-only / GPL-3.0-only"]


class TestSyft:
    def setup_method(self):
        self.deps = _parsed(_SYFT)

    def test_a_licence_title_with_a_comma_is_stored_whole(self):
        assert self.deps["commons-io"]["license"] == "Apache License, Version 2.0"

    def test_the_poms_licences_are_alternatives(self):
        assert self.deps["jnr-posix"]["license"] == "EPL-2.0 OR GPL-2.0-only OR LGPL-2.1-only"

    def test_an_os_packages_licences_all_apply(self):
        assert self.deps["libc6"]["license"] == "GPL-2.0-only AND LGPL-2.1-only"

    def test_a_licence_known_only_by_url_resolves_through_the_url(self):
        assert self.deps["url-only"]["license"] == "Apache-2.0"

    def test_an_empty_licence_value_is_no_licence(self):
        assert self.deps["no-licence-data"]["license"] == ""

    def test_the_pom_choice_raises_no_strong_copyleft_finding(self):
        result = _analyze([self.deps["jnr-posix"]])
        assert _issues(result, LicenseCategory.STRONG_COPYLEFT) == []
        assert [entry["license"] for entry in result["component_licenses"]] == ["EPL-2.0"]

    @pytest.mark.parametrize("name", ["commons-io", "url-only"])
    def test_an_apache_component_is_classified(self, name):
        summary = _analyze([self.deps[name]])["summary"]
        assert (summary["permissive"], summary["unknown"]) == (1, 0)


class TestSpdx:
    def setup_method(self):
        self.deps = _parsed(_SPDX)

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("commons-lang", "Apache-2.0"),
            ("compound", "MIT AND BSD-3-Clause"),
            ("trivy-style", "Apache-2.0"),
            ("vendor-lib", "LicenseRef-Acme-EULA"),
        ],
    )
    def test_a_licence_ref_resolves_through_the_documents_extracted_names(self, name, expected):
        assert self.deps[name]["license"] == expected

    def test_a_resolved_licence_ref_is_classified(self):
        summary = _analyze([self.deps["commons-lang"]])["summary"]
        assert (summary["permissive"], summary["unknown"]) == (1, 0)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://opensource.org/licenses/MIT-0", None),
        ("https://opensource.org/licenses/mit-license.php", "MIT"),
    ],
)
def test_the_mit_url_pattern_does_not_claim_mit_0(url, expected):
    assert normalizer.extract_license_from_url(url) == expected
