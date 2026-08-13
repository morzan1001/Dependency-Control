"""Tests for SBOM parser - format detection, CycloneDX/SPDX/Syft parsing."""

import re

from app.schemas.sbom import SBOMFormat
from app.services.sbom_parser import (
    SBOMParser,
    extract_license_from_url,
    is_url,
    parse_sbom,
)


class TestIsUrl:
    def test_https_url(self):
        assert is_url("https://example.com") is True

    def test_http_url(self):
        assert is_url("http://example.com") is True

    def test_not_url(self):
        assert is_url("MIT") is False

    def test_empty_string(self):
        assert is_url("") is False

    def test_ftp_url(self):
        assert is_url("ftp://example.com") is False

    def test_none_like(self):
        assert is_url(None) is False  # type: ignore[arg-type]  # Testing None handling

    def test_url_with_path(self):
        assert is_url("https://example.com/path/to/resource") is True


class TestExtractLicenseFromUrl:
    def test_mit_license_org(self):
        # mit-license.org pattern matches because url.lower() keeps it lowercase
        assert extract_license_from_url("https://mit-license.org") == "MIT"

    def test_gpl3_url(self):
        result = extract_license_from_url("https://www.gnu.org/licenses/gpl-3.0.html")
        assert result == "GPL-3.0"

    def test_unknown_url(self):
        assert extract_license_from_url("https://example.com/license") is None

    def test_empty_url(self):
        assert extract_license_from_url("") is None

    def test_none(self):
        assert extract_license_from_url(None) is None  # type: ignore[arg-type]  # Testing None handling

    def test_case_sensitive_patterns_not_matching_uppercase(self):
        # url.lower() converts MIT to mit, but the pattern has uppercase MIT, so it won't match.
        assert extract_license_from_url("https://opensource.org/licenses/MIT") is None

    def test_unlicense_org(self):
        assert extract_license_from_url("https://unlicense.org") == "Unlicense"


class TestResolveCyclonedxDirectRefs:
    """The fallback (root bom-ref doesn't match a graph node) must return the root's children (direct deps), not the roots themselves — and flag them as inferred."""

    def test_fallback_returns_root_children_not_roots(self):
        # app -> [A, B]; A -> [C]. "app" is the root (nothing depends on it).
        deps_graph = {"app": ["A", "B"], "A": ["C"], "B": [], "C": []}
        all_transitive_refs = {"A", "B", "C"}
        # main_bom_ref does NOT match any graph node (e.g. a purl vs. plain refs).
        direct_refs, inferred = SBOMParser._resolve_cyclonedx_direct_refs(
            deps_graph, all_transitive_refs, "pkg:maven/com.acme/app@1.0"
        )
        assert direct_refs == {"A", "B"}  # NOT {"app"}
        assert inferred is True

    def test_fallback_with_no_main_bom_ref(self):
        deps_graph = {"app": ["A", "B"], "A": [], "B": []}
        all_transitive_refs = {"A", "B"}
        direct_refs, inferred = SBOMParser._resolve_cyclonedx_direct_refs(deps_graph, all_transitive_refs, None)
        assert direct_refs == {"A", "B"}
        assert inferred is True

    def test_matched_main_bom_ref_returns_root_depends_on(self):
        deps_graph = {"app": ["A", "B"], "A": ["C"], "B": [], "C": []}
        all_transitive_refs = {"A", "B", "C"}
        direct_refs, inferred = SBOMParser._resolve_cyclonedx_direct_refs(deps_graph, all_transitive_refs, "app")
        assert direct_refs == {"A", "B"}
        assert inferred is False

    def test_flat_graph_treats_roots_as_direct(self):
        # No real edges: every ref is a childless root -> treat all as direct (not empty).
        deps_graph = {"X": [], "Y": []}
        all_transitive_refs: set = set()
        direct_refs, inferred = SBOMParser._resolve_cyclonedx_direct_refs(deps_graph, all_transitive_refs, None)
        assert direct_refs == {"X", "Y"}
        assert inferred is True


def _cyclonedx_image_partial_graph() -> dict:
    """Syft-style image SBOM: the dependencies graph covers only the app ecosystem while the components list also holds OS packages the graph never mentions."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": [{"name": "syft", "version": "1.19.0"}],
            "component": {
                "type": "container",
                "name": "registry.example.com/team/service",
                "version": "sha256:abc123",
                "bom-ref": "root-image",
            },
        },
        "components": [
            {
                "type": "library",
                "name": "express",
                "version": "4.19.2",
                "purl": "pkg:npm/express@4.19.2",
                "bom-ref": "pkg:npm/express@4.19.2",
            },
            {
                "type": "library",
                "name": "body-parser",
                "version": "1.20.2",
                "purl": "pkg:npm/body-parser@1.20.2",
                "bom-ref": "pkg:npm/body-parser@1.20.2",
            },
            {
                "type": "library",
                "name": "libssl3",
                "version": "3.0.11-1~deb12u2",
                "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2",
                "bom-ref": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2",
            },
            {
                "type": "library",
                "name": "zlib1g",
                "version": "1.2.13",
                "purl": "pkg:deb/debian/zlib1g@1.2.13",
                "bom-ref": "pkg:deb/debian/zlib1g@1.2.13",
            },
        ],
        "dependencies": [
            {"ref": "root-image", "dependsOn": ["pkg:npm/express@4.19.2"]},
            {"ref": "pkg:npm/express@4.19.2", "dependsOn": ["pkg:npm/body-parser@1.20.2"]},
        ],
    }


class TestCycloneDXDirectnessHonesty:
    """(direct=True, direct_inferred=False) is reserved for refs explicitly listed under the main component; everything the graph never mentions stays direct but is flagged inferred."""

    def setup_method(self):
        self.parser = SBOMParser()

    def test_explicit_direct_ref_is_hard_fact(self):
        result = self.parser.parse(_cyclonedx_image_partial_graph())
        deps = {d.name: d for d in result.dependencies}
        assert deps["express"].direct is True
        assert deps["express"].direct_inferred is False

    def test_transitive_ref_stays_transitive(self):
        result = self.parser.parse(_cyclonedx_image_partial_graph())
        deps = {d.name: d for d in result.dependencies}
        assert deps["body-parser"].direct is False
        assert deps["body-parser"].direct_inferred is False

    def test_refs_absent_from_graph_are_direct_but_inferred(self):
        result = self.parser.parse(_cyclonedx_image_partial_graph())
        deps = {d.name: d for d in result.dependencies}
        for name in ("libssl3", "zlib1g"):
            assert deps[name].direct is True
            assert deps[name].direct_inferred is True

    def test_roots_children_fallback_marks_direct_refs_inferred(self):
        sbom = _cyclonedx_image_partial_graph()
        # Main bom-ref absent from the graph (13 of 43 re-parsed prod SBOMs): the
        # roots-children fallback resolves express as direct, but only as a guess.
        sbom["dependencies"] = [
            {"ref": "app-node", "dependsOn": ["pkg:npm/express@4.19.2"]},
            {"ref": "pkg:npm/express@4.19.2", "dependsOn": ["pkg:npm/body-parser@1.20.2"]},
        ]
        result = self.parser.parse(sbom)
        deps = {d.name: d for d in result.dependencies}
        assert deps["express"].direct is True
        assert deps["express"].direct_inferred is True
        assert deps["body-parser"].direct is False
        assert deps["body-parser"].direct_inferred is False
        assert deps["libssl3"].direct is True
        assert deps["libssl3"].direct_inferred is True

    def test_no_graph_at_all_stays_fully_inferred(self):
        sbom = _cyclonedx_image_partial_graph()
        sbom["dependencies"] = []
        result = self.parser.parse(sbom)
        assert all(d.direct is True and d.direct_inferred is True for d in result.dependencies)


class TestSBOMFormatDetection:
    def setup_method(self):
        self.parser = SBOMParser()

    def test_cyclonedx_by_bom_format(self, cyclonedx_minimal):
        fmt, version = self.parser.detect_format(cyclonedx_minimal)
        assert fmt == SBOMFormat.CYCLONEDX
        assert version == "1.5"

    def test_cyclonedx_by_schema(self):
        sbom = {"$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json"}
        fmt, version = self.parser.detect_format(sbom)
        assert fmt == SBOMFormat.CYCLONEDX
        assert version == "1.5"

    def test_cyclonedx_by_components_with_purl(self):
        sbom = {
            "specVersion": "1.4",
            "components": [{"name": "pkg", "purl": "pkg:pypi/pkg@1.0"}],
        }
        fmt, _ = self.parser.detect_format(sbom)
        assert fmt == SBOMFormat.CYCLONEDX

    def test_spdx_by_spdx_version(self, spdx_minimal):
        fmt, version = self.parser.detect_format(spdx_minimal)
        assert fmt == SBOMFormat.SPDX
        assert version == "SPDX-2.3"

    def test_spdx_by_schema(self):
        sbom = {"$schema": "https://spdx.org/schema/SPDX-2.3.json"}
        fmt, _ = self.parser.detect_format(sbom)
        assert fmt == SBOMFormat.SPDX

    def test_syft_by_descriptor(self, syft_minimal):
        fmt, version = self.parser.detect_format(syft_minimal)
        assert fmt == SBOMFormat.SYFT
        assert version == "0.100.0"

    def test_syft_by_source_type(self):
        sbom = {
            "source": {"type": "image", "target": "nginx:latest"},
            "artifacts": [],
        }
        fmt, _ = self.parser.detect_format(sbom)
        assert fmt == SBOMFormat.SYFT

    def test_unknown_format(self):
        fmt, version = self.parser.detect_format({"random": "data"})
        assert fmt == SBOMFormat.UNKNOWN
        assert version is None


class TestCycloneDXParsing:
    def setup_method(self):
        self.parser = SBOMParser()

    def test_basic_parse(self, cyclonedx_minimal):
        result = self.parser.parse(cyclonedx_minimal)
        assert result.format == SBOMFormat.CYCLONEDX
        assert len(result.dependencies) == 2
        assert result.parsed_components == 2

    def test_component_names(self, cyclonedx_minimal):
        result = self.parser.parse(cyclonedx_minimal)
        names = [d.name for d in result.dependencies]
        assert "requests" in names
        assert "urllib3" in names

    def test_direct_dependency_detection(self, cyclonedx_minimal):
        result = self.parser.parse(cyclonedx_minimal)
        deps = {d.name: d for d in result.dependencies}
        assert deps["requests"].direct is True

    def test_transitive_dependency_detection(self, cyclonedx_minimal):
        result = self.parser.parse(cyclonedx_minimal)
        deps = {d.name: d for d in result.dependencies}
        assert deps["urllib3"].direct is False

    def test_purl_preserved(self, cyclonedx_minimal):
        result = self.parser.parse(cyclonedx_minimal)
        deps = {d.name: d for d in result.dependencies}
        assert deps["requests"].purl == "pkg:pypi/requests@2.31.0"

    def test_tool_info_extracted(self, cyclonedx_minimal):
        result = self.parser.parse(cyclonedx_minimal)
        assert result.tool_name == "trivy"
        assert result.tool_version == "0.50.0"

    def test_source_type_application(self, cyclonedx_minimal):
        result = self.parser.parse(cyclonedx_minimal)
        assert result.source_type == "application"

    def test_component_without_name_skipped(self):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "root"}},
            "components": [
                {"type": "library", "version": "1.0"},  # no name
                {"type": "library", "name": "valid", "version": "2.0", "purl": "pkg:pypi/valid@2.0"},
            ],
            "dependencies": [],
        }
        result = self.parser.parse(sbom)
        assert result.parsed_components == 1
        assert result.skipped_components == 1
        assert result.total_components == 2

    def test_file_component_skipped(self):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "root"}},
            "components": [
                {"type": "library", "name": "valid", "version": "2.0", "purl": "pkg:pypi/valid@2.0"},
                {"type": "file", "name": "/etc/selinux/semanage.conf"},
            ],
            "dependencies": [],
        }
        result = self.parser.parse(sbom)
        assert [d.name for d in result.dependencies] == ["valid"]
        assert result.skipped_components == 1
        assert result.total_components == 2

    def test_purl_constructed_when_missing(self):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "root"}},
            "components": [
                {"type": "library", "name": "no-purl-pkg", "version": "1.0.0"},
            ],
            "dependencies": [],
        }
        result = self.parser.parse(sbom)
        dep = result.dependencies[0]
        assert dep.purl is not None
        assert "no-purl-pkg" in dep.purl

    def test_license_extraction_spdx_id(self):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "root"}},
            "components": [
                {
                    "type": "library",
                    "name": "pkg",
                    "version": "1.0",
                    "purl": "pkg:pypi/pkg@1.0",
                    "licenses": [{"license": {"id": "MIT"}}],
                },
            ],
            "dependencies": [],
        }
        result = self.parser.parse(sbom)
        assert result.dependencies[0].license == "MIT"

    def test_license_extraction_expression(self):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "root"}},
            "components": [
                {
                    "type": "library",
                    "name": "pkg",
                    "version": "1.0",
                    "purl": "pkg:pypi/pkg@1.0",
                    "licenses": [{"expression": "Apache-2.0 OR MIT"}],
                },
            ],
            "dependencies": [],
        }
        result = self.parser.parse(sbom)
        assert result.dependencies[0].license == "Apache-2.0 OR MIT"

    def test_container_source_type(self):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "component": {
                    "type": "container",
                    "name": "nginx",
                    "version": "latest",
                    "bom-ref": "root",
                },
            },
            "components": [],
            "dependencies": [],
        }
        result = self.parser.parse(sbom)
        assert result.source_type == "image"
        assert result.source_target == "nginx:latest"


class TestSPDXParsing:
    def setup_method(self):
        self.parser = SBOMParser()

    def test_basic_parse(self, spdx_minimal):
        result = self.parser.parse(spdx_minimal)
        assert result.format == SBOMFormat.SPDX
        assert len(result.dependencies) == 1

    def test_component_name(self, spdx_minimal):
        result = self.parser.parse(spdx_minimal)
        assert result.dependencies[0].name == "requests"
        assert result.dependencies[0].version == "2.31.0"

    def test_direct_via_describes_relationship(self, spdx_minimal):
        result = self.parser.parse(spdx_minimal)
        assert result.dependencies[0].direct is True

    def test_license_concluded_preferred(self, spdx_minimal):
        result = self.parser.parse(spdx_minimal)
        assert result.dependencies[0].license == "Apache-2.0"

    def test_license_noassertion_fallback(self):
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {
                    "SPDXID": "SPDXRef-pkg",
                    "name": "test-pkg",
                    "versionInfo": "1.0",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "MIT",
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/test-pkg@1.0"}],
                }
            ],
            "relationships": [],
        }
        result = self.parser.parse(sbom)
        assert result.dependencies[0].license == "MIT"

    def test_purl_from_external_refs(self, spdx_minimal):
        result = self.parser.parse(spdx_minimal)
        assert result.dependencies[0].purl == "pkg:pypi/requests@2.31.0"

    def test_type_inferred_from_purl(self, spdx_minimal):
        result = self.parser.parse(spdx_minimal)
        assert result.dependencies[0].type == "pypi"


class TestSyftParsing:
    def setup_method(self):
        self.parser = SBOMParser()

    def test_basic_parse(self, syft_minimal):
        result = self.parser.parse(syft_minimal)
        assert result.format == SBOMFormat.SYFT
        assert len(result.dependencies) == 1

    def test_component_name(self, syft_minimal):
        result = self.parser.parse(syft_minimal)
        assert result.dependencies[0].name == "requests"
        assert result.dependencies[0].version == "2.31.0"

    def test_source_type_directory(self, syft_minimal):
        result = self.parser.parse(syft_minimal)
        assert result.source_type == "directory"
        assert result.source_target == "/app"

    def test_source_type_image(self):
        sbom = {
            "descriptor": {"name": "syft", "version": "0.100.0"},
            "source": {"type": "image", "target": "nginx:latest"},
            "artifacts": [],
            "artifactRelationships": [],
        }
        result = self.parser.parse(sbom)
        assert result.source_type == "image"

    def test_license_extraction(self, syft_minimal):
        result = self.parser.parse(syft_minimal)
        assert result.dependencies[0].license == "Apache-2.0"

    def test_locations_extracted(self, syft_minimal):
        result = self.parser.parse(syft_minimal)
        assert "/app/requirements.txt" in result.dependencies[0].locations

    def test_tool_info(self, syft_minimal):
        result = self.parser.parse(syft_minimal)
        assert result.tool_name == "syft"
        assert result.tool_version == "0.100.0"


class TestParseSBOMConvenience:
    def test_convenience_function(self, cyclonedx_minimal):
        result = parse_sbom(cyclonedx_minimal)
        assert result.format == SBOMFormat.CYCLONEDX
        assert len(result.dependencies) > 0

    def test_unknown_format_best_effort(self):
        result = parse_sbom({"random": "data"})
        assert result.format == SBOMFormat.UNKNOWN
        assert len(result.dependencies) == 0

    def test_total_components_count(self, cyclonedx_minimal):
        result = parse_sbom(cyclonedx_minimal)
        assert result.total_components == (
            result.parsed_components + result.skipped_components + result.merged_components
        )


def _nested_npm_sbom():
    """Mirrors prod cyclonedx-npm 6.0.1 output: sub-dependencies nested in
    components[].components[], pipe-joined bom-refs, nested refs present in
    the dependencies graph."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": "2026-08-01T00:00:00Z",
            "tools": {
                "components": [
                    {"type": "application", "name": "npm", "version": "11.17.0"},
                    {"type": "application", "group": "@cyclonedx", "name": "cyclonedx-npm", "version": "6.0.1"},
                ]
            },
            "component": {
                "type": "application",
                "name": "web-frontend",
                "version": "0.0.0",
                "bom-ref": "web-frontend@0.0.0",
                "purl": "pkg:npm/web-frontend@0.0.0",
            },
        },
        "components": [
            {
                "type": "library",
                "name": "parse5",
                "version": "8.0.1",
                "bom-ref": "web-frontend@0.0.0|parse5@8.0.1",
                "purl": "pkg:npm/parse5@8.0.1",
                "licenses": [{"license": {"id": "MIT", "acknowledgement": "declared"}}],
                "properties": [{"name": "cdx:npm:package:path", "value": "node_modules/parse5"}],
                "components": [
                    {
                        "type": "library",
                        "name": "entities",
                        "version": "8.0.0",
                        "bom-ref": "web-frontend@0.0.0|parse5@8.0.1|entities@8.0.0",
                        "purl": "pkg:npm/entities@8.0.0",
                        "licenses": [{"license": {"id": "BSD-2-Clause", "acknowledgement": "declared"}}],
                        "properties": [
                            {"name": "cdx:npm:package:path", "value": "node_modules/parse5/node_modules/entities"}
                        ],
                    }
                ],
            },
            {
                "type": "library",
                "name": "ora",
                "version": "5.4.1",
                "bom-ref": "web-frontend@0.0.0|ora@5.4.1",
                "purl": "pkg:npm/ora@5.4.1",
            },
        ],
        "dependencies": [
            {
                "ref": "web-frontend@0.0.0",
                "dependsOn": ["web-frontend@0.0.0|parse5@8.0.1", "web-frontend@0.0.0|ora@5.4.1"],
            },
            {
                "ref": "web-frontend@0.0.0|parse5@8.0.1",
                "dependsOn": ["web-frontend@0.0.0|parse5@8.0.1|entities@8.0.0"],
            },
            {"ref": "web-frontend@0.0.0|ora@5.4.1", "dependsOn": []},
            {"ref": "web-frontend@0.0.0|parse5@8.0.1|entities@8.0.0"},
        ],
    }


class TestCycloneDXNestedComponents:
    def setup_method(self):
        self.parser = SBOMParser()

    def test_nested_components_are_parsed(self):
        result = self.parser.parse(_nested_npm_sbom())
        names = [d.name for d in result.dependencies]
        assert names == ["parse5", "entities", "ora"]

    def test_nested_components_count_toward_total(self):
        result = self.parser.parse(_nested_npm_sbom())
        assert result.total_components == 3
        assert result.parsed_components == 3
        assert result.skipped_components == 0

    def test_nested_component_directness_resolved_from_graph(self):
        result = self.parser.parse(_nested_npm_sbom())
        deps = {d.name: d for d in result.dependencies}
        assert deps["parse5"].direct is True
        assert deps["parse5"].direct_inferred is False
        assert deps["entities"].direct is False
        assert deps["entities"].direct_inferred is False

    def test_nested_component_parents_resolved_from_graph(self):
        result = self.parser.parse(_nested_npm_sbom())
        deps = {d.name: d for d in result.dependencies}
        assert deps["entities"].parent_components == ["web-frontend@0.0.0|parse5@8.0.1"]

    def test_deeply_nested_components_are_parsed(self):
        sbom = _nested_npm_sbom()
        sbom["components"][0]["components"][0]["components"] = [
            {
                "type": "library",
                "name": "deep-pkg",
                "version": "1.0.0",
                "bom-ref": "web-frontend@0.0.0|parse5@8.0.1|entities@8.0.0|deep-pkg@1.0.0",
                "purl": "pkg:npm/deep-pkg@1.0.0",
            }
        ]
        result = self.parser.parse(sbom)
        assert "deep-pkg" in [d.name for d in result.dependencies]

    def test_nesting_beyond_depth_cap_skips_subtree_and_counts_it(self):
        chain: dict = {
            "type": "library",
            "name": "level-149",
            "version": "1.0.0",
            "purl": "pkg:npm/level-149@1.0.0",
        }
        for i in range(148, -1, -1):
            chain = {
                "type": "library",
                "name": f"level-{i}",
                "version": "1.0.0",
                "purl": f"pkg:npm/level-{i}@1.0.0",
                "components": [chain],
            }
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "root"}},
            "components": [chain],
            "dependencies": [],
        }
        result = self.parser.parse(sbom)
        names = {d.name for d in result.dependencies}
        assert result.parsed_components == 100
        assert result.skipped_components == 50
        assert result.total_components == 150
        assert {"level-0", "level-99"} <= names
        assert "level-100" not in names

    def test_nested_file_component_still_skipped(self):
        sbom = _nested_npm_sbom()
        sbom["components"][0]["components"].append({"type": "file", "name": "/app/index.js"})
        result = self.parser.parse(sbom)
        assert "/app/index.js" not in [d.name for d in result.dependencies]
        assert result.skipped_components == 1
        assert result.total_components == 4


def _syft_image_sbom_with_duplicate_package():
    """Mirrors a prod syft 1.42.3 image SBOM: the same npm package catalogued
    in two node_modules trees, with distinct package-id bom-refs, layers, and
    location properties."""

    def _copy(package_id: str, layer_id: str, path: str):
        return {
            "bom-ref": f"pkg:npm/%40isaacs/cliui@8.0.2?package-id={package_id}",
            "type": "library",
            "author": "Ben Coe <ben@npmjs.com>",
            "name": "@isaacs/cliui",
            "version": "8.0.2",
            "licenses": [{"license": {"id": "ISC"}}],
            "cpe": "cpe:2.3:a:\\@isaacs\\/cliui:\\@isaacs\\/cliui:8.0.2:*:*:*:*:*:*:*",
            "purl": "pkg:npm/%40isaacs/cliui@8.0.2",
            "properties": [
                {"name": "syft:package:foundBy", "value": "javascript-package-cataloger"},
                {"name": "syft:package:type", "value": "npm"},
                {"name": "syft:location:0:layerID", "value": layer_id},
                {"name": "syft:location:0:path", "value": path},
            ],
        }

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "tools": {
                "components": [{"type": "application", "author": "anchore", "name": "syft", "version": "1.42.3"}]
            },
            "component": {
                "type": "container",
                "name": "registry.example.com/app",
                "version": "1.2.3",
                "bom-ref": "root",
            },
        },
        "components": [
            _copy(
                "a82d332383092fc4",
                "sha256:f82f355dbd9bd7a91f6e61dde913a586ad11763ea58fe26280194bd3dbde67a2",
                "/usr/local/lib/node_modules/npm/node_modules/@isaacs/cliui/package.json",
            ),
            _copy(
                "0626882b793a9edd",
                "sha256:d7a699b2505c57989a3b2b73465c56f82f10e742b4b7f39c7a2f22abf9854d19",
                "/usr/src/app/node_modules/@isaacs/cliui/package.json",
            ),
        ],
        "dependencies": [],
    }


class TestDuplicateComponentMerge:
    def setup_method(self):
        self.parser = SBOMParser()

    def test_duplicates_collapse_to_one_document(self):
        result = self.parser.parse(_syft_image_sbom_with_duplicate_package())
        assert len(result.dependencies) == 1
        assert result.parsed_components == 1
        assert result.merged_components == 1
        assert result.skipped_components == 0
        assert result.total_components == 2

    def test_merged_locations_are_unioned(self):
        result = self.parser.parse(_syft_image_sbom_with_duplicate_package())
        locations = result.dependencies[0].locations
        assert "/usr/local/lib/node_modules/npm/node_modules/@isaacs/cliui/package.json" in locations
        assert "/usr/src/app/node_modules/@isaacs/cliui/package.json" in locations

    def test_merge_keeps_first_non_null_layer_digest_and_found_by(self):
        # Trivy image SBOM shape: only the second copy carries layer/foundBy data.
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "container", "name": "app-image", "bom-ref": "root"}},
            "components": [
                {
                    "type": "library",
                    "name": "jcip-annotations",
                    "version": "1.0-1",
                    "bom-ref": "pkg:maven/net.jcip/jcip-annotations@1.0-1?uuid=1",
                    "purl": "pkg:maven/net.jcip/jcip-annotations@1.0-1",
                },
                {
                    "type": "library",
                    "name": "jcip-annotations",
                    "version": "1.0-1",
                    "bom-ref": "pkg:maven/net.jcip/jcip-annotations@1.0-1?uuid=2",
                    "purl": "pkg:maven/net.jcip/jcip-annotations@1.0-1",
                    "properties": [
                        {"name": "aquasecurity:trivy:LayerDigest", "value": "sha256:abc123"},
                        {"name": "syft:package:foundBy", "value": "java-archive-cataloger"},
                    ],
                },
            ],
            "dependencies": [],
        }
        result = self.parser.parse(sbom)
        assert len(result.dependencies) == 1
        assert result.dependencies[0].layer_digest == "sha256:abc123"
        assert result.dependencies[0].found_by == "java-archive-cataloger"

    def test_merge_unions_cpes_hashes_and_parents(self):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "root"}},
            "components": [
                {
                    "type": "library",
                    "name": "lib-a",
                    "version": "1.0",
                    "bom-ref": "lib-a-1",
                    "purl": "pkg:npm/lib-a@1.0",
                    "cpe": "cpe:2.3:a:lib-a:lib-a:1.0:*:*:*:*:*:*:*",
                    "hashes": [{"alg": "SHA-1", "content": "aaa"}],
                },
                {
                    "type": "library",
                    "name": "lib-a",
                    "version": "1.0",
                    "bom-ref": "lib-a-2",
                    "purl": "pkg:npm/lib-a@1.0",
                    "cpe": "cpe:2.3:a:liba:liba:1.0:*:*:*:*:*:*:*",
                    "hashes": [{"alg": "SHA-256", "content": "bbb"}],
                },
            ],
            "dependencies": [
                {"ref": "root", "dependsOn": ["parent-x", "parent-y"]},
                {"ref": "parent-x", "dependsOn": ["lib-a-1"]},
                {"ref": "parent-y", "dependsOn": ["lib-a-2"]},
            ],
        }
        result = self.parser.parse(sbom)
        assert len(result.dependencies) == 1
        dep = result.dependencies[0]
        assert set(dep.cpes) == {
            "cpe:2.3:a:lib-a:lib-a:1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:liba:liba:1.0:*:*:*:*:*:*:*",
        }
        assert dep.hashes == {"sha-1": "aaa", "sha-256": "bbb"}
        assert set(dep.parent_components) == {"parent-x", "parent-y"}

    def test_merge_direct_anywhere_wins_over_transitive(self):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "root"}},
            "components": [
                {
                    "type": "library",
                    "name": "lib-b",
                    "version": "2.0",
                    "bom-ref": "lib-b-1",
                    "purl": "pkg:npm/lib-b@2.0",
                },
                {
                    "type": "library",
                    "name": "lib-b",
                    "version": "2.0",
                    "bom-ref": "lib-b-2",
                    "purl": "pkg:npm/lib-b@2.0",
                },
            ],
            "dependencies": [
                {"ref": "root", "dependsOn": ["lib-b-2", "other"]},
                {"ref": "other", "dependsOn": ["lib-b-1"]},
                {"ref": "lib-b-1", "dependsOn": []},
                {"ref": "lib-b-2", "dependsOn": []},
            ],
        }
        result = self.parser.parse(sbom)
        assert len(result.dependencies) == 1
        assert result.dependencies[0].direct is True
        assert result.dependencies[0].direct_inferred is False


class TestSyftLegacyStringCpes:
    """Syft schema < 16.0 emits `cpes` as plain strings; parsing must not crash."""

    def test_string_form_cpes_do_not_crash_and_are_captured(self):
        parser = SBOMParser()
        sbom = {
            "descriptor": {"name": "syft", "version": "0.90.0"},
            "source": {"type": "directory", "target": "/app"},
            "artifacts": [
                {
                    "id": "a1",
                    "name": "pkg-a",
                    "version": "1.0",
                    "type": "python",
                    "cpes": ["cpe:2.3:a:pkg-a:pkg-a:1.0:*:*:*:*:*:*:*"],
                },
                {
                    "id": "a2",
                    "name": "pkg-b",
                    "version": "2.0",
                    "type": "python",
                    "cpes": ["cpe:2.3:a:pkg-b:pkg-b:2.0:*:*:*:*:*:*:*"],
                },
            ],
            "artifactRelationships": [],
        }
        result = parser.parse(sbom)
        deps = {d.name: d for d in result.dependencies}
        # Both artifacts survive.
        assert set(deps) == {"pkg-a", "pkg-b"}
        assert deps["pkg-a"].cpes == ["cpe:2.3:a:pkg-a:pkg-a:1.0:*:*:*:*:*:*:*"]

    def test_dict_form_cpes_still_work(self):
        parser = SBOMParser()
        sbom = {
            "descriptor": {"name": "syft", "version": "1.0.0"},
            "source": {"type": "directory", "target": "/app"},
            "artifacts": [
                {
                    "id": "a1",
                    "name": "pkg-a",
                    "version": "1.0",
                    "type": "python",
                    "cpes": [{"cpe": "cpe:2.3:a:pkg-a:pkg-a:1.0:*:*:*:*:*:*:*"}],
                },
            ],
            "artifactRelationships": [],
        }
        result = parser.parse(sbom)
        assert result.dependencies[0].cpes == ["cpe:2.3:a:pkg-a:pkg-a:1.0:*:*:*:*:*:*:*"]


class TestCycloneDXCpe:
    """CycloneDX spec defines a singular `cpe` string, not a `cpes` array."""

    def test_singular_cpe_field_captured(self):
        parser = SBOMParser()
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "root"}},
            "components": [
                {
                    "type": "library",
                    "name": "pkg",
                    "version": "1.0",
                    "purl": "pkg:pypi/pkg@1.0",
                    "cpe": "cpe:2.3:a:pkg:pkg:1.0:*:*:*:*:*:*:*",
                },
            ],
            "dependencies": [],
        }
        result = parser.parse(sbom)
        assert result.dependencies[0].cpes == ["cpe:2.3:a:pkg:pkg:1.0:*:*:*:*:*:*:*"]

    def test_no_cpe_yields_empty_list(self):
        parser = SBOMParser()
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "root"}},
            "components": [
                {"type": "library", "name": "pkg", "version": "1.0", "purl": "pkg:pypi/pkg@1.0"},
            ],
            "dependencies": [],
        }
        result = parser.parse(sbom)
        assert result.dependencies[0].cpes == []


class TestSPDXDirectDependencyDetection:
    """In the canonical GitHub SBOM layout the DESCRIBES target is the app root; its DEPENDS_ON children are the direct deps, and the root itself is not direct."""

    def test_github_layout_root_children_are_direct(self):
        parser = SBOMParser()
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {
                    "SPDXID": "SPDXRef-repo",
                    "name": "my-repo",
                    "versionInfo": "1.0",
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:github/acme/my-repo@1.0"}],
                },
                {
                    "SPDXID": "SPDXRef-dep1",
                    "name": "dep1",
                    "versionInfo": "1.0",
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/dep1@1.0"}],
                },
                {
                    "SPDXID": "SPDXRef-dep2",
                    "name": "dep2",
                    "versionInfo": "2.0",
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/dep2@2.0"}],
                },
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relatedSpdxElement": "SPDXRef-repo",
                    "relationshipType": "DESCRIBES",
                },
                {
                    "spdxElementId": "SPDXRef-repo",
                    "relatedSpdxElement": "SPDXRef-dep1",
                    "relationshipType": "DEPENDS_ON",
                },
                {
                    "spdxElementId": "SPDXRef-repo",
                    "relatedSpdxElement": "SPDXRef-dep2",
                    "relationshipType": "DEPENDS_ON",
                },
            ],
        }
        result = parser.parse(sbom)
        deps = {d.name: d for d in result.dependencies}
        assert deps["dep1"].direct is True
        assert deps["dep2"].direct is True
        assert "my-repo" not in deps

    def test_transitive_dep_of_direct_is_not_direct(self):
        parser = SBOMParser()
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {"SPDXID": "SPDXRef-repo", "name": "my-repo", "versionInfo": "1.0"},
                {"SPDXID": "SPDXRef-dep1", "name": "dep1", "versionInfo": "1.0"},
                {"SPDXID": "SPDXRef-dep2", "name": "dep2", "versionInfo": "2.0"},
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relatedSpdxElement": "SPDXRef-repo",
                    "relationshipType": "DESCRIBES",
                },
                {
                    "spdxElementId": "SPDXRef-repo",
                    "relatedSpdxElement": "SPDXRef-dep1",
                    "relationshipType": "DEPENDS_ON",
                },
                {
                    "spdxElementId": "SPDXRef-dep1",
                    "relatedSpdxElement": "SPDXRef-dep2",
                    "relationshipType": "DEPENDS_ON",
                },
            ],
        }
        result = parser.parse(sbom)
        deps = {d.name: d for d in result.dependencies}
        assert deps["dep1"].direct is True
        assert deps["dep2"].direct is False
        assert "my-repo" not in deps

    def test_document_depends_on_directly(self):
        # No intermediate root package: DOCUMENT DEPENDS_ON dep1 directly.
        parser = SBOMParser()
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {"SPDXID": "SPDXRef-dep1", "name": "dep1", "versionInfo": "1.0"},
                {"SPDXID": "SPDXRef-dep2", "name": "dep2", "versionInfo": "2.0"},
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relatedSpdxElement": "SPDXRef-dep1",
                    "relationshipType": "DEPENDS_ON",
                },
                {
                    "spdxElementId": "SPDXRef-dep1",
                    "relatedSpdxElement": "SPDXRef-dep2",
                    "relationshipType": "DEPENDS_ON",
                },
            ],
        }
        result = parser.parse(sbom)
        deps = {d.name: d for d in result.dependencies}
        assert deps["dep1"].direct is True
        assert deps["dep2"].direct is False


_SYFT_SOURCE_ID = "cdb4ee2aea69cc6a83331bbe96dc2caa9a299d21329efb0336fc02a82e1839a8"


def _syft_json_project_sbom() -> dict:
    """Mirrors the prod syft 1.42.3 directory scan: `dependency-of` edges point
    library -> root project ('parent IS A DEPENDENCY OF child'), plus
    contains/evident-by edges from the source for every artifact."""

    def _artifact(aid: str, name: str, version: str, purl: str | None, atype: str = "java-archive") -> dict:
        art: dict = {"id": aid, "name": name, "version": version, "type": atype}
        if purl:
            art["purl"] = purl
        return art

    return {
        "descriptor": {"name": "syft", "version": "1.42.3"},
        "source": {"id": _SYFT_SOURCE_ID, "type": "directory", "target": "/build", "name": "."},
        "artifacts": [
            _artifact("aaaa000000000001", "demo", "0.0.1-SNAPSHOT", "pkg:maven/com.example/demo@0.0.1-SNAPSHOT"),
            _artifact("aaaa000000000002", "slf4j-api", "2.0.16", "pkg:maven/org.slf4j/slf4j-api@2.0.16"),
            _artifact("aaaa000000000003", "logback-core", "1.5.6", "pkg:maven/ch.qos.logback/logback-core@1.5.6"),
            _artifact("aaaa000000000004", "actions/checkout", "v4", "pkg:github/actions/checkout@v4", "github-action"),
        ],
        "artifactRelationships": [
            {"parent": _SYFT_SOURCE_ID, "child": "aaaa000000000001", "type": "contains"},
            {"parent": _SYFT_SOURCE_ID, "child": "aaaa000000000002", "type": "contains"},
            {"parent": _SYFT_SOURCE_ID, "child": "aaaa000000000003", "type": "contains"},
            {"parent": _SYFT_SOURCE_ID, "child": "aaaa000000000004", "type": "contains"},
            # slf4j-api is a dependency of demo; logback-core is a dependency of slf4j-api.
            {"parent": "aaaa000000000002", "child": "aaaa000000000001", "type": "dependency-of"},
            {"parent": "aaaa000000000003", "child": "aaaa000000000002", "type": "dependency-of"},
            {"parent": "aaaa000000000001", "child": "evidence-file-1", "type": "evident-by"},
        ],
        "files": [],
    }


class TestSyftRelationshipDirection:
    """Syft `dependency-of` means 'parent IS A DEPENDENCY OF child'; the old code read it backwards."""

    def setup_method(self):
        self.parser = SBOMParser()
        self.result = self.parser.parse(_syft_json_project_sbom())
        self.deps = {d.name: d for d in self.result.dependencies}

    def test_single_root_children_are_direct(self):
        assert self.deps["slf4j-api"].direct is True

    def test_transitive_dependency_is_not_direct(self):
        dep = self.deps["logback-core"]
        assert dep.direct is False
        assert dep.direct_inferred is False

    def test_root_project_does_not_list_its_dependencies_as_parents(self):
        assert self.deps["demo"].parent_components == []

    def test_parents_point_at_dependents_not_dependencies(self):
        assert self.deps["slf4j-api"].parent_components == ["pkg:maven/com.example/demo@0.0.1-SNAPSHOT"]
        assert self.deps["logback-core"].parent_components == ["pkg:maven/org.slf4j/slf4j-api@2.0.16"]

    def test_parent_refs_are_purls_not_syft_hex_ids(self):
        for dep in self.result.dependencies:
            for ref in dep.parent_components:
                assert not re.fullmatch(r"[0-9a-f]{16}", ref)

    def test_contains_only_artifact_is_direct_but_flagged_inferred(self):
        action = self.deps["actions/checkout"]
        assert action.direct is True
        assert action.direct_inferred is True

    def test_source_level_depends_on_is_graph_confirmed_direct(self):
        sbom = _syft_json_project_sbom()
        sbom["artifactRelationships"].append(
            {"parent": _SYFT_SOURCE_ID, "child": "aaaa000000000002", "type": "depends-on"}
        )
        result = self.parser.parse(sbom)
        dep = {d.name: d for d in result.dependencies}["slf4j-api"]
        assert dep.direct is True
        assert dep.direct_inferred is False

    def test_source_level_dependency_of_is_graph_confirmed_direct(self):
        sbom = _syft_json_project_sbom()
        sbom["artifactRelationships"].append(
            {"parent": "aaaa000000000003", "child": _SYFT_SOURCE_ID, "type": "dependency-of"}
        )
        result = self.parser.parse(sbom)
        dep = {d.name: d for d in result.dependencies}["logback-core"]
        assert dep.direct is True
        assert dep.direct_inferred is False

    def test_multiple_roots_do_not_promote_their_children(self):
        # Two independent top-level packages: their children must stay transitive.
        sbom = _syft_json_project_sbom()
        sbom["artifactRelationships"] = [
            {"parent": "aaaa000000000002", "child": "aaaa000000000001", "type": "dependency-of"},
            {"parent": "aaaa000000000003", "child": "aaaa000000000004", "type": "dependency-of"},
        ]
        result = self.parser.parse(sbom)
        deps = {d.name: d for d in result.dependencies}
        assert deps["slf4j-api"].direct is False
        assert deps["logback-core"].direct is False
        assert deps["demo"].direct is True
        assert deps["demo"].direct_inferred is True

    def test_no_relationships_keeps_everything_direct_inferred(self):
        sbom = _syft_json_project_sbom()
        sbom["artifactRelationships"] = []
        result = self.parser.parse(sbom)
        assert all(d.direct is True and d.direct_inferred is True for d in result.dependencies)

    def test_image_scan_with_contains_only_relationships_is_direct_inferred(self):
        # K17: the old app-package-type fallback keyed on type names syft never
        # emits; graph-silent artifacts are now uniformly direct-but-inferred.
        sbom = {
            "descriptor": {"name": "syft", "version": "1.42.3"},
            "source": {"id": _SYFT_SOURCE_ID, "type": "image", "target": "registry.example.com/app:1"},
            "artifacts": [
                {
                    "id": "bbbb000000000001",
                    "name": "spring-core",
                    "version": "6.2.1",
                    "type": "java-archive",
                    "purl": "pkg:maven/org.springframework/spring-core@6.2.1",
                },
                {
                    "id": "bbbb000000000002",
                    "name": "libssl3",
                    "version": "3.0.11",
                    "type": "deb",
                    "purl": "pkg:deb/debian/libssl3@3.0.11",
                },
            ],
            "artifactRelationships": [
                {"parent": _SYFT_SOURCE_ID, "child": "bbbb000000000001", "type": "contains"},
                {"parent": _SYFT_SOURCE_ID, "child": "bbbb000000000002", "type": "contains"},
            ],
        }
        result = self.parser.parse(sbom)
        assert all(d.direct is True and d.direct_inferred is True for d in result.dependencies)


def _three_component_sbom(second_component: dict) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "root"}},
        "components": [
            {"type": "library", "name": "first", "version": "1.0", "purl": "pkg:pypi/first@1.0"},
            second_component,
            {"type": "library", "name": "third", "version": "3.0", "purl": "pkg:pypi/third@3.0"},
        ],
        "dependencies": [],
    }


class TestMalformedComponentResilience:
    """One bad component must not truncate the parse; the loss must be counted."""

    def setup_method(self):
        self.parser = SBOMParser()

    def test_null_version_component_is_coerced_not_fatal(self):
        sbom = _three_component_sbom(
            {"type": "library", "name": "second", "version": None, "purl": "pkg:pypi/second@2.0"}
        )
        result = self.parser.parse(sbom)
        names = [d.name for d in result.dependencies]
        assert names == ["first", "second", "third"]
        assert result.dependencies[1].version == "unknown"

    def test_properties_object_instead_of_list_is_not_fatal(self):
        sbom = _three_component_sbom(
            {
                "type": "library",
                "name": "second",
                "version": "2.0",
                "purl": "pkg:pypi/second@2.0",
                "properties": {"name": "x", "value": "y"},
            }
        )
        result = self.parser.parse(sbom)
        assert [d.name for d in result.dependencies] == ["first", "second", "third"]

    def test_crashing_component_is_skipped_and_counted_others_survive(self):
        sbom = _three_component_sbom(
            {"type": "library", "name": "second", "version": "2.0", "purl": "pkg:pypi/second@2.0", "licenses": 5}
        )
        result = self.parser.parse(sbom)
        assert [d.name for d in result.dependencies] == ["first", "third"]
        assert result.skipped_components == 1
        assert result.skipped_reasons.get("parse-error") == 1
        assert result.total_components == 3

    def test_non_dict_component_is_counted(self):
        sbom = _three_component_sbom({"type": "library", "name": "second", "version": "2.0"})
        sbom["components"].append(123)
        result = self.parser.parse(sbom)
        assert len(result.dependencies) == 3
        assert result.skipped_components == 1
        assert result.total_components == 4

    def test_null_licenses_and_hashes_are_not_fatal(self):
        sbom = _three_component_sbom(
            {
                "type": "library",
                "name": "second",
                "version": "2.0",
                "purl": "pkg:pypi/second@2.0",
                "licenses": None,
                "hashes": None,
                "externalReferences": None,
                "evidence": None,
            }
        )
        result = self.parser.parse(sbom)
        assert [d.name for d in result.dependencies] == ["first", "second", "third"]

    def test_syft_artifact_crash_is_isolated(self):
        sbom = {
            "descriptor": {"name": "syft", "version": "1.0.0"},
            "source": {"type": "directory", "target": "/app"},
            "artifacts": [
                {"id": "a1", "name": "ok-1", "version": "1.0", "type": "python", "purl": "pkg:pypi/ok-1@1.0"},
                {"id": "a2", "name": "bad", "version": "1.0", "type": "python", "licenses": 5},
                {"id": "a3", "name": "ok-2", "version": "2.0", "type": "python", "purl": "pkg:pypi/ok-2@2.0"},
            ],
            "artifactRelationships": [],
        }
        result = self.parser.parse(sbom)
        assert [d.name for d in result.dependencies] == ["ok-1", "ok-2"]
        assert result.skipped_reasons.get("parse-error") == 1

    def test_spdx_package_crash_is_isolated(self):
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {"SPDXID": "SPDXRef-1", "name": "ok-1", "versionInfo": "1.0", "checksums": 5},
                {"SPDXID": "SPDXRef-2", "name": "ok-2", "versionInfo": "2.0"},
            ],
            "relationships": [],
        }
        result = self.parser.parse(sbom)
        assert [d.name for d in result.dependencies] == ["ok-2"]
        assert result.skipped_reasons.get("parse-error") == 1

    def test_unknown_format_attempts_do_not_leak_state_between_handlers(self):
        # CycloneDX-shaped components (undetectable: no purl on the first) yield zero
        # dependencies; the SPDX attempt must win with a clean slate, not inherit the
        # CycloneDX attempt's skip counters.
        sbom = {
            "components": [{"type": "file", "name": "/etc/passwd"}],
            "packages": [{"SPDXID": "SPDXRef-1", "name": "real-pkg", "versionInfo": "1.0"}],
            "relationships": [],
        }
        result = parse_sbom(sbom)
        assert [d.name for d in result.dependencies] == ["real-pkg"]
        assert result.skipped_components == 0
        assert result.total_components == 1


def _spdx_github_export() -> dict:
    """Mirrors a GitHub dependency-graph SBOM export: DOCUMENT DESCRIBES the repo
    package, which DEPENDS_ON the actual dependencies."""
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "com.github.acme/my-service",
        "creationInfo": {"created": "2026-08-01T00:00:00Z"},
        "packages": [
            {
                "SPDXID": "SPDXRef-repo",
                "name": "com.github.acme/my-service",
                "versionInfo": "",
                "downloadLocation": "git+https://github.com/acme/my-service",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:github/acme/my-service"}],
            },
            {
                "SPDXID": "SPDXRef-npm-left-pad",
                "name": "npm:left-pad",
                "versionInfo": "1.3.0",
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NONE",
                "packageFileName": "package-lock.json",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0"}],
            },
            {
                "SPDXID": "SPDXRef-maven-commons-text",
                "name": "org.apache.commons:commons-text",
                "versionInfo": "NOASSERTION",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:maven/org.apache.commons/commons-text@1.14.0"}
                ],
            },
            {
                "SPDXID": "SPDXRef-composer-monolog",
                "name": "monolog/monolog",
                "versionInfo": "3.9.0",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:composer/monolog/monolog@3.9.0"}],
            },
            {"SPDXID": "SPDXRef-noassert", "name": "NOASSERTION", "versionInfo": "1.0"},
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-repo",
                "relationshipType": "DESCRIBES",
            },
            {
                "spdxElementId": "SPDXRef-repo",
                "relatedSpdxElement": "SPDXRef-npm-left-pad",
                "relationshipType": "DEPENDS_ON",
            },
            {
                "spdxElementId": "SPDXRef-repo",
                "relatedSpdxElement": "SPDXRef-maven-commons-text",
                "relationshipType": "DEPENDS_ON",
            },
            {
                "spdxElementId": "SPDXRef-maven-commons-text",
                "relatedSpdxElement": "SPDXRef-composer-monolog",
                "relationshipType": "DEPENDS_ON",
            },
        ],
    }


class TestSPDXRootSkipAndFields:
    def setup_method(self):
        self.parser = SBOMParser()
        self.result = self.parser.parse(_spdx_github_export())
        self.deps = {d.name: d for d in self.result.dependencies}

    def test_described_root_is_not_ingested_as_dependency(self):
        assert "com.github.acme/my-service" not in self.deps
        assert self.result.skipped_reasons.get("root-component") == 1

    def test_source_comes_from_described_root(self):
        assert self.result.source_type == "application"
        assert self.result.source_target == "com.github.acme/my-service"

    def test_parents_resolve_to_purls_not_spdxrefs(self):
        assert self.deps["monolog/monolog"].parent_components == ["pkg:maven/org.apache.commons/commons-text@1.14.0"]

    def test_direct_dependency_has_no_unresolvable_root_parent(self):
        assert self.deps["npm:left-pad"].parent_components == []

    def test_noassertion_version_is_normalized(self):
        assert self.deps["org.apache.commons:commons-text"].version == "unknown"

    def test_none_license_is_dropped(self):
        assert self.deps["npm:left-pad"].license == ""

    def test_package_named_noassertion_is_dropped(self):
        assert "NOASSERTION" not in self.deps

    def test_package_file_name_becomes_location(self):
        assert self.deps["npm:left-pad"].locations == ["package-lock.json"]

    def test_type_falls_back_to_purl_type_for_unmapped_ecosystems(self):
        assert self.deps["monolog/monolog"].type == "composer"

    def test_group_derived_from_purl_namespace(self):
        assert self.deps["org.apache.commons:commons-text"].group == "org.apache.commons"

    def test_dependencies_inherit_source_target(self):
        assert self.deps["npm:left-pad"].source_target == "com.github.acme/my-service"

    def test_minimal_describes_only_document_keeps_package(self):
        # A document that DESCRIBES a package with no DEPENDS_ON children is an
        # SBOM *of* that package; it must stay ingested and direct.
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [{"SPDXID": "SPDXRef-only", "name": "lonely-lib", "versionInfo": "1.0"}],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relatedSpdxElement": "SPDXRef-only",
                    "relationshipType": "DESCRIBES",
                }
            ],
        }
        result = self.parser.parse(sbom)
        assert [d.name for d in result.dependencies] == ["lonely-lib"]
        assert result.dependencies[0].direct is True


def _syft_cyclonedx_component_sbom(properties: list[dict], **extra) -> dict:
    comp = {
        "bom-ref": "pkg:maven/org.hdrhistogram/HdrHistogram@2.2.2?package-id=abc",
        "type": "library",
        "name": "HdrHistogram",
        "version": "2.2.2",
        "purl": "pkg:maven/org.hdrhistogram/HdrHistogram@2.2.2",
        "properties": properties,
        **extra,
    }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "syft", "version": "1.42.2"}]},
            "component": {"type": "container", "name": "registry.example.com/app", "version": "1", "bom-ref": "root"},
        },
        "components": [comp],
        "dependencies": [],
    }


class TestSyftCycloneDXLocationProperties:
    """syft:location:N:layerID feeds layer_digest, path/accessPath feed locations deduplicated (prod shape: 97% of location-bearing docs held a sha256 pseudo-path and layer_digest stayed null)."""

    def setup_method(self):
        self.parser = SBOMParser()

    def test_layer_id_goes_to_layer_digest_not_locations(self):
        layer = "sha256:16b50a465761e86ece11e7312e0dccecb2a17c18e0b4a34c9d40baba6f8e77f3"
        result = self.parser.parse(
            _syft_cyclonedx_component_sbom(
                [
                    {"name": "syft:location:0:layerID", "value": layer},
                    {"name": "syft:location:0:path", "value": "/app/libs/HdrHistogram-2.2.2.jar"},
                ]
            )
        )
        dep = result.dependencies[0]
        assert dep.layer_digest == layer
        assert dep.locations == ["/app/libs/HdrHistogram-2.2.2.jar"]

    def test_path_and_access_path_are_deduplicated(self):
        result = self.parser.parse(
            _syft_cyclonedx_component_sbom(
                [
                    {"name": "syft:location:0:path", "value": "/app/libs/HdrHistogram-2.2.2.jar"},
                    {"name": "syft:location:0:accessPath", "value": "/app/libs/HdrHistogram-2.2.2.jar"},
                ]
            )
        )
        assert result.dependencies[0].locations == ["/app/libs/HdrHistogram-2.2.2.jar"]

    def test_first_layer_id_wins_across_locations(self):
        result = self.parser.parse(
            _syft_cyclonedx_component_sbom(
                [
                    {"name": "syft:location:0:layerID", "value": "sha256:first"},
                    {"name": "syft:location:1:layerID", "value": "sha256:second"},
                ]
            )
        )
        assert result.dependencies[0].layer_digest == "sha256:first"

    def test_trivy_layer_digest_still_recognised(self):
        result = self.parser.parse(
            _syft_cyclonedx_component_sbom([{"name": "aquasecurity:trivy:LayerDigest", "value": "sha256:trivy"}])
        )
        assert result.dependencies[0].layer_digest == "sha256:trivy"

    def test_cdx_npm_package_path_still_a_location(self):
        result = self.parser.parse(
            _syft_cyclonedx_component_sbom([{"name": "cdx:npm:package:path", "value": "node_modules/parse5"}])
        )
        assert result.dependencies[0].locations == ["node_modules/parse5"]


class TestSyftCpePropertiesLifted:
    """Syft-generated CycloneDX carries CPEs only as repeated syft:cpe23 properties."""

    def setup_method(self):
        self.parser = SBOMParser()

    def test_all_cpe23_properties_are_lifted(self):
        cpes = [
            "cpe:2.3:a:org.hdrhistogram:HdrHistogram:2.2.2:*:*:*:*:*:*:*",
            "cpe:2.3:a:HdrHistogram:HdrHistogram:2.2.2:*:*:*:*:*:*:*",
            "cpe:2.3:a:hdrhistogram:HdrHistogram:2.2.2:*:*:*:*:*:*:*",
        ]
        result = self.parser.parse(_syft_cyclonedx_component_sbom([{"name": "syft:cpe23", "value": c} for c in cpes]))
        assert result.dependencies[0].cpes == cpes

    def test_spec_cpe_field_and_properties_are_merged_without_duplicates(self):
        cpe = "cpe:2.3:a:org.hdrhistogram:HdrHistogram:2.2.2:*:*:*:*:*:*:*"
        result = self.parser.parse(_syft_cyclonedx_component_sbom([{"name": "syft:cpe23", "value": cpe}], cpe=cpe))
        assert result.dependencies[0].cpes == [cpe]


class TestDetectFormatMalformed:
    """detect_format must not raise on structurally odd (but valid JSON) SBOMs; it falls through to UNKNOWN."""

    def setup_method(self):
        self.parser = SBOMParser()

    def test_components_first_element_not_dict(self):
        fmt, _ = self.parser.detect_format({"components": [123, 456]})
        assert fmt == SBOMFormat.UNKNOWN

    def test_components_first_element_is_list(self):
        fmt, _ = self.parser.detect_format({"components": [["nested"]]})
        assert fmt == SBOMFormat.UNKNOWN

    def test_source_is_string(self):
        fmt, _ = self.parser.detect_format({"source": "some-string"})
        assert fmt == SBOMFormat.UNKNOWN

    def test_parse_does_not_raise_on_malformed(self):
        result = parse_sbom({"components": [123], "source": "x"})
        assert result is not None
        assert result.format == SBOMFormat.UNKNOWN
