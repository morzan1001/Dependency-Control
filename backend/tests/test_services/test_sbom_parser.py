"""Tests for SBOM parser - format detection, CycloneDX/SPDX/Syft parsing."""

from app.schemas.sbom import SBOMFormat
from app.services.sbom_parser import (
    SBOMParser,
    is_url,
    extract_license_from_url,
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
        # url.lower() converts MIT to mit, but pattern has uppercase MIT
        # This is the actual behavior - patterns with uppercase won't match
        assert extract_license_from_url("https://opensource.org/licenses/MIT") is None

    def test_unlicense_org(self):
        assert extract_license_from_url("https://unlicense.org") == "Unlicense"


class TestResolveCyclonedxDirectRefs:
    """The fallback (SBOM root bom-ref does not match a graph node) must return the
    root's CHILDREN — the direct deps — not the root nodes themselves (regression: a
    mismatched main_bom_ref marked every dependency transitive)."""

    def test_fallback_returns_root_children_not_roots(self):
        # app -> [A, B]; A -> [C]. "app" is the root (nothing depends on it).
        deps_graph = {"app": ["A", "B"], "A": ["C"], "B": [], "C": []}
        all_transitive_refs = {"A", "B", "C"}
        # main_bom_ref does NOT match any graph node (e.g. a purl vs. plain refs).
        result = SBOMParser._resolve_cyclonedx_direct_refs(
            deps_graph, all_transitive_refs, "pkg:maven/com.acme/app@1.0"
        )
        assert result == {"A", "B"}  # NOT {"app"}

    def test_fallback_with_no_main_bom_ref(self):
        deps_graph = {"app": ["A", "B"], "A": [], "B": []}
        all_transitive_refs = {"A", "B"}
        result = SBOMParser._resolve_cyclonedx_direct_refs(deps_graph, all_transitive_refs, None)
        assert result == {"A", "B"}

    def test_matched_main_bom_ref_returns_root_depends_on(self):
        deps_graph = {"app": ["A", "B"], "A": ["C"], "B": [], "C": []}
        all_transitive_refs = {"A", "B", "C"}
        result = SBOMParser._resolve_cyclonedx_direct_refs(deps_graph, all_transitive_refs, "app")
        assert result == {"A", "B"}

    def test_flat_graph_treats_roots_as_direct(self):
        # No real edges: every ref is a childless root -> treat all as direct (not empty).
        deps_graph = {"X": [], "Y": []}
        all_transitive_refs: set = set()
        result = SBOMParser._resolve_cyclonedx_direct_refs(deps_graph, all_transitive_refs, None)
        assert result == {"X", "Y"}


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
        assert result.dependencies[0].type == "python"


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
        assert result.total_components == result.parsed_components + result.skipped_components


class TestSyftLegacyStringCpes:
    """Finding 1: Syft schema < 16.0 emits `cpes` as a list of plain strings.
    Parsing must not crash (which silently discarded all remaining artifacts)."""

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
        # Both artifacts survive (before the fix the first one crashed the whole loop)
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
    """Finding 3: CycloneDX spec defines a singular `cpe` string, not a `cpes` array."""

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
    """Finding 2: In the canonical GitHub SBOM layout the DESCRIBES target is the
    application root; its DEPENDS_ON children are the DIRECT deps and the root itself
    must not be reported as a direct dependency."""

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
        assert deps["my-repo"].direct is False

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
        assert deps["my-repo"].direct is False

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


class TestDetectFormatMalformed:
    """Finding 5: detect_format must not raise on structurally odd (but valid JSON)
    SBOMs; it should fall through to UNKNOWN so the best-effort path runs."""

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
