"""Tests for SBOM parser - format detection, CycloneDX/SPDX/Syft parsing."""

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.schemas.sbom import ParsedDependency, SBOMFormat
from app.services.analyzers.end_of_life import collect_products_to_check
from app.services.analyzers.license_compliance.normalizer import extract_license_from_url
from app.services.sbom_parser import (
    SBOMParser,
    is_url,
    merge_duplicate_dependencies,
    parse_sbom,
)
from tests.helpers.comparisons import counted_str_type


def test_the_parser_imports_in_a_fresh_interpreter():
    imported = subprocess.run(
        [sys.executable, "-c", "import app.services.sbom_parser"],
        cwd=Path(__file__).parents[2],
        capture_output=True,
        text=True,
        check=False,
    )

    assert imported.returncode == 0, imported.stderr


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

    def test_an_uppercase_url_segment_still_matches(self):
        assert extract_license_from_url("https://opensource.org/licenses/MIT") == "MIT"

    def test_unlicense_org(self):
        assert extract_license_from_url("https://unlicense.org") == "Unlicense"


FIXTURES = Path(__file__).parent.parent / "fixtures" / "sbom"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _accounted(result) -> int:
    return len(result.dependencies) + result.skipped_components + result.merged_components


def _fixture_with(name: str, field: str, entry: object) -> dict:
    sbom = _fixture(name)
    sbom[field] = [*sbom[field], entry]
    return sbom


def _directness(result) -> dict[str, tuple[bool, bool]]:
    return {dep.name: (dep.direct, dep.direct_inferred) for dep in result.dependencies}


_POETRY_TRANSITIVES = ("anyio", "certifi", "h11", "httpcore", "idna", "sniffio")
_UV_DEV_TRANSITIVES = (
    *("anyio", "certifi", "h11", "httpcore", "idna", "typing-extensions"),
    *("colorama", "iniconfig", "packaging", "pluggy", "pygments"),
)
_SYFT_MONOREPO = {
    "debug": (True, True),
    "ms": (False, True),
    "httpx": (True, True),
    **dict.fromkeys(_POETRY_TRANSITIVES, (False, True)),
}


class TestDirectnessOfRealGraphs:
    """syft 1.42.1 and trivy 0.58.1 output for one npm + poetry monorepo, in every format they write."""

    @pytest.mark.parametrize(
        ("fixture", "expected", "skipped_roots"),
        [
            pytest.param("mono.syft.json", _SYFT_MONOREPO, 1, id="syft-json"),
            pytest.param("mono.syft.cdx.json", _SYFT_MONOREPO, 1, id="syft-cyclonedx"),
            # syft's SPDX output carries none of the lockfile metadata that marks myapp as the project.
            pytest.param(
                "mono.syft.spdx.json",
                {**_SYFT_MONOREPO, "myapp": (True, True), "debug": (False, True)},
                0,
                id="syft-spdx",
            ),
            pytest.param(
                "poetry.syft.json",
                {"httpx": (True, True), **dict.fromkeys(_POETRY_TRANSITIVES, (False, True))},
                0,
                id="syft-json-poetry-only",
            ),
            pytest.param(
                "mono.trivy.cdx.json",
                {
                    "debug": (True, False),
                    "ms": (False, False),
                    "httpx": (True, False),
                    **dict.fromkeys(_POETRY_TRANSITIVES, (False, False)),
                },
                0,
                id="trivy-cyclonedx",
            ),
        ],
    )
    def test_each_format_resolves_the_same_direct_set(self, fixture, expected, skipped_roots):
        result = parse_sbom(_fixture(fixture))

        assert _directness(result) == expected
        assert result.skipped_reasons.get("root-component", 0) == skipped_roots

    @pytest.mark.parametrize(
        "fixture", ["mono.syft.json", "mono.syft.cdx.json", "mono.syft.spdx.json", "mono.trivy.cdx.json"]
    )
    def test_each_format_records_the_same_parents(self, fixture):
        deps = {dep.name: dep for dep in parse_sbom(_fixture(fixture)).dependencies}

        assert deps["ms"].parent_components == ["pkg:npm/debug@4.3.4"]
        assert deps["h11"].parent_components == ["pkg:pypi/httpcore@1.0.5"]

    def test_trivy_os_descriptor_passes_directness_to_the_top_level_os_packages(self):
        directness = _directness(parse_sbom(_fixture("rootfs.trivy.cdx.json")))

        direct = {name for name, value in directness.items() if value == (True, False)}
        assert direct == {
            "alpine",
            "myapp",
            "alpine-baselayout",
            "alpine-keys",
            "apk-tools",
            "musl-utils",
            "ssl_client",
        }
        assert all(value == (False, False) for name, value in directness.items() if name not in direct)

    @pytest.mark.parametrize(
        ("fixture", "project_deps"),
        [
            pytest.param("maven.trivy.cdx.json", {"logback-classic", "slf4j-api"}, id="pom"),
            pytest.param(
                "gomod.trivy.cdx.json",
                {"github.com/google/uuid", "golang.org/x/sys", "golang.org/x/text"},
                id="gomod",
            ),
            pytest.param("gobinary.trivy.cdx.json", {"github.com/google/uuid", "stdlib"}, id="gobinary"),
        ],
    )
    def test_trivy_root_package_is_skipped_and_its_children_are_direct(self, fixture, project_deps):
        result = parse_sbom(_fixture(fixture))

        directness = _directness(result)
        assert {name for name, value in directness.items() if value == (True, False)} == project_deps
        assert all(value == (False, False) for name, value in directness.items() if name not in project_deps)
        assert result.skipped_reasons.get("root-component") == 1
        ingested = {dep.purl for dep in result.dependencies}
        assert all(set(dep.parent_components) <= ingested for dep in result.dependencies)

    @pytest.mark.parametrize(
        ("fixture", "expected"),
        [
            pytest.param(
                "cargo.trivy.cdx.json",
                {"myservice": (True, False), "serde_json": (False, False), "itoa": (False, False)},
                id="crate",
            ),
            # A virtual workspace's members are absent, so its direct dependency looks like a crate root.
            pytest.param(
                "cargows.trivy.cdx.json",
                {"serde_json": (True, False), **dict.fromkeys(("itoa", "ryu", "serde"), (False, False))},
                id="virtual-workspace",
            ),
        ],
    )
    def test_trivy_cargo_lock_keeps_every_package(self, fixture, expected):
        result = parse_sbom(_fixture(fixture))

        assert _directness(result) == expected
        assert "root-component" not in result.skipped_reasons

    def test_trivy_go_binary_without_main_module_keeps_every_package(self):
        # gofmt (Go toolchain) and a `go build main.go` binary carry no main module, so trivy gives them no root.
        result = parse_sbom(_fixture("gobinnomain.trivy.cdx.json"))

        assert sorted((dep.name, dep.direct, dep.direct_inferred) for dep in result.dependencies) == [
            ("github.com/google/uuid", True, False),
            ("stdlib", True, False),
        ]
        assert "root-component" not in result.skipped_reasons

    @pytest.mark.parametrize(
        ("fixture", "expected", "skipped_roots"),
        [
            # npm auto-installs react as react-dom's peer; syft links no edge to it, so it is a second lock root.
            pytest.param(
                "npmpeer.syft.cdx.json",
                {
                    "myapp": (True, True),
                    "react": (True, True),
                    **dict.fromkeys(("react-dom", "loose-envify", "scheduler", "js-tokens"), (False, True)),
                },
                0,
                id="npm-peer-cyclonedx",
            ),
            pytest.param(
                "npmpeer.syft.json",
                {
                    "react-dom": (True, True),
                    "react": (True, True),
                    **dict.fromkeys(("loose-envify", "scheduler", "js-tokens"), (False, True)),
                },
                1,
                id="npm-peer-json",
            ),
            # syft links no uv dev group to the project, so pytest is a second lock root.
            pytest.param(
                "uvdev.syft.cdx.json",
                {
                    "uvdemo": (True, True),
                    "pytest": (True, True),
                    "httpx": (False, True),
                    **dict.fromkeys(_UV_DEV_TRANSITIVES, (False, True)),
                },
                0,
                id="uv-dev-cyclonedx",
            ),
            pytest.param(
                "uvdev.syft.json",
                {
                    "pytest": (True, True),
                    "httpx": (True, True),
                    **dict.fromkeys(_UV_DEV_TRANSITIVES, (False, True)),
                },
                1,
                id="uv-dev-json",
            ),
        ],
    )
    def test_a_second_lock_root_keeps_every_registry_package(self, fixture, expected, skipped_roots):
        result = parse_sbom(_fixture(fixture))

        assert _directness(result) == expected
        assert result.skipped_reasons.get("root-component", 0) == skipped_roots

    def test_spdx_image_root_sets_the_image_source(self):
        result = parse_sbom(_fixture("alpine.syft.spdx.json"))

        apk = [dep for dep in result.dependencies if dep.type == "apk"]
        assert (result.source_type, result.source_target) == ("image", "alpine:3.20")
        assert {(dep.source_type, dep.source_target) for dep in apk} == {("image", "alpine:3.20")}
        assert {dep.name for dep in apk if dep.direct} == {
            "alpine-baselayout",
            "alpine-keys",
            "apk-tools",
            "musl-utils",
            "ssl_client",
        }

    def test_the_spdx_image_root_is_skipped_and_its_distro_becomes_the_operating_system(self):
        result = parse_sbom(_fixture("alpine.syft.spdx.json"))
        components = [dep.to_dict() for dep in result.dependencies]

        assert [dep.purl for dep in result.dependencies if dep.type == "oci"] == []
        assert result.skipped_reasons["root-component"] == 1
        assert [
            (dep.name, dep.version, dep.source_type, dep.source_target)
            for dep in result.dependencies
            if dep.type == "operating-system"
        ] == [("alpine", "3.20.10", "image", "alpine:3.20")]
        assert collect_products_to_check(components)["alpine-linux"] == [("alpine", "3.20.10", False)]

    @pytest.mark.parametrize("fixture", ["alpine.syft.json", "alpine.syft.cdx.json", "alpine.syft.spdx.json"])
    def test_every_syft_format_of_one_image_hands_its_distro_to_end_of_life(self, fixture):
        result = parse_sbom(_fixture(fixture))
        components = [dep.to_dict() for dep in result.dependencies]

        assert collect_products_to_check(components)["alpine-linux"] == [("alpine", "3.20.10", False)]

    @pytest.mark.parametrize("distro", [{"id": 5, "versionID": ["3.20"], "prettyName": 7}, "alpine", {}])
    def test_a_syft_distro_without_an_id_and_version_adds_no_operating_system(self, distro):
        sbom = _fixture("alpine.syft.json")
        sbom["distro"] = distro

        result = parse_sbom(sbom)

        assert len(result.dependencies) == 14
        assert not [dep for dep in result.dependencies if dep.type == "operating-system"]

    def test_an_spdx_operating_system_package_is_not_doubled_by_the_purl_distro(self):
        sbom = _fixture("alpine.syft.spdx.json")
        sbom["packages"].append(
            {
                "SPDXID": "SPDXRef-OperatingSystem-alpine",
                "name": "alpine",
                "versionInfo": "3.20.9",
                "primaryPackagePurpose": "OPERATING-SYSTEM",
            }
        )

        result = parse_sbom(sbom)

        assert [(dep.name, dep.version) for dep in result.dependencies if dep.name == "alpine"] == [
            ("alpine", "3.20.9")
        ]


class TestMalformedDependencyGraph:
    """A graph entry of the wrong shape fails the document in every format instead of silently dropping an edge."""

    @pytest.mark.parametrize(
        ("sbom", "message"),
        [
            pytest.param(
                _fixture_with("mono.trivy.cdx.json", "dependencies", None),
                "dependencies must be a list of objects",
                id="cyclonedx-entry",
            ),
            pytest.param(
                _fixture_with(
                    "mono.trivy.cdx.json",
                    "dependencies",
                    {"ref": "pkg:npm/debug@4.3.4", "dependsOn": "pkg:npm/ms@2.1.2"},
                ),
                "dependsOn",
                id="cyclonedx-depends-on-string",
            ),
            pytest.param(
                _fixture_with("mono.syft.spdx.json", "relationships", None),
                "relationships must be a list of objects",
                id="spdx-entry",
            ),
            pytest.param(
                _fixture_with("mono.syft.json", "artifactRelationships", None),
                "artifactRelationships must be a list of objects",
                id="syft-entry",
            ),
        ],
    )
    def test_malformed_edge_fails_the_document(self, sbom, message):
        with pytest.raises(ValueError, match=message):
            parse_sbom(sbom)

    def test_malformed_source_hints_leave_the_graph_intact(self):
        sbom = _fixture("mono.trivy.cdx.json")
        sbom["metadata"]["properties"] = [None]
        sbom["metadata"]["component"] = None

        result = parse_sbom(sbom)

        assert len(result.dependencies) == 9


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

    def test_roots_children_fallback_marks_the_whole_graph_inferred(self):
        sbom = _cyclonedx_image_partial_graph()
        # Main bom-ref absent from the graph (13 of 43 re-parsed prod SBOMs): the
        # component-less root passes directness to express, but only as a guess.
        sbom["dependencies"] = [
            {"ref": "app-node", "dependsOn": ["pkg:npm/express@4.19.2"]},
            {"ref": "pkg:npm/express@4.19.2", "dependsOn": ["pkg:npm/body-parser@1.20.2"]},
        ]
        result = self.parser.parse(sbom)
        assert _directness(result) == {
            "express": (True, True),
            "body-parser": (False, True),
            "libssl3": (True, True),
            "zlib1g": (True, True),
        }

    def test_main_component_named_by_purl_anchors_the_graph(self):
        sbom = _cyclonedx_image_partial_graph()
        root = sbom["metadata"]["component"]
        del root["bom-ref"]
        root["purl"] = sbom["dependencies"][0]["ref"] = "pkg:oci/service@sha256%3Aabc123"
        result = self.parser.parse(sbom)
        assert _directness(result)["express"] == (True, False)

    def test_no_graph_at_all_stays_fully_inferred(self):
        sbom = _cyclonedx_image_partial_graph()
        sbom["dependencies"] = []
        result = self.parser.parse(sbom)
        assert all(d.direct is True and d.direct_inferred is True for d in result.dependencies)


class TestSBOMFormatDetection:
    def setup_method(self):
        self.parser = SBOMParser()

    def test_cyclonedx_by_bom_format(self, cyclonedx_minimal):
        fmt = self.parser.detect_format(cyclonedx_minimal)
        assert fmt == SBOMFormat.CYCLONEDX

    def test_cyclonedx_by_schema(self):
        sbom = {"$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json"}
        fmt = self.parser.detect_format(sbom)
        assert fmt == SBOMFormat.CYCLONEDX

    def test_cyclonedx_by_components_with_purl(self):
        sbom = {
            "specVersion": "1.4",
            "components": [{"name": "pkg", "purl": "pkg:pypi/pkg@1.0"}],
        }
        fmt = self.parser.detect_format(sbom)
        assert fmt == SBOMFormat.CYCLONEDX

    def test_spdx_by_spdx_version(self, spdx_minimal):
        fmt = self.parser.detect_format(spdx_minimal)
        assert fmt == SBOMFormat.SPDX

    def test_spdx_by_schema(self):
        sbom = {"$schema": "https://spdx.org/schema/SPDX-2.3.json"}
        fmt = self.parser.detect_format(sbom)
        assert fmt == SBOMFormat.SPDX

    def test_syft_by_descriptor(self, syft_minimal):
        fmt = self.parser.detect_format(syft_minimal)
        assert fmt == SBOMFormat.SYFT

    def test_syft_by_source_type(self):
        sbom = {
            "source": {"type": "image", "target": "nginx:latest"},
            "artifacts": [],
        }
        fmt = self.parser.detect_format(sbom)
        assert fmt == SBOMFormat.SYFT

    def test_unknown_format(self):
        fmt = self.parser.detect_format({"random": "data"})
        assert fmt == SBOMFormat.UNKNOWN


class TestCycloneDXParsing:
    def setup_method(self):
        self.parser = SBOMParser()

    def test_basic_parse(self, cyclonedx_minimal):
        result = self.parser.parse(cyclonedx_minimal)
        assert result.format == SBOMFormat.CYCLONEDX
        assert len(result.dependencies) == 2
        assert len(result.dependencies) == 2

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
        assert len(result.dependencies) == 1
        assert result.skipped_components == 1
        assert _accounted(result) == 2

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
        assert _accounted(result) == 2

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

    def test_license_extraction(self, syft_minimal):
        result = self.parser.parse(syft_minimal)
        assert result.dependencies[0].license == "Apache-2.0"

    def test_locations_extracted(self, syft_minimal):
        result = self.parser.parse(syft_minimal)
        assert "/app/requirements.txt" in result.dependencies[0].locations


class TestParseSBOMConvenience:
    def test_convenience_function(self, cyclonedx_minimal):
        result = parse_sbom(cyclonedx_minimal)
        assert result.format == SBOMFormat.CYCLONEDX
        assert len(result.dependencies) > 0

    def test_unknown_format_best_effort(self):
        result = parse_sbom({"random": "data"})
        assert result.format == SBOMFormat.UNKNOWN
        assert len(result.dependencies) == 0


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
        assert _accounted(result) == 3
        assert len(result.dependencies) == 3
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
        assert deps["entities"].parent_components == ["pkg:npm/parse5@8.0.1"]

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
        assert len(result.dependencies) == 100
        assert result.skipped_components == 50
        assert _accounted(result) == 150
        assert {"level-0", "level-99"} <= names
        assert "level-100" not in names

    def test_nested_file_component_still_skipped(self):
        sbom = _nested_npm_sbom()
        sbom["components"][0]["components"].append({"type": "file", "name": "/app/index.js"})
        result = self.parser.parse(sbom)
        assert "/app/index.js" not in [d.name for d in result.dependencies]
        assert result.skipped_components == 1
        assert _accounted(result) == 4


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
        assert len(result.dependencies) == 1
        assert result.merged_components == 1
        assert result.skipped_components == 0
        assert _accounted(result) == 2

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
                {"type": "library", "name": "parent-x", "version": "1.0", "bom-ref": "parent-x"},
                {"type": "library", "name": "parent-y", "version": "1.0", "bom-ref": "parent-y"},
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
        [dep] = [d for d in result.dependencies if d.name == "lib-a"]
        assert set(dep.cpes) == {
            "cpe:2.3:a:lib-a:lib-a:1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:liba:liba:1.0:*:*:*:*:*:*:*",
        }
        assert dep.hashes == {"sha1": "aaa", "sha256": "bbb"}
        assert set(dep.parent_components) == {"pkg:generic/parent-x@1.0", "pkg:generic/parent-y@1.0"}

    def test_merge_fills_metadata_the_first_copy_lacks(self):
        bare = {"type": "library", "name": "lib-c", "version": "1.0", "purl": "pkg:pypi/lib-c@1.0", "bom-ref": "c-1"}
        described = {
            **bare,
            "bom-ref": "c-2",
            "group": "acme",
            "licenses": [{"license": {"id": "MIT", "url": "https://opensource.org/licenses/MIT"}}],
            "description": "Parses C",
            "author": "Jane Doe",
            "publisher": "Acme",
            "externalReferences": [
                {"type": "website", "url": "https://lib-c.example"},
                {"type": "vcs", "url": "https://github.com/acme/lib-c"},
                {"type": "distribution", "url": "https://files.example/lib-c-1.0.tar.gz"},
            ],
        }
        fields = (
            "license",
            "license_url",
            "description",
            "author",
            "publisher",
            "group",
            "homepage",
            "repository_url",
            "download_url",
        )

        [merged] = self.parser.parse(_cyclonedx_with([bare, described])).dependencies
        [alone] = self.parser.parse(_cyclonedx_with([described])).dependencies

        assert all(getattr(alone, field) for field in fields)
        assert {f: getattr(merged, f) for f in fields} == {f: getattr(alone, f) for f in fields}

    def test_merge_keeps_the_first_copy_s_populated_metadata(self):
        first = {
            "type": "library",
            "name": "lib-d",
            "version": "1.0",
            "purl": "pkg:npm/lib-d@1.0",
            "bom-ref": "pkg:npm/lib-d@1.0?uuid=1",
            "description": "first copy",
            "properties": [{"name": "aquasecurity:trivy:LayerDigest", "value": "sha256:first"}],
        }
        second = {
            **first,
            "bom-ref": "pkg:npm/lib-d@1.0?uuid=2",
            "description": "second copy",
            "properties": [{"name": "aquasecurity:trivy:LayerDigest", "value": "sha256:second"}],
        }

        [dep] = self.parser.parse(_cyclonedx_with([first, second])).dependencies

        assert (dep.layer_digest, dep.description) == ("sha256:first", "first copy")

    @pytest.mark.parametrize("scopes", [("optional", "required"), ("required", "optional"), ("excluded", None)])
    def test_merge_lets_a_runtime_scope_win(self, scopes):
        component = {"type": "library", "name": "x", "version": "1.0.0", "purl": "pkg:npm/x@1.0.0"}
        copies = [{**component, "bom-ref": f"x-{i}", "scope": scope} for i, scope in enumerate(scopes)]

        [dep] = self.parser.parse(_cyclonedx_with(copies)).dependencies

        assert dep.scope == next(scope for scope in scopes if scope not in ("optional", "excluded"))

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

    demo = _artifact("aaaa000000000001", "demo", "0.0.1-SNAPSHOT", "pkg:maven/com.example/demo@0.0.1-SNAPSHOT")
    demo["metadata"] = {
        "virtualPath": "",
        "pomProject": {"path": "", "groupId": "com.example", "artifactId": "demo", "version": "0.0.1-SNAPSHOT"},
    }
    return {
        "descriptor": {"name": "syft", "version": "1.42.3"},
        "source": {"id": _SYFT_SOURCE_ID, "type": "directory", "target": "/build", "name": "."},
        "artifacts": [
            demo,
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

    def test_project_root_children_are_direct(self):
        assert self.deps["slf4j-api"].direct is True

    def test_transitive_dependency_is_not_direct(self):
        dep = self.deps["logback-core"]
        assert dep.direct is False
        assert dep.direct_inferred is True

    def test_pom_project_is_the_root_component_not_a_dependency(self):
        assert "demo" not in self.deps
        assert self.result.skipped_reasons.get("root-component") == 1

    def test_parents_point_at_dependents_not_dependencies(self):
        assert self.deps["slf4j-api"].parent_components == []
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

    def test_roots_without_project_evidence_are_direct_and_their_children_transitive(self):
        sbom = _syft_json_project_sbom()
        del sbom["artifacts"][0]["metadata"]
        sbom["artifactRelationships"] = [
            {"parent": "aaaa000000000002", "child": "aaaa000000000001", "type": "dependency-of"},
            {"parent": "aaaa000000000003", "child": "aaaa000000000004", "type": "dependency-of"},
        ]
        result = self.parser.parse(sbom)
        assert _directness(result) == {
            "demo": (True, True),
            "actions/checkout": (True, True),
            "slf4j-api": (False, True),
            "logback-core": (False, True),
        }

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
        assert result.dependencies[1].version == "2.0"

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

    @pytest.mark.parametrize(
        "malform",
        [
            pytest.param(lambda sbom: sbom["components"][0].update(properties=5), id="component-properties"),
            pytest.param(lambda sbom: sbom["metadata"].update(properties=5), id="metadata-properties"),
            pytest.param(lambda sbom: sbom["metadata"]["component"].update(name=2024), id="application-name"),
            pytest.param(
                lambda sbom: sbom["metadata"]["component"].update(name=2024, type="container"), id="container-name"
            ),
        ],
    )
    def test_one_malformed_document_field_keeps_every_component(self, malform):
        sbom = _fixture("mono.trivy.cdx.json")
        malform(sbom)

        result = self.parser.parse(sbom)

        assert len(result.dependencies) == 9

    def test_a_numeric_spdx_root_name_keeps_every_package(self):
        sbom = _spdx_github_export()
        sbom["packages"][0]["name"] = 2024

        result = self.parser.parse(sbom)

        assert len(result.dependencies) == 3
        assert result.source_target is None

    def test_crashing_component_is_skipped_and_counted_others_survive(self):
        sbom = _three_component_sbom(
            {"type": "library", "name": "second", "version": "2.0", "purl": "pkg:pypi/second@2.0", "licenses": 5}
        )
        result = self.parser.parse(sbom)
        assert [d.name for d in result.dependencies] == ["first", "third"]
        assert result.skipped_components == 1
        assert result.skipped_reasons.get("parse-error") == 1
        assert _accounted(result) == 3

    def test_non_dict_component_is_counted(self):
        sbom = _three_component_sbom({"type": "library", "name": "second", "version": "2.0"})
        sbom["components"].append(123)
        result = self.parser.parse(sbom)
        assert len(result.dependencies) == 3
        assert result.skipped_components == 1
        assert _accounted(result) == 4

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
                {"SPDXID": "SPDXRef-1", "name": "ok-1", "versionInfo": "1.0", "externalRefs": 5},
                {"SPDXID": "SPDXRef-2", "name": "ok-2", "versionInfo": "2.0"},
            ],
            "relationships": [],
        }
        result = self.parser.parse(sbom)
        assert [d.name for d in result.dependencies] == ["ok-2"]
        assert result.skipped_reasons.get("parse-error") == 1

    def test_document_level_malformed_known_format_raises(self):
        # metadata with the wrong JSON type breaks the handler before the
        # component loop; success here would let persistence replace the scan's
        # previous dependencies with an empty set.
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": [],
            "components": [{"type": "library", "name": "valid", "version": "1.0", "purl": "pkg:pypi/valid@1.0"}],
        }
        with pytest.raises(AttributeError):
            self.parser.parse(sbom)

    def test_unknown_format_raises_when_every_handler_fails(self):
        sbom = {"metadata": "bogus", "relationships": "bogus", "source": "bogus"}
        with pytest.raises(AttributeError):
            self.parser.parse(sbom)

    def test_unknown_format_junk_without_handler_crash_still_returns_empty(self):
        result = self.parser.parse({"random": "data"})
        assert result.dependencies == []

    def test_dict_version_is_treated_as_missing(self):
        sbom = _three_component_sbom(
            {"type": "library", "name": "second", "version": {"raw": "2.0"}, "purl": "pkg:pypi/second"}
        )
        result = self.parser.parse(sbom)
        deps = {d.name: d for d in result.dependencies}
        assert deps["second"].version == "unknown"

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
        assert _accounted(result) == 1


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

    def test_noassertion_version_falls_back_to_the_purl_version(self):
        assert self.deps["org.apache.commons:commons-text"].version == "1.14.0"

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

    def test_document_describes_array_names_the_root(self):
        sbom = _spdx_github_export()
        sbom["spdxVersion"] = "SPDX-2.2"
        sbom["documentDescribes"] = ["SPDXRef-repo"]
        sbom["relationships"] = [r for r in sbom["relationships"] if r["relationshipType"] != "DESCRIBES"]

        result = self.parser.parse(sbom)
        left_pad = {d.name: d for d in result.dependencies}["npm:left-pad"]

        assert result.skipped_reasons.get("root-component") == 1
        assert (result.source_type, result.source_target) == ("application", "com.github.acme/my-service")
        assert (left_pad.direct, left_pad.direct_inferred, left_pad.parent_components) == (True, False, [])

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
    """syft:location:N:layerID feeds layer_digest, syft:location:N:path feeds locations (prod shape: 97% of location-bearing docs held a sha256 pseudo-path and layer_digest stayed null)."""

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

    def test_syft_metadata_paths_are_not_locations(self):
        result = self.parser.parse(
            _syft_cyclonedx_component_sbom(
                [
                    {"name": "syft:location:0:path", "value": "/app/libs/HdrHistogram-2.2.2.jar"},
                    {"name": "syft:metadata:virtualPath", "value": "/app/libs/HdrHistogram-2.2.2.jar:inner.jar"},
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

    def test_location_annotation_properties_are_not_locations(self):
        # Newer syft emits syft:location:N:annotations:evidence; the extra colon
        # must not fall through to the substring heuristic.
        result = self.parser.parse(
            _syft_cyclonedx_component_sbom(
                [
                    {"name": "syft:location:0:path", "value": "/app/libs/HdrHistogram-2.2.2.jar"},
                    {"name": "syft:location:0:annotations:evidence", "value": "primary"},
                ]
            )
        )
        assert result.dependencies[0].locations == ["/app/libs/HdrHistogram-2.2.2.jar"]


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


def _cyclonedx_with(components: list[dict], root: dict | None = None) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": root or {"type": "container", "name": "registry.example.com/app", "bom-ref": "root"}},
        "components": components,
        "dependencies": [],
    }


class TestFabricatedIdentifiers:
    """OS descriptors and binary applications got fabricated pkg:generic purls no vulnerability or enrichment source can ever match (10.8k prod rows, 94 syntactically invalid)."""

    def setup_method(self):
        self.parser = SBOMParser()

    def test_operating_system_component_kept_without_fabricated_purl(self):
        # Prod shape: bom-ref os:rhel@9.8, purl null, real OS CPE.
        result = self.parser.parse(
            _cyclonedx_with(
                [
                    {
                        "bom-ref": "os:rhel@9.8",
                        "type": "operating-system",
                        "name": "rhel",
                        "version": "9.8",
                        "cpe": "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*",
                    }
                ]
            )
        )
        assert len(result.dependencies) == 1
        dep = result.dependencies[0]
        assert dep.purl is None
        assert dep.version == "9.8"
        assert dep.cpes == ["cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*"]

    def test_binary_application_without_purl_or_cpe_is_skipped(self):
        result = self.parser.parse(_cyclonedx_with([{"type": "application", "name": "Notifu", "version": "1.7.6.0"}]))
        assert result.dependencies == []
        assert result.skipped_reasons.get("unidentifiable") == 1

    def test_application_with_cpe_is_kept_without_fabricated_purl(self):
        result = self.parser.parse(
            _cyclonedx_with(
                [
                    {
                        "type": "application",
                        "name": "chrome",
                        "version": "126.0.6478.126",
                        "cpe": "cpe:2.3:a:google:chrome:126.0.6478.126:*:*:*:*:*:*:*",
                    }
                ]
            )
        )
        assert len(result.dependencies) == 1
        assert result.dependencies[0].purl is None
        assert result.dependencies[0].cpes

    def test_device_data_firmware_components_are_skipped(self):
        result = self.parser.parse(
            _cyclonedx_with(
                [
                    {"type": "device", "name": "sensor", "version": "1"},
                    {"type": "data", "name": "training-set", "version": "1"},
                    {"type": "firmware", "name": "bios", "version": "1"},
                ]
            )
        )
        assert result.dependencies == []
        assert result.skipped_reasons.get("non-dependency") == 3

    def test_root_component_repeated_in_component_list_is_skipped(self):
        root = {
            "type": "application",
            "name": "app",
            "version": "1.0.0",
            "bom-ref": "app@1.0.0",
            "purl": "pkg:npm/app@1.0.0",
        }
        result = self.parser.parse(
            _cyclonedx_with(
                [
                    dict(root),
                    {"type": "library", "name": "dep", "version": "2.0", "purl": "pkg:npm/dep@2.0"},
                ],
                root=root,
            )
        )
        assert [d.name for d in result.dependencies] == ["dep"]
        assert result.skipped_reasons.get("root-component") == 1

    def test_library_without_purl_and_placeholder_version_is_skipped(self):
        result = self.parser.parse(
            _cyclonedx_with([{"type": "library", "name": "mavenEcjBootstrapAgent", "version": "UNKNOWN"}])
        )
        assert result.dependencies == []
        assert result.skipped_reasons.get("unidentifiable") == 1

    def test_placeholder_version_with_real_purl_is_normalized_and_kept(self):
        result = self.parser.parse(
            _cyclonedx_with(
                [
                    {
                        "type": "library",
                        "name": "slf4j-api",
                        "version": "UNKNOWN",
                        "purl": "pkg:maven/org.slf4j/slf4j-api",
                    }
                ]
            )
        )
        assert len(result.dependencies) == 1
        assert result.dependencies[0].version == "unknown"

    def test_fabricated_purl_segments_are_percent_encoded(self):
        result = self.parser.parse(_cyclonedx_with([{"type": "library", "name": "my lib", "version": "1.0, rev 2"}]))
        assert result.dependencies[0].purl == "pkg:generic/my%20lib@1.0%2C%20rev%202"

    def test_syft_artifact_with_placeholder_version_but_purl_is_kept(self):
        sbom = {
            "descriptor": {"name": "syft", "version": "1.42.3"},
            "source": {"id": "src", "type": "directory", "target": "/build"},
            "artifacts": [
                {
                    "id": "a1",
                    "name": "spring-boot-starter-test",
                    "version": "UNKNOWN",
                    "type": "java-archive",
                    "purl": "pkg:maven/org.springframework.boot/spring-boot-starter-test",
                },
                {"id": "a2", "name": "esc-cli.amd64.windows", "version": "UNKNOWN", "type": "binary"},
            ],
            "artifactRelationships": [],
        }
        result = self.parser.parse(sbom)
        assert [d.name for d in result.dependencies] == ["spring-boot-starter-test"]
        assert result.dependencies[0].version == "unknown"
        assert result.skipped_reasons.get("unidentifiable") == 1

    def test_spdx_package_without_purl_and_noassertion_version_is_skipped(self):
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {"SPDXID": "SPDXRef-1", "name": "ghost-pkg", "versionInfo": "NOASSERTION"},
                {"SPDXID": "SPDXRef-2", "name": "real-pkg", "versionInfo": "1.0"},
            ],
            "relationships": [],
        }
        result = self.parser.parse(sbom)
        assert [d.name for d in result.dependencies] == ["real-pkg"]


class TestTypeIsPurlEcosystem:
    """`type` is surfaced as 'ecosystem' by Inventory; all three branches must emit the purl vocabulary, not the generator's."""

    def setup_method(self):
        self.parser = SBOMParser()

    def test_trivy_framework_component_gets_purl_type(self):
        result = self.parser.parse(
            _cyclonedx_with(
                [
                    {
                        "type": "framework",
                        "name": "@angular-devkit/architect",
                        "version": "0.1902.14",
                        "purl": "pkg:npm/%40angular-devkit/architect@0.1902.14",
                    }
                ]
            )
        )
        assert result.dependencies[0].type == "npm"

    def test_cyclonedx_library_gets_purl_type(self):
        result = self.parser.parse(
            _cyclonedx_with(
                [
                    {
                        "type": "library",
                        "name": "guava",
                        "version": "33.0.0",
                        "purl": "pkg:maven/com.google.guava/guava@33.0.0",
                    }
                ]
            )
        )
        assert result.dependencies[0].type == "maven"

    def test_operating_system_keeps_its_component_type(self):
        result = self.parser.parse(
            _cyclonedx_with(
                [
                    {
                        "bom-ref": "os:debian@13",
                        "type": "operating-system",
                        "name": "debian",
                        "version": "13",
                        "cpe": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:*",
                    }
                ]
            )
        )
        assert result.dependencies[0].type == "operating-system"

    def test_purl_less_application_falls_back_to_syft_package_type_property(self):
        result = self.parser.parse(
            _cyclonedx_with(
                [
                    {
                        "type": "application",
                        "name": "windows-kill",
                        "version": "1.0",
                        "cpe": "cpe:2.3:a:windows-kill:windows-kill:1.0:*:*:*:*:*:*:*",
                        "properties": [{"name": "syft:package:type", "value": "binary"}],
                    }
                ]
            )
        )
        assert result.dependencies[0].type == "generic"

    def test_fabricated_purl_prefers_syft_package_type_property(self):
        result = self.parser.parse(
            _cyclonedx_with(
                [
                    {
                        "type": "library",
                        "name": "some-lib",
                        "version": "1.0",
                        "properties": [{"name": "syft:package:type", "value": "java-archive"}],
                    }
                ]
            )
        )
        assert (result.dependencies[0].type, result.dependencies[0].purl) == ("maven", "pkg:maven/some-lib@1.0")

    def test_syft_artifact_type_replaced_by_purl_type(self):
        sbom = {
            "descriptor": {"name": "syft", "version": "1.42.3"},
            "source": {"id": "src", "type": "directory", "target": "/build"},
            "artifacts": [
                {
                    "id": "a1",
                    "name": "slf4j-api",
                    "version": "2.0.16",
                    "type": "java-archive",
                    "purl": "pkg:maven/org.slf4j/slf4j-api@2.0.16",
                },
                {
                    "id": "a2",
                    "name": "actions/checkout",
                    "version": "v4",
                    "type": "github-action",
                    "purl": "pkg:github/actions/checkout@v4",
                },
            ],
            "artifactRelationships": [],
        }
        result = self.parser.parse(sbom)
        deps = {d.name: d for d in result.dependencies}
        assert deps["slf4j-api"].type == "maven"
        assert deps["actions/checkout"].type == "github"


class TestVcsUrlNormalization:
    """Maven SCM strings copied verbatim (4.3% of prod repository_url values) are unusable as links."""

    def setup_method(self):
        self.parser = SBOMParser()

    def _repo_url(self, vcs_value: str) -> str | None:
        sbom = _cyclonedx_with(
            [
                {
                    "type": "library",
                    "name": "pkg",
                    "version": "1.0",
                    "purl": "pkg:maven/g/pkg@1.0",
                    "externalReferences": [{"type": "vcs", "url": vcs_value}],
                }
            ]
        )
        return self.parser.parse(sbom).dependencies[0].repository_url

    def test_scm_git_git_protocol(self):
        assert (
            self._repo_url("scm:git:git://github.com/jayway/JsonPath.git") == "https://github.com/jayway/JsonPath.git"
        )

    def test_git_at_host_colon_path(self):
        assert self._repo_url("git@github.com:prometheus/client_java.git") == (
            "https://github.com/prometheus/client_java.git"
        )

    def test_scm_git_git_at_host(self):
        assert self._repo_url("scm:git:git@github.com:lukas-krecan/ShedLock.git") == (
            "https://github.com/lukas-krecan/ShedLock.git"
        )

    def test_plain_https_untouched(self):
        assert self._repo_url("https://github.com/psf/requests") == "https://github.com/psf/requests"

    def test_git_plus_https_prefix_stripped(self):
        assert self._repo_url("git+https://github.com/acme/lib.git") == "https://github.com/acme/lib.git"

    def test_garbage_is_dropped(self):
        assert self._repo_url("not a url at all") is None


class TestSyftArtifactMetadata:
    """deb 'source' is a package name, not a URL."""

    def setup_method(self):
        self.parser = SBOMParser()

    def _parse_artifact(self, artifact: dict):
        sbom = {
            "descriptor": {"name": "syft", "version": "1.42.3"},
            "source": {"id": "src", "type": "directory", "target": "/build"},
            "artifacts": [artifact],
            "artifactRelationships": [],
        }
        return self.parser.parse(sbom).dependencies[0]

    def test_source_package_name_is_not_a_repository_url(self):
        dep = self._parse_artifact(
            {
                "id": "a1",
                "name": "libssl3",
                "version": "3.0.11",
                "type": "deb",
                "purl": "pkg:deb/debian/libssl3@3.0.11",
                "metadata": {"source": "openssl-src", "architecture": "amd64"},
            }
        )
        assert dep.repository_url is None

    def test_real_source_url_is_kept(self):
        dep = self._parse_artifact(
            {
                "id": "a1",
                "name": "some-lib",
                "version": "1.0",
                "type": "npm",
                "purl": "pkg:npm/some-lib@1.0",
                "metadata": {"source": "https://github.com/acme/some-lib"},
            }
        )
        assert dep.repository_url == "https://github.com/acme/some-lib"


class TestComponentAccounting:
    """Every input element the parser sees is a dependency, a labelled skip or a merge."""

    def setup_method(self):
        self.parser = SBOMParser()

    def test_crypto_assets_are_counted(self):
        result = self.parser.parse(
            _cyclonedx_with(
                [
                    {
                        "type": "cryptographic-asset",
                        "name": "AES-256-GCM",
                        "cryptoProperties": {"assetType": "algorithm"},
                    },
                    {"type": "library", "name": "lib", "version": "1.0", "purl": "pkg:npm/lib@1.0"},
                ]
            )
        )
        assert len(result.dependencies) == 1
        assert result.skipped_reasons.get("cryptographic-asset") == 1
        assert _accounted(result) == 2
        assert len(result.crypto_assets) == 1

    def test_syft_files_array_is_counted(self):
        sbom = {
            "descriptor": {"name": "syft", "version": "1.42.3"},
            "source": {"id": "src", "type": "directory", "target": "/build"},
            "artifacts": [{"id": "a1", "name": "lib", "version": "1.0", "type": "npm", "purl": "pkg:npm/lib@1.0"}],
            "artifactRelationships": [],
            "files": [{"id": "f1"}, {"id": "f2"}, {"id": "f3"}, {"id": "f4"}, {"id": "f5"}],
        }
        result = self.parser.parse(sbom)
        assert len(result.dependencies) == 1
        assert result.skipped_reasons.get("file") == 5
        assert _accounted(result) == 6

    def test_spdx_files_array_is_counted(self):
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [{"SPDXID": "SPDXRef-1", "name": "pkg", "versionInfo": "1.0"}],
            "files": [{"SPDXID": "SPDXRef-File-1", "fileName": "./src/main.py"}],
            "relationships": [],
        }
        result = self.parser.parse(sbom)
        assert len(result.dependencies) == 1
        assert result.skipped_reasons.get("file") == 1
        assert _accounted(result) == 2


class TestDetectFormatMalformed:
    """detect_format must not raise on structurally odd (but valid JSON) SBOMs; it falls through to UNKNOWN."""

    def setup_method(self):
        self.parser = SBOMParser()

    def test_components_first_element_not_dict(self):
        fmt = self.parser.detect_format({"components": [123, 456]})
        assert fmt == SBOMFormat.UNKNOWN

    def test_components_first_element_is_list(self):
        fmt = self.parser.detect_format({"components": [["nested"]]})
        assert fmt == SBOMFormat.UNKNOWN

    def test_source_is_string(self):
        fmt = self.parser.detect_format({"source": "some-string"})
        assert fmt == SBOMFormat.UNKNOWN

    def test_parse_does_not_raise_on_malformed(self):
        result = parse_sbom({"components": [123], "source": "x"})
        assert result is not None
        assert result.format == SBOMFormat.UNKNOWN


# Large enough that a list-membership dedupe makes about a million comparisons.
_DISTINCT = 1000
_LODASH_PURL = "pkg:npm/lodash@4.17.21"


def _lodash(**lists: list[str]) -> ParsedDependency:
    """Assigned after construction, because validation would turn the counted values into plain str."""
    dependency = ParsedDependency(name="lodash", version="4.17.21", purl=_LODASH_PURL)
    for attr, values in lists.items():
        setattr(dependency, attr, values)
    return dependency


class TestDuplicateMergeIsLinear:
    @pytest.mark.parametrize("attr", ["locations", "parent_components", "cpes"])
    def test_long_lists_merge_without_pairwise_comparison(self, attr):
        counted = counted_str_type()
        kept = _lodash(**{attr: [counted(f"a{i}") for i in range(_DISTINCT)]})
        duplicate = _lodash(**{attr: [*(counted(f"b{i}") for i in range(_DISTINCT)), counted("a0")]})

        merged, merged_count = merge_duplicate_dependencies([kept, duplicate])

        # The one value both lists carry is the only hash match.
        assert counted.comparisons == 1
        assert merged_count == 1
        expected = [f"a{i}" for i in range(_DISTINCT)] + [f"b{i}" for i in range(_DISTINCT)]
        assert getattr(merged[0], attr) == expected

    def test_many_duplicates_of_one_package_hash_its_list_once(self):
        counted = counted_str_type()
        kept = _lodash(parent_components=[counted(f"p{i}") for i in range(_DISTINCT)])
        duplicates = [_lodash(parent_components=[counted(f"q{i}")]) for i in range(_DISTINCT)]

        merged, merged_count = merge_duplicate_dependencies([kept, *duplicates])

        assert counted.comparisons == 0
        assert counted.hashes <= 4 * _DISTINCT
        assert merged_count == _DISTINCT
        expected = [f"p{i}" for i in range(_DISTINCT)] + [f"q{i}" for i in range(_DISTINCT)]
        assert merged[0].parent_components == expected

    def test_two_components_sharing_a_huge_fan_in_merge_linearly(self, monkeypatch):
        """Two copies of one package under different bom-refs, each depended on by every entry."""
        counted = counted_str_type()
        original = SBOMParser._parse_cyclonedx_component

        def _counted_purl(self, *args, **kwargs):
            parsed = original(self, *args, **kwargs)
            parsed.purl = counted(parsed.purl)
            return parsed

        monkeypatch.setattr(SBOMParser, "_parse_cyclonedx_component", _counted_purl)
        component = {"type": "library", "name": "lodash", "version": "4.17.21", "purl": _LODASH_PURL}
        parents = [
            {"type": "library", "name": f"p{i}", "version": "1.0.0", "bom-ref": f"p{i}", "purl": f"pkg:npm/p{i}@1.0.0"}
            for i in range(_DISTINCT)
        ]
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{**component, "bom-ref": "A"}, {**component, "bom-ref": "B"}, *parents],
            "dependencies": [{"ref": f"p{i}", "dependsOn": ["A", "B"]} for i in range(_DISTINCT)],
        }

        result = parse_sbom(sbom)

        # B's parent refs are the very key objects in A's list, so only the merge key compares.
        assert counted.comparisons == 1
        assert result.merged_components == 1
        assert result.dependencies[0].parent_components == [f"pkg:npm/p{i}@1.0.0" for i in range(_DISTINCT)]


class TestParserDedupeIsLinear:
    """Each per-component dedupe compares a value only on a hash match."""

    def test_cyclonedx_cpes(self):
        counted = counted_str_type()
        component = {
            "type": "library",
            "name": "lodash",
            "version": "4.17.21",
            "purl": _LODASH_PURL,
            "cpes": [counted(f"cpe:2.3:a:lodash:{i}") for i in range(_DISTINCT)],
        }

        result = parse_sbom({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [component]})

        assert counted.comparisons == 0
        assert result.dependencies[0].cpes == [f"cpe:2.3:a:lodash:{i}" for i in range(_DISTINCT)]

    def test_cyclonedx_property_cpes_locations_and_occurrences(self):
        counted = counted_str_type()
        component = {
            "type": "library",
            "name": "lodash",
            "version": "4.17.21",
            "purl": _LODASH_PURL,
            "properties": [
                *({"name": "syft:cpe23", "value": counted(f"cpe:{i}")} for i in range(_DISTINCT)),
                *({"name": f"syft:location:{i}:path", "value": counted(f"/prop/{i}")} for i in range(_DISTINCT)),
            ],
            "evidence": {"occurrences": [{"location": counted(f"/occ/{i}")} for i in range(_DISTINCT)]},
        }

        result = parse_sbom({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [component]})

        dependency = result.dependencies[0]
        assert counted.comparisons == 0
        assert dependency.cpes == [f"cpe:{i}" for i in range(_DISTINCT)]
        assert dependency.locations == [f"/prop/{i}" for i in range(_DISTINCT)] + [
            f"/occ/{i}" for i in range(_DISTINCT)
        ]

    def test_syft_locations(self):
        counted = counted_str_type()
        artifact = {
            "id": "lodash",
            "name": "lodash",
            "version": "4.17.21",
            "type": "npm",
            "purl": _LODASH_PURL,
            "locations": [{"path": counted(f"/loc/{i}")} for i in range(_DISTINCT)],
        }

        result = parse_sbom({"descriptor": {"name": "syft"}, "source": {}, "artifacts": [artifact]})

        assert counted.comparisons == 0
        assert result.dependencies[0].locations == [f"/loc/{i}" for i in range(_DISTINCT)]

    def test_spdx_parent_refs(self, monkeypatch):
        counted = counted_str_type()
        original = SBOMParser._parse_spdx_package

        def _counted_purl(self, *args, **kwargs):
            parsed = original(self, *args, **kwargs)
            parsed.purl = counted(parsed.purl)
            return parsed

        monkeypatch.setattr(SBOMParser, "_parse_spdx_package", _counted_purl)
        packages = [_spdx_package("child"), *(_spdx_package(f"p{i}") for i in range(_DISTINCT))]
        relationships = [
            {"spdxElementId": f"SPDXRef-p{i}", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-child"}
            for i in range(_DISTINCT)
        ]
        sbom = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": packages}

        result = parse_sbom({**sbom, "relationships": relationships})

        child = next(dep for dep in result.dependencies if dep.name == "child")
        assert counted.comparisons == 0
        assert child.parent_components == [f"pkg:npm/p{i}@1.0.0" for i in range(_DISTINCT)]

    def test_syft_parent_refs(self, monkeypatch):
        counted = counted_str_type()
        original = SBOMParser._parse_syft_artifact

        def _counted_purl(self, *args, **kwargs):
            parsed = original(self, *args, **kwargs)
            parsed.purl = counted(parsed.purl)
            return parsed

        monkeypatch.setattr(SBOMParser, "_parse_syft_artifact", _counted_purl)
        artifacts = [_syft_artifact("child"), *(_syft_artifact(f"p{i}") for i in range(_DISTINCT))]
        relationships = [{"parent": f"p{i}", "child": "child", "type": "depends-on"} for i in range(_DISTINCT)]
        sbom = {"descriptor": {"name": "syft"}, "source": {"id": "src"}, "artifacts": artifacts}

        result = parse_sbom({**sbom, "artifactRelationships": relationships})

        child = next(dep for dep in result.dependencies if dep.name == "child")
        assert counted.comparisons == 0
        assert child.parent_components == [f"pkg:npm/p{i}@1.0.0" for i in range(_DISTINCT)]


def _spdx_package(name: str) -> dict:
    return {
        "SPDXID": f"SPDXRef-{name}",
        "name": name,
        "versionInfo": "1.0.0",
        "externalRefs": [{"referenceType": "purl", "referenceLocator": f"pkg:npm/{name}@1.0.0"}],
    }


def _syft_artifact(name: str) -> dict:
    return {"id": name, "name": name, "version": "1.0.0", "type": "npm", "purl": f"pkg:npm/{name}@1.0.0"}


class TestCycloneDXNpmScope:
    def test_a_scoped_npm_component_keeps_its_scope_in_the_name(self):
        result = parse_sbom(
            _cyclonedx_with(
                [
                    {
                        "type": "library",
                        "group": "@angular",
                        "name": "core",
                        "version": "16.2.0",
                        "purl": "pkg:npm/%40angular/core@16.2.0",
                    }
                ]
            )
        )

        [dep] = result.dependencies
        assert (dep.name, dep.group) == ("@angular/core", "@angular")

    def test_a_maven_group_stays_in_its_own_field(self):
        result = parse_sbom(
            _cyclonedx_with(
                [
                    {
                        "type": "library",
                        "group": "org.jetbrains",
                        "name": "annotations",
                        "version": "24.0.1",
                        "purl": "pkg:maven/org.jetbrains/annotations@24.0.1",
                    }
                ]
            )
        )

        [dep] = result.dependencies
        assert (dep.name, dep.group) == ("annotations", "org.jetbrains")


def _syft_cyclonedx() -> dict:
    """syft's CycloneDX output: bom-refs are purls carrying a package-id qualifier."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "container", "name": "app", "bom-ref": "root-ref"}},
        "components": [
            {
                "type": "library",
                "name": "express",
                "version": "4.18.2",
                "bom-ref": "pkg:npm/express@4.18.2?package-id=aaa",
                "purl": "pkg:npm/express@4.18.2",
            },
            {
                "type": "library",
                "name": "body-parser",
                "version": "1.20.1",
                "bom-ref": "pkg:npm/body-parser@1.20.1?package-id=bbb",
                "purl": "pkg:npm/body-parser@1.20.1",
            },
        ],
        "dependencies": [
            {"ref": "root-ref", "dependsOn": ["pkg:npm/express@4.18.2?package-id=aaa"]},
            {
                "ref": "pkg:npm/express@4.18.2?package-id=aaa",
                "dependsOn": ["pkg:npm/body-parser@1.20.1?package-id=bbb"],
            },
            {"ref": "0b9c3e2a-lockfile-uuid", "dependsOn": ["pkg:npm/body-parser@1.20.1?package-id=bbb"]},
        ],
    }


def _npm_cyclonedx() -> dict:
    """cyclonedx-npm output: bom-refs are name@version paths, not purls."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "app@1.0.0"}},
        "components": [
            {"type": "library", "name": "express", "version": "4.18.2", "bom-ref": "app@1.0.0|express@4.18.2"},
            {
                "type": "library",
                "name": "body-parser",
                "version": "1.20.1",
                "bom-ref": "app@1.0.0|express@4.18.2|body-parser@1.20.1",
                "purl": "pkg:npm/body-parser@1.20.1",
            },
        ],
        "dependencies": [
            {"ref": "app@1.0.0", "dependsOn": ["app@1.0.0|express@4.18.2"]},
            {"ref": "app@1.0.0|express@4.18.2", "dependsOn": ["app@1.0.0|express@4.18.2|body-parser@1.20.1"]},
        ],
    }


def _express_syft_json() -> dict:
    artifacts = [
        {"id": "a-express", "name": "express", "version": "4.18.2", "type": "npm", "purl": "pkg:npm/express@4.18.2"},
        {
            "id": "a-body",
            "name": "body-parser",
            "version": "1.20.1",
            "type": "npm",
            "purl": "pkg:npm/body-parser@1.20.1",
        },
    ]
    return {
        "descriptor": {"name": "syft"},
        "source": {"id": "src"},
        "artifacts": artifacts,
        "artifactRelationships": [
            {"parent": "src", "child": "a-express", "type": "depends-on"},
            {"parent": "a-express", "child": "a-body", "type": "depends-on"},
        ],
    }


def _express_spdx() -> dict:
    packages = [_spdx_package("app"), _spdx_package("express"), _spdx_package("body-parser")]
    edges = [
        ("DOCUMENT", "DESCRIBES", "app"),
        ("app", "DEPENDS_ON", "express"),
        ("express", "DEPENDS_ON", "body-parser"),
    ]
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": packages,
        "relationships": [
            {"spdxElementId": f"SPDXRef-{a}", "relationshipType": kind, "relatedSpdxElement": f"SPDXRef-{b}"}
            for a, kind, b in edges
        ],
    }


class TestCycloneDXParentRefs:
    def test_parents_are_stored_as_the_parent_s_node_key(self):
        deps = {d.name: d for d in parse_sbom(_syft_cyclonedx()).dependencies}

        assert deps["body-parser"].parent_components == ["pkg:npm/express@4.18.2"]
        assert deps["express"].parent_components == []

    @pytest.mark.parametrize(
        "sbom",
        [_syft_cyclonedx(), _npm_cyclonedx(), _express_syft_json(), _express_spdx()],
        ids=["cyclonedx-syft", "cyclonedx-npm", "syft-json", "spdx"],
    )
    def test_the_dependency_tree_nests_every_sbom_format(self, sbom):
        from app.api.v1.endpoints.analytics.dependencies import _build_dependency_graph
        from app.services.dependency_store import _parsed_dep_to_dependency

        now = datetime.now(timezone.utc)
        dependencies = [_parsed_dep_to_dependency(d, "p", "s", now) for d in parse_sbom(sbom).dependencies]
        graph = _build_dependency_graph(dependencies, {}, len(dependencies))

        nodes = {node.name: node for node in graph.nodes}
        assert nodes["express"].child_ids == [nodes["body-parser"].id]
        assert graph.roots == [nodes["express"].id]

    def test_chain_and_cycle_analysis_read_a_syft_cyclonedx_graph(self):
        import itertools

        from app.services.recommendation.graph import analyze_deep_dependency_chains

        names = [f"p{i}" for i in range(4)]
        ref = {name: f"pkg:npm/{name}@1.0.0?package-id={name}" for name in names}
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"component": {"type": "container", "name": "app", "bom-ref": "root-ref"}},
            "components": [
                {"type": "library", "name": n, "version": "1.0.0", "bom-ref": ref[n], "purl": f"pkg:npm/{n}@1.0.0"}
                for n in names
            ],
            "dependencies": [
                {"ref": "root-ref", "dependsOn": [ref["p0"]]},
                *({"ref": ref[a], "dependsOn": [ref[b]]} for a, b in itertools.pairwise(names)),
                {"ref": ref["p3"], "dependsOn": [ref["p2"]]},
            ],
        }
        dependencies = [d.to_dict() for d in parse_sbom(sbom).dependencies]

        titles = sorted(r.title for r in analyze_deep_dependency_chains(dependencies, max_dependency_depth=3))

        assert titles == [
            "Circular dependencies detected (2 packages)",
            "Deep dependency chains detected (max depth: 4)",
        ]


class TestComponentSource:
    @pytest.mark.parametrize(
        ("purl", "pkg_type", "layer_digest", "scan_source", "expected"),
        [
            pytest.param("pkg:deb/debian/libssl@1.0", "library", None, "directory", "directory", id="deb-dir-scan"),
            pytest.param("pkg:deb/debian/libssl@1.0", "library", "sha256:ab", None, "image", id="deb-in-a-layer"),
            pytest.param("pkg:rpm/redhat/bash@5", "library", None, "image", "image", id="rpm-image-scan"),
            pytest.param(None, "APK", None, "image", "image", id="declared-os-type"),
            pytest.param("pkg:npm/lodash@4", "deb", None, "image", "application", id="purl-type-wins"),
        ],
    )
    def test_os_packages_are_image_only_in_an_image_context(self, purl, pkg_type, layer_digest, scan_source, expected):
        assert SBOMParser()._determine_component_source(purl, pkg_type, layer_digest, scan_source) == expected


_AOPALLIANCE_SHA1 = "0235ba8b489512805ac13a8f9ea77a1ca5ebe3e8"
_AOPALLIANCE_JAR = "/private/tmp/w3b-syft/proj/aopalliance-1.0.jar"


def _syft_142_artifacts() -> list[dict]:
    """Artifacts as syft 1.42.1 writes them for a jar, npm/yarn/pnpm lockfiles, Cargo.lock and composer.lock."""
    return [
        {
            "id": "8552ae7062d051b8",
            "name": "aopalliance",
            "version": "1.0",
            "type": "java-archive",
            "foundBy": "java-archive-cataloger",
            "locations": [
                {"path": _AOPALLIANCE_JAR, "accessPath": _AOPALLIANCE_JAR, "annotations": {"evidence": "primary"}}
            ],
            "licenses": [],
            "language": "java",
            "cpes": [
                {"cpe": "cpe:2.3:a:aopalliance:aopalliance:1.0:*:*:*:*:*:*:*", "source": "syft-generated"},
                {"cpe": "cpe:2.3:a:aopalliance:aopalliance:1.0:*:*:*:*:*:*:*", "source": "syft-generated"},
            ],
            "purl": "pkg:maven/aopalliance/aopalliance@1.0",
            "metadataType": "java-archive",
            "metadata": {
                "virtualPath": _AOPALLIANCE_JAR,
                "manifest": {"main": [{"key": "Manifest-Version", "value": "1.0"}]},
                "digest": [{"algorithm": "sha1", "value": _AOPALLIANCE_SHA1}],
            },
        },
        {
            "id": "676e218c311d0cdc",
            "name": "lodash",
            "version": "4.17.21",
            "type": "npm",
            "foundBy": "javascript-lock-cataloger",
            "locations": [{"path": "/package-lock.json", "accessPath": "/package-lock.json"}],
            "licenses": [],
            "language": "javascript",
            "cpes": [{"cpe": "cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*", "source": "syft-generated"}],
            "purl": "pkg:npm/lodash@4.17.21",
            "metadataType": "javascript-npm-package-lock-entry",
            "metadata": {
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",
                "dependencies": None,
            },
        },
        {
            "id": "0b45582a9b830905",
            "name": "ms",
            "version": "2.1.3",
            "type": "npm",
            "foundBy": "javascript-lock-cataloger",
            "locations": [{"path": "/yarn.lock", "accessPath": "/yarn.lock"}],
            "licenses": [],
            "language": "javascript",
            "cpes": [],
            "purl": "pkg:npm/ms@2.1.3",
            "metadataType": "javascript-yarn-lock-entry",
            "metadata": {
                "resolved": "https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz",
                "integrity": "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==",
                "dependencies": {},
            },
        },
        {
            "id": "f8f75ae760ba5aeb",
            "name": "debug",
            "version": "4.3.4",
            "type": "npm",
            "foundBy": "javascript-lock-cataloger",
            "locations": [{"path": "/pnpm-lock.yaml", "accessPath": "/pnpm-lock.yaml"}],
            "licenses": [],
            "language": "javascript",
            "cpes": [],
            "purl": "pkg:npm/debug@4.3.4",
            "metadataType": "javascript-pnpm-lock-entry",
            "metadata": {
                "resolution": {
                    "integrity": "sha512-PRWFHuSU3eDtQJPvnNY7Jcket1j0t5OuOsFzPPzsekD52Zl8qUfFIPEiswXqIvHWGVHOgX+7G/vCNNhehwxfkQ=="
                },
                "dependencies": {},
            },
        },
        {
            "id": "6ce1453c37754295",
            "name": "itoa",
            "version": "1.0.11",
            "type": "rust-crate",
            "foundBy": "rust-cargo-lock-cataloger",
            "locations": [{"path": "/Cargo.lock", "accessPath": "/Cargo.lock"}],
            "licenses": [],
            "language": "rust",
            "cpes": [],
            "purl": "pkg:cargo/itoa@1.0.11",
            "metadataType": "rust-cargo-lock-entry",
            "metadata": {
                "name": "itoa",
                "version": "1.0.11",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "checksum": "49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b",
                "dependencies": [],
            },
        },
        {
            "id": "55bbf18cf4ab1368",
            "name": "monolog/monolog",
            "version": "3.5.0",
            "type": "php-composer",
            "foundBy": "php-composer-lock-cataloger",
            "locations": [{"path": "/composer.lock", "accessPath": "/composer.lock"}],
            "licenses": [],
            "language": "php",
            "cpes": [],
            "purl": "pkg:composer/monolog/monolog@3.5.0",
            "metadataType": "php-composer-lock-entry",
            "metadata": {
                "name": "monolog/monolog",
                "version": "3.5.0",
                "source": {
                    "type": "git",
                    "url": "https://github.com/Seldaek/monolog.git",
                    "reference": "c915e2634718dbc8a4a15c61b0e62e7a44e14448",
                },
                "type": "library",
                "authors": [{"name": "Jordi Boggiano", "email": "j.boggiano@seld.be", "homepage": "https://seld.be"}],
                "description": "Sends your logs to files, sockets, inboxes, databases and various web services",
                "homepage": "https://github.com/Seldaek/monolog",
            },
        },
    ]


def _syft_142_json(artifacts: list[dict] | None = None, source: dict | None = None) -> dict:
    return {
        "artifacts": _syft_142_artifacts() if artifacts is None else artifacts,
        "artifactRelationships": [],
        "source": source
        or {
            "id": "e73c023a2e8e90349bb4d853730e1bfc878257475334825422f01a09830de3b6",
            "name": "proj",
            "version": "",
            "type": "directory",
            "metadata": {"path": "proj"},
        },
        "distro": {},
        "descriptor": {"name": "syft", "version": "1.42.1"},
        "schema": {
            "version": "16.0.43",
            "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.43.json",
        },
    }


class TestSyftJsonRealShapes:
    def setup_method(self):
        self.result = parse_sbom(_syft_142_json())
        self.deps = {d.name: d for d in self.result.dependencies}

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            pytest.param("aopalliance", {"sha1": _AOPALLIANCE_SHA1}, id="jar-digest"),
            pytest.param(
                "lodash",
                {
                    "sha512": "bf690311ee7b95e713ba568322e3533f2dd1cb880b189e99d4edef13592b81764daec43e2c54c61d5c558dc5cfb35ecb85b65519e74026ff17675b6f8f916f4a"
                },
                id="npm-lock-integrity",
            ),
            pytest.param(
                "ms",
                {
                    "sha512": "e85973b9b4cb646dc9d9afcd542025784863ceae68c601f268253dc985ef70bb2fa1568726afece715c8ebf5d73fab73ed1f7100eb479d23bfb57b45dd645394"
                },
                id="yarn-integrity",
            ),
            pytest.param(
                "debug",
                {
                    "sha512": "3d15851ee494dde0ed4093ef9cd63b25c91eb758f4b793ae3ac1733cfcec7a40f9d9997ca947c520f122b305ea22f1d61951ce817fbb1bfbc234d85e870c5f91"
                },
                id="pnpm-resolution-integrity",
            ),
            pytest.param(
                "itoa",
                {"sha256": "49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b"},
                id="cargo-checksum",
            ),
        ],
    )
    def test_hashes_come_from_every_syft_metadata_shape(self, name, expected):
        assert self.deps[name].hashes == expected

    def test_composer_object_authors_keep_the_package(self):
        assert self.result.skipped_reasons == {}
        assert self.deps["monolog/monolog"].author == "Jordi Boggiano"

    def test_directory_source_target_comes_from_metadata_path(self):
        assert (self.result.source_type, self.result.source_target) == ("directory", "proj")
        assert self.deps["lodash"].source_target == "proj"

    def test_group_comes_from_the_purl_namespace(self):
        assert self.deps["aopalliance"].group == "aopalliance"
        assert self.deps["monolog/monolog"].group == "monolog"
        assert self.deps["lodash"].group is None

    def test_repeated_cpes_are_stored_once(self):
        assert self.deps["aopalliance"].cpes == ["cpe:2.3:a:aopalliance:aopalliance:1.0:*:*:*:*:*:*:*"]

    def test_no_raw_properties_are_stored(self):
        assert all(dep.properties == {} for dep in self.result.dependencies)

    def test_a_symlinked_location_keeps_its_real_path(self):
        [artifact] = [a for a in _syft_142_artifacts() if a["name"] == "aopalliance"]
        artifact["locations"] = [{"path": "/usr/lib/libx.so.1.2", "accessPath": "/usr/lib/libx.so.1"}]
        [dep] = parse_sbom(_syft_142_json([artifact])).dependencies
        assert dep.locations == ["/usr/lib/libx.so.1.2"]

    def test_placeholder_version_falls_back_to_the_purl_version(self):
        [artifact] = [a for a in _syft_142_artifacts() if a["name"] == "lodash"]
        artifact["version"] = ""
        [dep] = parse_sbom(_syft_142_json([artifact])).dependencies
        assert dep.version == "4.17.21"


def _syft_060_alpine_image() -> dict:
    """syft 0.60 (JSON schema 5): an image source keeps its details in a `target` object."""
    return {
        "artifacts": [
            {
                "id": "3d3fbd2b8d1f7e44",
                "name": "busybox",
                "version": "1.35.0-r29",
                "type": "apk",
                "foundBy": "apkdb-cataloger",
                "locations": [
                    {
                        "path": "/lib/apk/db/installed",
                        "layerID": "sha256:ded7a220bb058e28ee3254fbba04ca90b679070424424761a53a043b93b612bf",
                    }
                ],
                "licenses": ["GPL-2.0-only"],
                "language": "",
                "cpes": ["cpe:2.3:a:busybox:busybox:1.35.0-r29:*:*:*:*:*:*:*"],
                "purl": "pkg:apk/alpine/busybox@1.35.0-r29?arch=x86_64&upstream=busybox&distro=alpine-3.17.0",
                "metadataType": "ApkMetadata",
                "metadata": {
                    "package": "busybox",
                    "originPackage": "busybox",
                    "version": "1.35.0-r29",
                    "license": "GPL-2.0-only",
                    "architecture": "x86_64",
                    "url": "https://busybox.net/",
                    "description": "Size optimized toolbox of many common UNIX utilities",
                },
            }
        ],
        "artifactRelationships": [],
        "source": {
            "type": "image",
            "target": {
                "userInput": "alpine:3.17",
                "imageID": "sha256:042a816809aac8d0f7d7cacac7965782ee2ecac3f21bcf9f24b1de1a7387b769",
                "manifestDigest": "sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "tags": ["alpine:3.17"],
                "imageSize": 7049701,
                "repoDigests": ["alpine@sha256:f271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a"],
                "architecture": "amd64",
                "os": "linux",
            },
        },
        "distro": {"name": "alpine", "version": "3.17.0", "idLike": []},
        "descriptor": {"name": "syft", "version": "0.60.3"},
        "schema": {
            "version": "5.0.0",
            "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-5.0.0.json",
        },
    }


class TestSyftSourceShapes:
    def test_legacy_image_target_object_yields_the_image_reference(self):
        result = parse_sbom(_syft_060_alpine_image())
        assert result.skipped_reasons == {}
        assert (result.source_type, result.source_target) == ("image", "alpine:3.17")
        [dep] = result.dependencies
        assert (dep.name, dep.source_target, dep.source_type) == ("busybox", "alpine:3.17", "image")

    def test_current_image_source_reads_metadata_user_input(self):
        source = {
            "id": "sha256:91ef0af61f39ece4d6710e465df5ed6ca12112358344fd51ae6a3b886634148b",
            "name": "alpine",
            "version": "3.20",
            "type": "image",
            "metadata": {
                "userInput": "alpine:3.20",
                "imageID": "sha256:91ef0af61f39ece4d6710e465df5ed6ca12112358344fd51ae6a3b886634148b",
                "tags": ["alpine:3.20"],
                "architecture": "arm64",
                "os": "linux",
            },
        }
        result = parse_sbom(_syft_142_json(source=source))
        assert (result.source_type, result.source_target) == ("image", "alpine:3.20")

    def test_current_file_source_reads_metadata_path(self):
        source = {
            "id": "4e53b5e1c1a2b1f1",
            "name": "app.jar",
            "version": "sha256:7b1ffd2e48d3fce9e6e1b8a7a5f6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e",
            "type": "file",
            "metadata": {"path": "app.jar", "mimeType": "application/zip"},
        }
        result = parse_sbom(_syft_142_json(source=source))
        assert (result.source_type, result.source_target) == ("file", "app.jar")


def _syft_package_json_artifact(aid: str, name: str, version: str, metadata: dict) -> dict:
    return {
        "id": aid,
        "name": name,
        "version": version,
        "type": "npm",
        "foundBy": "javascript-package-cataloger",
        "locations": [{"path": f"/app/node_modules/{name}/package.json"}],
        "licenses": [],
        "language": "javascript",
        "cpes": [],
        "purl": f"pkg:npm/{name}@{version}",
        "metadataType": "javascript-npm-package",
        "metadata": {"name": name, "version": version, "private": False, **metadata},
    }


class TestSyftRepositoryUrls:
    def setup_method(self):
        artifacts = [
            _syft_package_json_artifact(
                "a-lodash",
                "lodash",
                "4.17.21",
                {
                    "author": "John-David Dalton <john.david.dalton@gmail.com>",
                    "homepage": "https://lodash.com/",
                    "description": "Lodash modular utilities.",
                    "url": "git+https://github.com/lodash/lodash.git",
                },
            ),
            _syft_package_json_artifact(
                "a-debug", "debug", "4.3.4", {"url": "git+ssh://git@github.com/debug-js/debug.git"}
            ),
            {
                "id": "a-zlib-apk",
                "name": "zlib",
                "version": "1.3.1-r0",
                "type": "apk",
                "foundBy": "apk-db-cataloger",
                "locations": [{"path": "/lib/apk/db/installed"}],
                "licenses": [],
                "cpes": [],
                "purl": "pkg:apk/alpine/zlib@1.3.1-r0?arch=x86_64&distro=alpine-3.20.0",
                "metadataType": "apk-db-entry",
                "metadata": {"package": "zlib", "originPackage": "zlib", "url": "https://zlib.net/"},
            },
            {
                "id": "a-zlib-deb",
                "name": "zlib1g",
                "version": "1:1.2.13.dfsg-1",
                "type": "deb",
                "foundBy": "dpkg-db-cataloger",
                "locations": [{"path": "/var/lib/dpkg/status"}],
                "licenses": [],
                "cpes": [],
                "purl": "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?arch=amd64&upstream=zlib&distro=debian-12",
                "metadataType": "dpkg-db-entry",
                "metadata": {"package": "zlib1g", "source": "zlib", "version": "1:1.2.13.dfsg-1"},
            },
        ]
        self.deps = {d.name: d for d in parse_sbom(_syft_142_json(artifacts)).dependencies}

    def test_npm_url_is_the_normalised_repository(self):
        lodash = self.deps["lodash"]
        assert (lodash.repository_url, lodash.homepage) == (
            "https://github.com/lodash/lodash.git",
            "https://lodash.com/",
        )

    def test_npm_ssh_url_is_normalised_and_never_a_homepage(self):
        debug = self.deps["debug"]
        assert (debug.repository_url, debug.homepage) == ("https://github.com/debug-js/debug.git", None)

    def test_apk_url_stays_the_homepage(self):
        assert (self.deps["zlib"].homepage, self.deps["zlib"].repository_url) == ("https://zlib.net/", None)

    def test_deb_source_package_name_is_no_url(self):
        assert (self.deps["zlib1g"].homepage, self.deps["zlib1g"].repository_url) == (None, None)


class TestSyftPurlLessIdentity:
    @pytest.mark.parametrize(
        ("syft_type", "name", "version", "purl", "dep_type"),
        [
            pytest.param("python", "urllib3", "2.0.0", "pkg:pypi/urllib3@2.0.0", "pypi", id="python"),
            pytest.param("rust-crate", "itoa", "1.0.11", "pkg:cargo/itoa@1.0.11", "cargo", id="rust-crate"),
            pytest.param(
                "dotnet", "Newtonsoft.Json", "13.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3", "nuget", id="dotnet"
            ),
            pytest.param("go-module", "stdlib", "go1.22.5", "pkg:golang/stdlib@go1.22.5", "golang", id="go-module"),
        ],
    )
    def test_a_purl_less_artifact_gets_its_purl_ecosystem(self, syft_type, name, version, purl, dep_type):
        artifact = {"id": "a1", "name": name, "version": version, "type": syft_type, "purl": "", "cpes": []}
        [dep] = parse_sbom(_syft_142_json([artifact])).dependencies
        assert (dep.purl, dep.type, dep.source_type) == (purl, dep_type, "application")

    def _binary(self, version: str) -> dict:
        return {
            "id": "b1",
            "name": "node",
            "version": version,
            "type": "binary",
            "foundBy": "binary-classifier-cataloger",
            "locations": [{"path": "/usr/local/bin/node"}],
            "licenses": [],
            "cpes": [{"cpe": "cpe:2.3:a:nodejs:node.js:20.11.1:*:*:*:*:*:*:*", "source": "syft-generated"}],
            "purl": "",
            "metadataType": "binary-signature",
            "metadata": {"matches": [{"classifier": "nodejs-binary", "location": {"path": "/usr/local/bin/node"}}]},
        }

    def test_a_binary_with_a_cpe_keeps_no_fabricated_purl(self):
        [dep] = parse_sbom(_syft_142_json([self._binary("20.11.1")])).dependencies
        assert (dep.purl, dep.type, dep.cpes) == (None, "generic", ["cpe:2.3:a:nodejs:node.js:20.11.1:*:*:*:*:*:*:*"])

    def test_a_versionless_binary_with_a_cpe_is_kept_like_in_cyclonedx(self):
        [dep] = parse_sbom(_syft_142_json([self._binary("")])).dependencies
        assert (dep.name, dep.purl, dep.version) == ("node", None, "unknown")


class TestCycloneDXFieldExtraction:
    def test_distribution_hashes_are_kept_first_file_per_algorithm(self):
        # cyclonedx-py 4.x puts every lockfile hash only on distribution references.
        component = {
            "bom-ref": "requests==2.32.3",
            "type": "library",
            "name": "requests",
            "version": "2.32.3",
            "purl": "pkg:pypi/requests@2.32.3",
            "externalReferences": [
                {
                    "comment": "file: requests-2.32.3-py3-none-any.whl",
                    "hashes": [
                        {
                            "alg": "SHA-256",
                            "content": "70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6",
                        }
                    ],
                    "type": "distribution",
                    "url": "https://files.pythonhosted.org/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfd6f7bf257d4a6a2a686d80da4d54/requests-2.32.3-py3-none-any.whl",
                },
                {
                    "comment": "file: requests-2.32.3.tar.gz",
                    "hashes": [
                        {
                            "alg": "SHA-256",
                            "content": "55365417734eb18255590a9ff9eb97e9e1da868d4ccd6402399eaf68af20a760",
                        }
                    ],
                    "type": "distribution",
                    "url": "https://files.pythonhosted.org/packages/63/70/2bf7780ad2d390a8d301ad0b550f1581eadbd9a20f896afe06353c2a2913/requests-2.32.3.tar.gz",
                },
            ],
        }
        [dep] = parse_sbom(_cyclonedx_with([component])).dependencies
        assert dep.hashes == {"sha256": "70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6"}

    def test_component_hashes_use_the_canonical_algorithm_name(self):
        component = {
            "type": "library",
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "hashes": [{"alg": "SHA-512", "content": "bf690311ee7b95e7"}],
        }
        [dep] = parse_sbom(_cyclonedx_with([component])).dependencies
        assert dep.hashes == {"sha512": "bf690311ee7b95e7"}

    def test_cyclonedx_16_authors_and_supplier(self):
        component = {
            "type": "library",
            "name": "acme-lib",
            "version": "1.0.0",
            "purl": "pkg:maven/com.acme/acme-lib@1.0.0",
            "authors": [{"name": "Alice", "email": "alice@acme.example"}, {"email": "bob@acme.example"}],
            "supplier": {"name": "ACME", "url": ["https://acme.example"]},
        }
        [dep] = parse_sbom(_cyclonedx_with([component])).dependencies
        assert (dep.author, dep.publisher) == ("Alice, bob@acme.example", "ACME")

    def test_digest_pinned_container_joins_with_at(self):
        root = {
            "bom-ref": "b1a1a4fb7bd1d6c2",
            "type": "container",
            "name": "registry.example.com/team/app",
            "version": "sha256:9b2c1f0e5d8a7b6c4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d",
        }
        result = parse_sbom(
            _cyclonedx_with([{"type": "library", "name": "dep", "version": "1", "purl": "pkg:npm/dep@1"}], root=root)
        )
        assert result.source_target == (
            "registry.example.com/team/app@sha256:9b2c1f0e5d8a7b6c4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d"
        )

    def test_tagged_container_joins_with_colon(self):
        root = {"bom-ref": "r", "type": "container", "name": "registry.example.com/team/app", "version": "1.4.2"}
        result = parse_sbom(
            _cyclonedx_with([{"type": "library", "name": "dep", "version": "1", "purl": "pkg:npm/dep@1"}], root=root)
        )
        assert result.source_target == "registry.example.com/team/app:1.4.2"

    def test_npm_development_marker_becomes_scope_excluded(self):
        component = {
            "type": "library",
            "bom-ref": "jest@29.7.0",
            "name": "jest",
            "version": "29.7.0",
            "purl": "pkg:npm/jest@29.7.0",
            "properties": [
                {"name": "cdx:npm:package:path", "value": "node_modules/jest"},
                {"name": "cdx:npm:package:development", "value": "true"},
            ],
        }
        [dep] = parse_sbom(_cyclonedx_with([component])).dependencies
        assert (dep.scope, dep.properties) == ("excluded", {})

    def test_declared_scope_wins_over_the_development_marker(self):
        component = {
            "type": "library",
            "name": "jest",
            "version": "29.7.0",
            "purl": "pkg:npm/jest@29.7.0",
            "scope": "optional",
            "properties": [{"name": "cdx:npm:package:development", "value": "true"}],
        }
        [dep] = parse_sbom(_cyclonedx_with([component])).dependencies
        assert dep.scope == "optional"

    def test_only_trivy_source_package_properties_are_stored(self):
        component = {
            "bom-ref": "pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64&distro=debian-12.6",
            "type": "library",
            "name": "libc6",
            "version": "2.36-9+deb12u7",
            "purl": "pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64&distro=debian-12.6",
            "properties": [
                {
                    "name": "aquasecurity:trivy:LayerDiffID",
                    "value": "sha256:8e2ab394fabf557b00041a8f080b10b4e91c7027b7c174f095332c7ebb6501cb",
                },
                {
                    "name": "aquasecurity:trivy:LayerDigest",
                    "value": "sha256:e4fff0779e6ddd22366469f08626c3ab1884b5cbe1719b26da238c95f247b305",
                },
                {"name": "aquasecurity:trivy:PkgID", "value": "libc6@2.36-9+deb12u7"},
                {"name": "aquasecurity:trivy:PkgType", "value": "debian"},
                {"name": "aquasecurity:trivy:SrcName", "value": "glibc"},
                {"name": "aquasecurity:trivy:SrcRelease", "value": "9+deb12u7"},
                {"name": "aquasecurity:trivy:SrcVersion", "value": "2.36"},
            ],
        }
        [dep] = parse_sbom(_cyclonedx_with([component])).dependencies
        assert dep.properties == {
            "aquasecurity:trivy:SrcName": "glibc",
            "aquasecurity:trivy:SrcRelease": "9+deb12u7",
            "aquasecurity:trivy:SrcVersion": "2.36",
        }

    def test_a_name_already_carrying_its_scope_is_not_prefixed_again(self):
        component = {
            "type": "library",
            "group": "@angular",
            "name": "@angular/core",
            "version": "16.2.0",
            "purl": "pkg:npm/%40angular/core@16.2.0",
        }
        [dep] = parse_sbom(_cyclonedx_with([component])).dependencies
        assert dep.name == "@angular/core"

    @pytest.mark.parametrize(
        ("purl", "group"),
        [
            pytest.param("pkg:maven/commons-io/commons-io@2.1", "commons-io", id="maven"),
            pytest.param("pkg:golang/github.com/sirupsen/logrus@v1.9.3", None, id="golang-host"),
            pytest.param("pkg:deb/debian/libc6@2.36-9", None, id="distro-vendor"),
        ],
    )
    def test_group_falls_back_to_the_purl_namespace(self, purl, group):
        [dep] = parse_sbom(
            _cyclonedx_with([{"type": "library", "name": "x", "version": "1", "purl": purl}])
        ).dependencies
        assert dep.group == group

    def test_placeholder_version_falls_back_to_the_purl_version(self):
        component = {
            "type": "library",
            "name": "guava",
            "version": "UNKNOWN",
            "purl": "pkg:maven/com.google.guava/guava@33.0.0",
        }
        [dep] = parse_sbom(_cyclonedx_with([component])).dependencies
        assert dep.version == "33.0.0"


def _syft_142_spdx() -> dict:
    """syft 1.42.1 SPDX 2.3 JSON of a directory holding a jar and a composer.lock."""
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "proj",
        "documentNamespace": "https://anchore.com/syft/dir/proj-5b3b5d7e-8a2f-4f55-9b0e-0c5a1f1e2d3c",
        "creationInfo": {
            "licenseListVersion": "3.27",
            "creators": ["Organization: Anchore, Inc", "Tool: syft-1.42.1"],
            "created": "2026-09-29T10:12:44Z",
        },
        "packages": [
            {
                "name": "aopalliance",
                "SPDXID": "SPDXRef-Package-java-archive-aopalliance-8552ae7062d051b8",
                "versionInfo": "1.0",
                "supplier": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA1", "checksumValue": _AOPALLIANCE_SHA1}],
                "sourceInfo": f"acquired package info from installed java archive: {_AOPALLIANCE_JAR}",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "SECURITY",
                        "referenceType": "cpe23Type",
                        "referenceLocator": "cpe:2.3:a:aopalliance:aopalliance:1.0:*:*:*:*:*:*:*",
                    },
                    {
                        "referenceCategory": "SECURITY",
                        "referenceType": "cpe23Type",
                        "referenceLocator": "cpe:2.3:a:aopalliance:aopalliance:1.0:*:*:*:*:*:*:*",
                    },
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:maven/aopalliance/aopalliance@1.0",
                    },
                ],
            },
            {
                "name": "monolog/monolog",
                "SPDXID": "SPDXRef-Package-php-composer-monolog-monolog-55bbf18cf4ab1368",
                "versionInfo": "3.5.0",
                "supplier": "Person: Jordi Boggiano (j.boggiano@seld.be)",
                "originator": "Person: Jordi Boggiano (j.boggiano@seld.be)",
                "downloadLocation": "https://api.github.com/repos/Seldaek/monolog/zipball/c915e2634718dbc8a4a15c61b0e62e7a44e14448",
                "filesAnalyzed": False,
                "homepage": "https://github.com/Seldaek/monolog",
                "sourceInfo": "acquired package info from PHP composer manifest: /composer.lock",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "MIT",
                "copyrightText": "NOASSERTION",
                "description": "Sends your logs to files, sockets, inboxes, databases and various web services",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:composer/monolog/monolog@3.5.0",
                    }
                ],
            },
            {
                "name": "proj",
                "SPDXID": "SPDXRef-DocumentRoot-Directory-proj",
                "supplier": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "primaryPackagePurpose": "FILE",
            },
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DocumentRoot-Directory-proj",
                "relatedSpdxElement": "SPDXRef-Package-java-archive-aopalliance-8552ae7062d051b8",
                "relationshipType": "CONTAINS",
            },
            {
                "spdxElementId": "SPDXRef-DocumentRoot-Directory-proj",
                "relatedSpdxElement": "SPDXRef-Package-php-composer-monolog-monolog-55bbf18cf4ab1368",
                "relationshipType": "CONTAINS",
            },
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-DocumentRoot-Directory-proj",
                "relationshipType": "DESCRIBES",
            },
        ],
    }


class TestSPDXFieldExtraction:
    def setup_method(self):
        self.result = parse_sbom(_syft_142_spdx())
        self.deps = {d.name: d for d in self.result.dependencies}

    def test_checksums_use_the_canonical_algorithm_name(self):
        assert self.deps["aopalliance"].hashes == {"sha1": _AOPALLIANCE_SHA1}

    def test_syft_documents_keep_the_generator_as_found_by(self):
        assert {d.found_by for d in self.result.dependencies} == {"syft-1.42.1"}

    def test_other_generators_leave_found_by_empty(self):
        assert all(d.found_by is None for d in parse_sbom(_spdx_github_export()).dependencies)

    def test_repeated_cpes_are_stored_once(self):
        assert self.deps["aopalliance"].cpes == ["cpe:2.3:a:aopalliance:aopalliance:1.0:*:*:*:*:*:*:*"]

    def test_no_raw_properties_are_stored(self):
        assert all(dep.properties == {} for dep in self.result.dependencies)

    def test_person_originator_becomes_the_author(self):
        assert self.deps["monolog/monolog"].author == "Jordi Boggiano (j.boggiano@seld.be)"

    def test_none_homepage_and_download_location_are_dropped(self):
        package = {
            "SPDXID": "SPDXRef-Package-npm-left-pad",
            "name": "left-pad",
            "versionInfo": "1.3.0",
            "homepage": "NONE",
            "downloadLocation": "NONE",
            "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0"}],
        }
        [dep] = parse_sbom(
            {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": [package]}
        ).dependencies
        assert (dep.homepage, dep.download_url) == (None, None)

    def test_a_malformed_checksum_entry_keeps_the_package(self):
        package = {
            "SPDXID": "SPDXRef-Package-npm-left-pad",
            "name": "left-pad",
            "versionInfo": "1.3.0",
            "checksums": [
                "SHA1: 1e9b28b2c4b6b0fe0b3b2f4a1a6c1b3e6a8c9d0f",
                {"algorithm": "SHA256", "checksumValue": "abc123"},
            ],
            "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0"}],
        }
        result = parse_sbom({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": [package]})
        assert [d.hashes for d in result.dependencies] == [{"sha256": "abc123"}]

    @pytest.mark.parametrize(
        ("purl", "group"),
        [
            pytest.param("pkg:golang/github.com/sirupsen/logrus@v1.9.3", None, id="golang-host"),
            pytest.param("pkg:deb/debian/libc6@2.36-9", None, id="distro-vendor"),
            pytest.param("pkg:npm/%40angular/core@16.2.0", "@angular", id="npm-scope"),
        ],
    )
    def test_group_is_the_purl_namespace_only_where_it_names_the_package(self, purl, group):
        package = {
            "SPDXID": "SPDXRef-Package-x",
            "name": "x",
            "versionInfo": "1",
            "externalRefs": [{"referenceType": "purl", "referenceLocator": purl}],
        }
        [dep] = parse_sbom(
            {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": [package]}
        ).dependencies
        assert dep.group == group

    def test_trivy_operating_system_package_keeps_no_fabricated_purl(self):
        packages = [
            {
                "name": "debian",
                "SPDXID": "SPDXRef-OperatingSystem-2d8ad1a2b3c4d5e6",
                "versionInfo": "12.6",
                "downloadLocation": "NONE",
                "filesAnalyzed": False,
                "primaryPackagePurpose": "OPERATING-SYSTEM",
            },
            {
                "name": "Gemfile.lock",
                "SPDXID": "SPDXRef-Application-9f8e7d6c5b4a3210",
                "versionInfo": "1.0",
                "downloadLocation": "NONE",
                "filesAnalyzed": False,
                "primaryPackagePurpose": "APPLICATION",
            },
        ]
        result = parse_sbom({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": packages})
        assert [(d.name, d.purl) for d in result.dependencies] == [("debian", None)]
        assert result.skipped_reasons.get("unidentifiable") == 1
