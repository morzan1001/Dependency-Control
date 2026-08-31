"""Golden-fixture tests for the callgraph parsers, fed by captured real producer output."""

import json

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.callgraph import _parse_callgraph, _resolve_format
from app.api.v1.helpers.callgraph import (
    canonical_module_key,
    detect_format,
    parse_generic_format,
    parse_madge_format,
)
from app.services.aggregation.components import build_component_index, lookup_component
from app.services.reachability_enrichment import _normalize_component

# madge 8.0.0: `npx madge@latest --json --include-npm src` over a fixture tree with a real
# node_modules (lodash, @babel/core), then the template's jq merge of package.json deps.
MADGE_OUTPUT = """
{
  "index.js": [
    "../node_modules/@babel/core/index.js",
    "../node_modules/lodash/index.js",
    "utils.js"
  ],
  "utils.js": [],
  "__analyzed_modules__": [
    "@babel/core",
    "lodash"
  ]
}
"""

# The `.callgraph-python` ast scanner from callgraph.yaml, run over a fixture package with
# requests/urllib3/PyYAML installed. The scanner resolves each import back to its distribution
# name (yaml -> PyYAML), which is the spelling findings carry; analyzed_modules is trimmed to
# the three distributions of that package.
PYTHON_AST_OUTPUT = """
{
  "imports": [
    {"module": "requests", "file": "app/client.py", "line": 1, "symbols": []},
    {"module": "urllib3", "file": "app/client.py", "line": 2, "symbols": []},
    {"module": "urllib3", "file": "app/client.py", "line": 3, "symbols": ["Retry"]},
    {"module": "typing", "file": "app/helpers.py", "line": 1, "symbols": ["Any"]},
    {"module": "PyYAML", "file": "app/helpers.py", "line": 3, "symbols": []}
  ],
  "analyzed_modules": ["PyYAML", "requests", "urllib3"]
}
"""

# The `.callgraph-go` producer from callgraph.yaml over `go list -deps -json ./...` and
# `go list -m all` (go1.27.0) in a two-dependency fixture module.
GO_LIST_OUTPUT = """
{
  "imports": [
    {"module": "github.com/example/textkit", "file": "cmd", "line": 0, "symbols": []},
    {"module": "github.com/Masterminds/semver", "file": ".", "line": 0, "symbols": []},
    {"module": "github.com/example/textkit", "file": ".", "line": 0, "symbols": []}
  ],
  "analyzed_modules": ["github.com/Masterminds/semver", "github.com/example/textkit"]
}
"""

# The `.callgraph-java` producer from callgraph.yaml over real `jdeps -verbose:class -R`
# output (temurin 21) against two fixture jars carrying META-INF/maven pom.properties.
JDEPS_OUTPUT = """
{
  "imports": [
    {"module": "com.example:textkit", "file": "com.example.app.Main", "line": 0, "symbols": ["Text"]},
    {"module": "hdrhistogram:hdrhistogram", "file": "com.example.app.Main", "line": 0, "symbols": ["Histogram"]}
  ],
  "analyzed_modules": ["com.example:textkit", "hdrhistogram:hdrhistogram"]
}
"""

# Names that a directory-based parser would produce instead of package names.
PATH_ARTEFACTS = {"src", "lib", "utils", "utils.js", "index.js", "node_modules", "app", "cmd", ".", ""}


def _parse(payload: str, language: str):
    """Detect the format of a captured payload and run the parser the endpoint would pick."""
    data = json.loads(payload)
    return _parse_callgraph(detect_format(data), data, language)


class TestMadgeGoldenFixture:
    @pytest.fixture
    def data(self):
        return json.loads(MADGE_OUTPUT)

    def test_detect_format_is_madge(self, data):
        assert detect_format(data) == "madge"

    def test_analyzed_modules_key_is_not_a_file_entry(self, data):
        imports, _, _, _ = parse_madge_format(data, "javascript")
        assert "__analyzed_modules__" not in {entry.file for entry in imports}

    def test_module_usage_keys_are_package_names(self):
        _, _, module_usage, _ = _parse(MADGE_OUTPUT, "javascript")
        assert set(module_usage) == {"lodash", "@babel/core"}
        assert not set(module_usage) & PATH_ARTEFACTS

    def test_first_party_file_is_imported_but_not_a_module(self):
        imports, _, module_usage, _ = _parse(MADGE_OUTPUT, "javascript")
        assert "utils.js" in {entry.module for entry in imports}
        assert "utils.js" not in module_usage

    def test_import_locations_name_the_importing_file(self):
        _, _, module_usage, _ = _parse(MADGE_OUTPUT, "javascript")
        assert module_usage["lodash"].import_locations == ["index.js"]

    def test_analyzed_modules_survives(self):
        _, _, _, analyzed = _parse(MADGE_OUTPUT, "javascript")
        assert analyzed == ["@babel/core", "lodash"]


class TestPythonAstGoldenFixture:
    def test_detect_format_is_generic(self):
        assert detect_format(json.loads(PYTHON_AST_OUTPUT)) == "generic"

    def test_module_usage_keys_are_top_level_package_names(self):
        _, _, module_usage, _ = _parse(PYTHON_AST_OUTPUT, "python")
        assert set(module_usage) == {"requests", "urllib3", "typing", "pyyaml"}
        assert not set(module_usage) & PATH_ARTEFACTS

    def test_submodule_imports_collapse_onto_one_usage_entry(self):
        _, _, module_usage, _ = _parse(PYTHON_AST_OUTPUT, "python")
        assert module_usage["urllib3"].import_count == 2
        assert module_usage["urllib3"].import_locations == ["app/client.py"]

    def test_imported_symbols_land_in_used_symbols(self):
        _, _, module_usage, _ = _parse(PYTHON_AST_OUTPUT, "python")
        assert module_usage["urllib3"].used_symbols == ["Retry"]
        assert module_usage["typing"].used_symbols == ["Any"]

    def test_analyzed_modules_is_canonicalised(self):
        _, _, _, analyzed = _parse(PYTHON_AST_OUTPUT, "python")
        assert analyzed == ["pyyaml", "requests", "urllib3"]


class TestGoListGoldenFixture:
    def test_detect_format_is_generic(self):
        assert detect_format(json.loads(GO_LIST_OUTPUT)) == "generic"

    def test_module_usage_keys_are_full_module_paths(self):
        _, _, module_usage, _ = _parse(GO_LIST_OUTPUT, "go")
        assert set(module_usage) == {"github.com/example/textkit", "github.com/masterminds/semver"}
        assert not set(module_usage) & PATH_ARTEFACTS

    def test_same_module_imported_from_two_packages_counts_twice(self):
        _, _, module_usage, _ = _parse(GO_LIST_OUTPUT, "go")
        assert module_usage["github.com/example/textkit"].import_count == 2
        assert module_usage["github.com/example/textkit"].import_locations == ["cmd", "."]

    def test_analyzed_modules_survives_canonicalised(self):
        _, _, _, analyzed = _parse(GO_LIST_OUTPUT, "go")
        assert analyzed == ["github.com/masterminds/semver", "github.com/example/textkit"]


class TestJdepsGoldenFixture:
    def test_detect_format_is_generic(self):
        assert detect_format(json.loads(JDEPS_OUTPUT)) == "generic"

    def test_module_usage_keys_are_maven_coordinates(self):
        _, _, module_usage, _ = _parse(JDEPS_OUTPUT, "java")
        assert set(module_usage) == {"com.example:textkit", "hdrhistogram:hdrhistogram"}
        assert not set(module_usage) & PATH_ARTEFACTS

    def test_referenced_class_names_land_in_used_symbols(self):
        _, _, module_usage, _ = _parse(JDEPS_OUTPUT, "java")
        assert module_usage["com.example:textkit"].used_symbols == ["Text"]
        assert module_usage["hdrhistogram:hdrhistogram"].used_symbols == ["Histogram"]

    def test_analyzed_modules_survives(self):
        _, _, _, analyzed = _parse(JDEPS_OUTPUT, "java")
        assert analyzed == ["com.example:textkit", "hdrhistogram:hdrhistogram"]


class TestUniverseMeetsUsage:
    """A package the producer both published as covered and recorded as imported must resolve.

    When the two disagree the gate reads "analyzed but unused" and falsifies a package the code
    demonstrably imports, which is the one verdict that must never be wrong.
    """

    @pytest.mark.parametrize(
        ("payload", "language", "imported"),
        [
            (MADGE_OUTPUT, "javascript", ["lodash", "@babel/core"]),
            (PYTHON_AST_OUTPUT, "python", ["requests", "urllib3", "PyYAML"]),
            (GO_LIST_OUTPUT, "go", ["github.com/Masterminds/semver", "github.com/example/textkit"]),
            (JDEPS_OUTPUT, "java", ["com.example:textkit", "hdrhistogram:hdrhistogram"]),
        ],
    )
    def test_every_covered_and_imported_package_resolves_in_usage(self, payload, language, imported):
        _, _, module_usage, analyzed = _parse(payload, language)
        index = build_component_index(module_usage)
        for component in imported:
            assert canonical_module_key(component, language) in analyzed
            assert lookup_component(index, _normalize_component(component, language)) is not None


class TestWriteReadMeetingPoint:
    """The stored key must be the one enrichment computes from a finding's component name."""

    @pytest.mark.parametrize(
        ("component", "language"),
        [
            ("lodash", "javascript"),
            ("@babel/core", "javascript"),
            ("requests", "python"),
            ("urllib3", "python"),
            ("typing-extensions", "python"),
            ("ruamel.yaml", "python"),
            ("zope.interface", "python"),
            ("github.com/example/textkit", "go"),
            ("github.com/Masterminds/semver", "go"),
            ("github.com/BurntSushi/toml", "go"),
            ("com.example:textkit", "java"),
            ("HdrHistogram:HdrHistogram", "java"),
        ],
    )
    def test_canonical_key_equals_read_side_normalization(self, component, language):
        assert canonical_module_key(component, language) == _normalize_component(component, language)

    @pytest.mark.parametrize(
        ("stored", "component", "language"),
        [
            ("ruamel.yaml", "ruamel.yaml", "python"),
            ("github.com/Masterminds/semver", "github.com/Masterminds/semver", "go"),
        ],
    )
    def test_component_resolves_without_relying_on_the_artifact_alias(self, stored, component, language):
        """A same-suffix sibling suppresses the bare-name alias, so the key itself must match."""
        decoys = {"python": "ruamel.yaml.clib", "go": "github.com/blang/semver"}
        index = build_component_index(
            {canonical_module_key(name, language): True for name in (stored, decoys[language])}
        )
        assert lookup_component(index, component) or lookup_component(index, _normalize_component(component, language))

    @pytest.mark.parametrize(
        ("payload", "language", "component"),
        [
            (MADGE_OUTPUT, "javascript", "lodash"),
            (MADGE_OUTPUT, "javascript", "@babel/core"),
            (PYTHON_AST_OUTPUT, "python", "requests"),
            (PYTHON_AST_OUTPUT, "python", "urllib3"),
            (GO_LIST_OUTPUT, "go", "github.com/example/textkit"),
            (GO_LIST_OUTPUT, "go", "github.com/Masterminds/semver"),
            (JDEPS_OUTPUT, "java", "com.example:textkit"),
            (JDEPS_OUTPUT, "java", "HdrHistogram:HdrHistogram"),
        ],
    )
    def test_stored_usage_resolves_under_the_component_name(self, payload, language, component):
        parser = parse_madge_format if payload is MADGE_OUTPUT else parse_generic_format
        _, _, module_usage, _ = parser(json.loads(payload), language)
        index = build_component_index(module_usage)
        assert lookup_component(index, component) or lookup_component(index, _normalize_component(component, language))

    def test_analyzed_modules_resolve_under_the_component_name(self):
        _, _, _, analyzed = _parse(JDEPS_OUTPUT, "java")
        index = build_component_index(dict.fromkeys(analyzed, True))
        assert lookup_component(index, "HdrHistogram:HdrHistogram")


class TestFormatDetectionRegressions:
    def test_empty_payload_is_unknown(self):
        assert detect_format({}) == "unknown"

    def test_empty_payload_is_rejected_with_400(self):
        with pytest.raises(HTTPException) as exc:
            _resolve_format("auto", {})
        assert exc.value.status_code == 400

    def test_node_edge_payload_is_unknown(self):
        data = {"nodes": [{"id": "app.main"}], "edges": [{"from": "app.main", "to": "requests.get"}]}
        assert detect_format(data) == "unknown"

    def test_node_edge_payload_is_rejected_with_400(self):
        data = {"nodes": [{"id": "app.main"}], "edges": [{"from": "app.main", "to": "requests.get"}]}
        with pytest.raises(HTTPException) as exc:
            _resolve_format("auto", data)
        assert exc.value.status_code == 400

    def test_pyan_format_is_no_longer_parseable(self):
        with pytest.raises(HTTPException) as exc:
            _parse_callgraph("pyan", {}, "python")
        assert exc.value.status_code == 400
        assert "pyan" in exc.value.detail

    def test_empty_node_edge_payload_is_unknown(self):
        assert detect_format({"nodes": [], "edges": []}) == "unknown"

    def test_madge_without_dependencies_or_universe_is_unknown(self):
        assert detect_format({"src/index.ts": []}) == "unknown"

    def test_madge_without_dependencies_is_valid_alongside_a_universe(self):
        data = {"src/index.ts": [], "__analyzed_modules__": ["lodash"]}
        assert detect_format(data) == "madge"
        _, _, module_usage, analyzed_modules = parse_madge_format(data, "typescript")
        assert module_usage == {}
        assert analyzed_modules == ["lodash"]
