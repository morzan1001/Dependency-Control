"""Golden-fixture tests for the callgraph parsers, fed by captured real producer output."""

import json

import pytest
from bson import ObjectId
from fastapi import HTTPException

from app.api.v1.endpoints.callgraph import _parse_callgraph, _resolve_format
from app.api.v1.helpers.callgraph import (
    callgraph_entry_count,
    detect_format,
    parse_generic_format,
    parse_madge_format,
)
from app.services.component_identity import build_component_index, canonical_module_key, lookup_component
from app.schemas.projections import CallgraphMinimal
from app.services.reachability_enrichment import (
    _find_usage,
    _is_package_in_callgraph,
    _normalize_component,
    _prepare_callgraph,
)
from tests.helpers.comparisons import counted_str_type

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


def _prepared_python_callgraph(imports: list[dict], analyzed: list[str] | None = None):
    _, _, module_usage, analyzed_keys = parse_generic_format(
        {"imports": imports, "analyzed_modules": analyzed or []}, "python"
    )
    return _prepare_callgraph(
        CallgraphMinimal(
            _id=ObjectId(),
            language="python",
            module_usage={key: usage.model_dump() for key, usage in module_usage.items()},
            analyzed_modules=analyzed_keys,
        )
    )


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
        ("one", "sibling"),
        [("ruamel.yaml", "ruamel.yaml.clib"), ("zope.interface", "zope.component"), ("oslo.config", "oslo.messaging")],
    )
    def test_dotted_python_distributions_keep_distinct_keys(self, one, sibling):
        assert canonical_module_key(one, "python") != canonical_module_key(sibling, "python")

    def test_a_dotted_distribution_is_not_reachable_through_an_imported_sibling(self):
        prepared = _prepared_python_callgraph(
            [{"module": "zope.interface", "file": "app/models.py", "line": 1, "symbols": ["Interface"]}],
            analyzed=["zope.interface", "zope.component"],
        )

        assert _is_package_in_callgraph(prepared, "zope.interface")
        assert not _is_package_in_callgraph(prepared, "zope.component")

    def test_an_unresolved_submodule_import_counts_for_its_distribution(self):
        """Without the dependencies installed the producer emits the module path of a from-import."""
        prepared = _prepared_python_callgraph(
            [{"module": "urllib3.util.retry", "file": "app/client.py", "line": 4, "symbols": ["Retry"]}]
        )

        usage = _find_usage(prepared, "urllib3")
        assert usage["used_symbols"] == ["Retry"]
        assert usage["import_locations"] == ["app/client.py"]

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


NODE_EDGE_PAYLOAD = {"nodes": [{"id": "app.main"}], "edges": [{"from": "app.main", "to": "requests.get"}]}


class TestFormatDetectionRegressions:
    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param({}, id="empty_payload"),
            pytest.param(NODE_EDGE_PAYLOAD, id="node_edge_payload"),
            pytest.param({"nodes": [], "edges": []}, id="empty_node_edge_payload"),
            pytest.param({"src/index.ts": []}, id="madge_without_dependencies_or_universe"),
        ],
    )
    def test_payload_is_unknown(self, payload):
        assert detect_format(payload) == "unknown"

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param({}, id="empty_payload"),
            pytest.param(NODE_EDGE_PAYLOAD, id="node_edge_payload"),
        ],
    )
    def test_payload_is_rejected_with_400(self, payload):
        with pytest.raises(HTTPException) as exc:
            _resolve_format("auto", payload)
        assert exc.value.status_code == 400

    def test_pyan_format_is_no_longer_parseable(self):
        with pytest.raises(HTTPException) as exc:
            _parse_callgraph("pyan", {}, "python")
        assert exc.value.status_code == 400
        assert "pyan" in exc.value.detail

    def test_madge_without_dependencies_is_valid_alongside_a_universe(self):
        data = {"src/index.ts": [], "__analyzed_modules__": ["lodash"]}
        assert detect_format(data) == "madge"
        _, _, module_usage, analyzed_modules = parse_madge_format(data, "typescript")
        assert module_usage == {}
        assert analyzed_modules == ["lodash"]


# Large enough that a list-membership dedupe makes about two million comparisons.
_DISTINCT = 2000


class TestDedupeIsLinear:
    """Each dedupe compares a value only on a hash match, so distinct values cost no comparison."""

    def test_generic_import_symbols(self):
        counted = counted_str_type()
        symbols = [counted(f"sym{i}") for i in range(_DISTINCT)]
        data = {"imports": [{"module": "lodash", "file": "src/a.js", "line": 1, "symbols": symbols}]}

        _, _, module_usage, _ = parse_generic_format(data, "javascript")

        assert counted.comparisons == 0
        assert module_usage["lodash"].used_symbols == [f"sym{i}" for i in range(_DISTINCT)]

    def test_generic_call_symbols(self):
        counted = counted_str_type()
        calls = [{"callee_module": "lodash", "callee_function": counted(f"fn{i}")} for i in range(_DISTINCT)]

        _, _, module_usage, _ = parse_generic_format({"calls": calls}, "javascript")

        assert counted.comparisons == 0
        assert module_usage["lodash"].used_symbols == [f"fn{i}" for i in range(_DISTINCT)]

    def test_generic_import_locations(self):
        counted = counted_str_type()
        imports = [{"module": "lodash", "file": counted(f"src/f{i}.js"), "symbols": []} for i in range(_DISTINCT)]

        _, _, module_usage, _ = parse_generic_format({"imports": imports}, "javascript")

        assert counted.comparisons == 0
        assert module_usage["lodash"].import_locations == [f"src/f{i}.js" for i in range(_DISTINCT)]

    def test_madge_import_locations(self):
        counted = counted_str_type()
        data = {counted(f"src/f{i}.js"): ["node_modules/lodash/index.js"] for i in range(_DISTINCT)}

        _, _, module_usage, _ = parse_madge_format(data, "javascript")

        # Each file key is told apart from the analyzed-modules key once, and deduped without a comparison.
        assert counted.comparisons == _DISTINCT
        assert module_usage["lodash"].import_locations == [f"src/f{i}.js" for i in range(_DISTINCT)]

    def test_analyzed_modules(self, monkeypatch):
        counted = counted_str_type()
        monkeypatch.setattr("app.api.v1.helpers.callgraph.canonical_module_key", lambda name, _language: counted(name))
        names = [f"pkg{i}" for i in range(_DISTINCT)]

        _, _, _, analyzed_modules = parse_generic_format({"analyzed_modules": names}, "javascript")

        assert counted.comparisons == 0
        assert analyzed_modules == names

    def test_duplicates_collapse_in_first_seen_order(self):
        data = {
            "imports": [
                {"module": "lodash", "file": "src/b.js", "symbols": ["map", "get"]},
                {"module": "lodash", "file": "src/a.js", "symbols": ["get", "set"]},
                {"module": "lodash", "file": "src/b.js", "symbols": ["map"]},
            ],
            "calls": [
                {"callee_module": "lodash", "callee_function": "set"},
                {"callee_module": "lodash", "callee_function": "pick"},
            ],
            "analyzed_modules": ["lodash", "express", "lodash"],
        }

        _, _, module_usage, analyzed_modules = parse_generic_format(data, "javascript")

        usage = module_usage["lodash"]
        assert usage.import_locations == ["src/b.js", "src/a.js"]
        assert usage.used_symbols == ["map", "get", "set", "pick"]
        assert (usage.import_count, usage.call_count) == (3, 2)
        assert analyzed_modules == ["lodash", "express"]


class TestCallgraphEntryCount:
    """What the parsers walk, counted off the raw payload before any of it is parsed."""

    def test_generic_counts_imports_symbols_calls_and_universe(self):
        data = {
            "imports": [
                {"module": "lodash", "file": "src/a.js", "symbols": ["map", "get"]},
                {"module": "express", "file": "src/b.js", "symbols": []},
            ],
            "calls": [{"callee_module": "lodash", "callee_function": "map"}],
            "analyzed_modules": ["lodash", "express", "react"],
        }

        assert callgraph_entry_count(data) == 2 + 2 + 1 + 3

    def test_madge_counts_every_dependency_and_the_universe(self):
        data = {"src/a.js": ["lodash", "src/b.js"], "src/b.js": ["express"], "__analyzed_modules__": ["lodash"]}

        assert callgraph_entry_count(data) == 3 + 1

    def test_non_list_values_cost_nothing(self):
        data = {"format": "generic", "language": "python", "imports": "not-a-list", "src/a.js": {"x": 1}}

        assert callgraph_entry_count(data) == 0
