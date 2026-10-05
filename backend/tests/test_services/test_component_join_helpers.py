"""The single implementation of the finding-component / dependency-name join.

Every consumer that joins the two collections on a name goes through these helpers, so
the "exact spelling, else the artifact name, never across packages" rule is defined once.
"""

import asyncio

import pytest

from app.services.component_identity import (
    artifact_name_expr,
    build_component_index,
    cluster_by_package_identity,
    component_match_expr,
    component_match_query,
    extract_artifact_name,
    lookup_component,
)
from tests.mocks.fake_mongo import FakeCollection


class TestBuildComponentIndexAndLookup:
    def test_bare_dependency_name_resolves_a_qualified_entry(self):
        index = build_component_index({"com.fasterxml.jackson.core:jackson-databind": 7})

        assert lookup_component(index, "jackson-databind") == 7

    def test_qualified_name_resolves_a_bare_entry(self):
        index = build_component_index({"jackson-databind": 7})

        assert lookup_component(index, "com.fasterxml.jackson.core:jackson-databind") == 7

    def test_exact_spelling_wins_over_the_alias(self):
        index = build_component_index({"@angular-devkit/core": 1, "@angular/core": 2})

        assert lookup_component(index, "@angular-devkit/core") == 1

    def test_ambiguous_artifact_name_is_not_aliased(self):
        index = build_component_index({"@angular/core": 1, "@messageformat/core": 2})

        assert lookup_component(index, "core") is None

    def test_mixed_case_dependency_name_resolves(self):
        index = build_component_index({"xerces:xercesImpl": 3})

        assert lookup_component(index, "xercesImpl") == 3

    def test_default_is_returned_when_nothing_matches(self):
        assert lookup_component(build_component_index({"a": 1}), "b", 0) == 0

    @pytest.mark.parametrize(
        ("stored", "other"),
        [("github.com/cespare/xxhash/v2", "github.com/foo/bar/v2"), ("org.foo:core", "com.bar:core")],
    )
    def test_a_qualified_name_never_reaches_another_qualified_package(self, stored, other):
        index = build_component_index({stored: 1})

        assert lookup_component(index, other) is None
        assert lookup_component(index, extract_artifact_name(stored)) == 1

    def test_a_qualified_name_resolves_a_mixed_case_bare_entry(self):
        index = build_component_index({"HikariCP": 4})

        assert lookup_component(index, "com.zaxxer:HikariCP") == 4


class TestMongoFragmentsMirrorThePythonRule:
    def test_query_matches_exact_and_qualified_forms_but_not_another_scope(self):
        stored = [
            "jackson-databind",
            "com.fasterxml.jackson.core:jackson-databind",
            "vendor/jackson-databind",
            "@types/jackson-databind",
            "jackson-databind-extra",
        ]

        assert _matching(stored, component_match_query("jackson-databind")) == [
            "jackson-databind",
            "com.fasterxml.jackson.core:jackson-databind",
            "vendor/jackson-databind",
        ]

    def test_artifact_name_expr_mirrors_extract_artifact_name(self):
        """Same inputs, same outputs; the pipeline copy must not drift from the Python one."""
        cases = [
            "com.fasterxml.jackson.core:jackson-databind",
            "@angular/core",
            "github.com/gin-gonic/gin",
            "lodash",
            "xerces:xercesImpl",
        ]
        for value in cases:
            assert _eval_expr(artifact_name_expr("$c"), {"c": value}) == extract_artifact_name(value)

    def test_match_expr_accepts_both_spellings_and_rejects_a_sibling(self):
        expr = component_match_expr("$name", "$$component")

        def _matches(name: str, component: str) -> bool:
            return bool(_eval_expr(expr, {"name": name, "component": component}))

        assert _matches("jackson-databind", "com.fasterxml.jackson.core:jackson-databind")
        assert _matches("com.fasterxml.jackson.core:jackson-databind", "com.fasterxml.jackson.core:jackson-databind")
        assert _matches("xercesImpl", "xerces:xercesImpl")
        assert not _matches("jackson-core", "com.fasterxml.jackson.core:jackson-databind")


def _matching(stored: list[str], query: dict) -> list[str]:
    collection = FakeCollection()
    collection._docs = {str(n): {"_id": str(n), "component": name} for n, name in enumerate(stored)}
    return [doc["component"] for doc in asyncio.run(collection.find(query).sort("_id", 1).to_list(None))]


class TestAnNpmScopeIsPartOfThePackageName:
    @pytest.mark.parametrize(
        ("scoped", "bare"),
        [("@types/lodash", "lodash"), ("@hapi/joi", "joi"), ("@types/react", "react")],
    )
    def test_a_scoped_package_is_not_a_qualified_spelling_of_the_bare_name(self, scoped, bare):
        assert cluster_by_package_identity([bare, scoped]) == {bare: bare, scoped: scoped}

    def test_a_group_qualified_coordinate_still_owns_its_bare_artifact_name(self):
        qualified = "org.apache.logging.log4j:log4j-core"

        assert cluster_by_package_identity(["log4j-core", qualified]) == {"log4j-core": qualified, qualified: qualified}

    def test_the_index_gives_a_scoped_entry_no_bare_alias(self):
        assert lookup_component(build_component_index({"@types/lodash": 3}), "lodash") is None

    def test_the_query_for_a_bare_name_does_not_reach_the_scoped_package(self):
        assert _matching(["lodash", "@types/lodash"], component_match_query("lodash")) == ["lodash"]


def _eval_expr(expr, doc):
    """Evaluate the aggregation fragment with the in-process Mongo emulation."""
    from tests.mocks.fake_mongo import _eval_expr as evaluate

    scoped = {**doc, **{f"${k}": v for k, v in doc.items()}}
    return evaluate(scoped, expr)
