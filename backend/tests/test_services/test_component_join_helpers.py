"""The single implementation of the finding-component / dependency-name join.

Every consumer that joins the two collections on a name goes through these helpers, so
the "exact spelling, else the artifact name, never across packages" rule is defined once.
"""

from app.services.aggregation.components import (
    artifact_name_expr,
    build_component_index,
    component_match_expr,
    component_match_query,
    extract_artifact_name,
    lookup_component,
)


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


class TestMongoFragmentsMirrorThePythonRule:
    def test_query_matches_exact_and_qualified_forms(self):
        query = component_match_query("jackson-databind")

        assert query["$or"][0] == {"component": "jackson-databind"}
        assert query["$or"][1]["component"]["$regex"] == "[:/]jackson\\-databind$"

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


def _eval_expr(expr, doc):
    """Evaluate the aggregation fragment with the in-process Mongo emulation."""
    from tests.mocks.fake_mongo import _eval_expr as evaluate

    scoped = {**doc, **{f"${k}": v for k, v in doc.items()}}
    return evaluate(scoped, expr)
