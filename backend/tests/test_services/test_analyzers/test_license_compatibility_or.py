"""Tests for SPDX OR-expression handling in cross-component license compatibility."""

from app.services.analyzers.license_compliance.compatibility import (
    check_license_compatibility,
    least_restrictive_group,
)


def _make_component(name, version, license_id, scope="runtime"):
    return {
        "name": name,
        "version": version,
        "licenses": [{"license": {"id": license_id}}],
        "scope": scope,
        "purl": f"pkg:pypi/{name}@{version}",
    }


def _make_expr_component(name, version, expression, scope="runtime"):
    return {
        "name": name,
        "version": version,
        "licenses": [{"expression": expression}],
        "scope": scope,
        "purl": f"pkg:maven/{name}@{version}",
    }


def test_dual_licensed_or_expression_no_self_conflict():
    """A dual-licensed component resolves to one chosen alternative, so it can't conflict with itself."""
    components = [_make_expr_component("foo", "1.0", "CDDL-1.0 OR GPL-2.0")]
    issues = check_license_compatibility(components, ignore_dev=True)
    assert issues == []


def test_dual_licensed_or_no_cross_component_false_positive():
    """The optional GPL-2.0 branch of an OR expression must not be flagged against an EPL-1.0 component."""
    components = [
        _make_expr_component("foo", "1.0", "CDDL-1.0 OR GPL-2.0"),
        _make_component("bar", "1.0", "EPL-1.0"),
    ]
    issues = check_license_compatibility(components, ignore_dev=True)
    assert issues == []


def test_and_expression_still_detects_cross_component_conflict():
    """AND means both licenses apply, so GPL-2.0 still conflicts with a CDDL-1.0 component."""
    components = [
        _make_expr_component("foo", "1.0", "GPL-2.0 AND GPL-3.0"),
        _make_component("bar", "1.0", "CDDL-1.0"),
    ]
    issues = check_license_compatibility(components, ignore_dev=True)
    assert len(issues) >= 1


def test_plain_incompatible_pair_still_flagged():
    components = [
        _make_component("a", "1.0", "CDDL-1.0"),
        _make_component("b", "1.0", "GPL-2.0"),
    ]
    issues = check_license_compatibility(components, ignore_dev=True)
    assert len(issues) == 1


def test_equally_restrictive_alternatives_resolve_to_the_first_declared():
    """Both GPL alternatives rank the same, so the declared order decides — and must stay stable."""
    assert least_restrictive_group([["GPL-2.0"], ["GPL-3.0"]]) == ["GPL-2.0"]
    assert least_restrictive_group([["GPL-3.0"], ["GPL-2.0"]]) == ["GPL-3.0"]


def test_a_later_alternative_wins_when_it_is_genuinely_less_restrictive():
    assert least_restrictive_group([["GPL-3.0"], ["MIT"]]) == ["MIT"]


def test_tied_or_alternatives_name_the_first_one_in_the_conflict():
    """CDDL-1.0 clashes with either GPL, so the resolved alternative is visible in the finding."""
    components = [
        _make_expr_component("foo", "1.0", "GPL-2.0 OR GPL-3.0"),
        _make_component("bar", "1.0", "CDDL-1.0"),
    ]
    issues = check_license_compatibility(components, ignore_dev=True)
    assert len(issues) == 1
    assert issues[0]["license"] == "GPL-2.0 / CDDL-1.0"
    assert "GPL-2.0" in issues[0]["message"]
