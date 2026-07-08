"""Tests for SPDX OR-expression handling in cross-component license compatibility."""

from app.services.analyzers.license_compliance.compatibility import check_license_compatibility


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
