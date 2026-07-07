"""Regression tests for SPDX OR-expression handling in cross-component
license compatibility checking (compatibility.py)."""

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
    """A single dual-licensed component (CDDL-1.0 OR GPL-2.0) must not conflict
    with itself: the OR expression resolves to one chosen alternative (the
    least restrictive), not both simultaneously."""
    components = [_make_expr_component("foo", "1.0", "CDDL-1.0 OR GPL-2.0")]
    issues = check_license_compatibility(components, ignore_dev=True)
    assert issues == []


def test_dual_licensed_or_no_cross_component_false_positive():
    """A dual-licensed component (CDDL-1.0 OR GPL-2.0) resolves to its
    least-restrictive alternative (CDDL-1.0). The optional GPL-2.0 branch must
    not be flattened in and then flagged against an EPL-1.0 component
    (EPL-1.0 + GPL-2.0 is a known incompatibility)."""
    components = [
        _make_expr_component("foo", "1.0", "CDDL-1.0 OR GPL-2.0"),
        _make_component("bar", "1.0", "EPL-1.0"),
    ]
    issues = check_license_compatibility(components, ignore_dev=True)
    assert issues == []


def test_and_expression_still_detects_cross_component_conflict():
    """GPL-2.0 AND GPL-3.0 means both licenses apply; the GPL-2.0 obligation
    still conflicts with a CDDL-1.0 component in another package."""
    components = [
        _make_expr_component("foo", "1.0", "GPL-2.0 AND GPL-3.0"),
        _make_component("bar", "1.0", "CDDL-1.0"),
    ]
    issues = check_license_compatibility(components, ignore_dev=True)
    assert len(issues) >= 1


def test_plain_incompatible_pair_still_flagged():
    """Sanity: the non-expression conflict path is unchanged."""
    components = [
        _make_component("a", "1.0", "CDDL-1.0"),
        _make_component("b", "1.0", "GPL-2.0"),
    ]
    issues = check_license_compatibility(components, ignore_dev=True)
    assert len(issues) == 1
