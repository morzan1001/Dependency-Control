"""Unit tests for extract_fix_versions against the slimmed details shape.

Task W8 stops pushing the full ``$details`` blob into the analytics $group and
instead projects it down to only the fix-version fields. ``extract_fix_versions``
must keep extracting fixes from that slimmed shape:

    {"fixed_version": <str>, "vulnerabilities": [{"fixed_version": <str>}, ...]}
"""

from app.api.v1.helpers.analytics import extract_fix_versions


def test_extracts_top_level_fixed_version():
    out = extract_fix_versions([{"fixed_version": "4.17.21", "vulnerabilities": []}])
    assert out == {"4.17.21"}


def test_extracts_nested_vulnerability_fixed_versions():
    out = extract_fix_versions(
        [{"fixed_version": None, "vulnerabilities": [{"fixed_version": "2.0.0"}, {"fixed_version": "2.0.1"}]}]
    )
    assert out == {"2.0.0", "2.0.1"}


def test_combines_top_level_and_nested():
    out = extract_fix_versions([{"fixed_version": "1.2.3", "vulnerabilities": [{"fixed_version": "1.2.4"}]}])
    assert out == {"1.2.3", "1.2.4"}


def test_ignores_missing_and_empty():
    out = extract_fix_versions(
        [
            {"fixed_version": None, "vulnerabilities": []},
            {"vulnerabilities": [{"fixed_version": None}]},
            {},
        ]
    )
    assert out == set()
