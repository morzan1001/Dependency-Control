"""extract_fix_versions names the versions that fix every advisory of a component version."""

from app.api.v1.helpers.analytics import extract_fix_versions


def _advisories(*fixes):
    return {"vulnerabilities": [{"fixed_version": fix} for fix in fixes]}


def test_only_the_version_fixing_every_advisory_is_listed():
    assert extract_fix_versions([_advisories("2.0.1", "1.9.9, 2.3.0")], "1.9.0") == {"2.3.0"}


def test_a_fix_per_release_line_is_split_into_single_versions():
    out = extract_fix_versions([_advisories("4.17.21, 5.0.1", "4.17.19, 5.0.1")], "4.17.0")
    assert out == {"4.17.21", "5.0.1"}


def test_every_projects_advisories_count_towards_the_fix():
    variants = [_advisories("2.0.1"), _advisories("2.0.1", "2.3.0")]
    assert extract_fix_versions(variants, "2.0.0") == {"2.3.0"}


def test_without_a_version_fixing_everything_each_advisorys_fix_is_listed():
    assert extract_fix_versions([_advisories("3.0.0", None)], "1.0") == {"3.0.0"}
    assert extract_fix_versions([_advisories("1.2.6", "2.0.1, 2.1.0")], "1.0") == {"1.2.6", "2.0.1", "2.1.0"}


def test_the_stored_document_fix_is_not_read():
    assert extract_fix_versions([{"fixed_version": "9.9.9", **_advisories("1.2.4")}], "1.0") == {"1.2.4"}


def test_ignores_missing_and_empty():
    assert extract_fix_versions([_advisories(None), {"vulnerabilities": []}, {}], "1.0") == set()
