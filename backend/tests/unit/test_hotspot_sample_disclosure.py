"""A hotspot row names the population behind each list it samples.

Every one of these lists reads as the whole of what the row found: the projects it affects, the
versions that fix it, the CVEs behind it. Without the population beside it, a reader acting on
ten project names cannot tell them from all the projects the component is in.
"""

from app.api.v1.endpoints.analytics.risk import (
    _CVES_SHOWN,
    _FIX_VERSIONS_SHOWN,
    _HOTSPOT_PROJECTS_SHOWN,
    _build_hotspot,
)

_MORE_PROJECTS_THAN_SHOWN = _HOTSPOT_PROJECTS_SHOWN + 3
_MORE_CVES_THAN_SHOWN = _CVES_SHOWN + 2
_MORE_FIX_VERSIONS_THAN_SHOWN = _FIX_VERSIONS_SHOWN + 2
_COMPONENT = "left-pad"
_VERSION = "1.0.0"
_NEWEST_FIX = "12.0.0"


def _project_ids(count: int) -> list[str]:
    return [f"p{index}" for index in range(count)]


def _group(*, project_count: int, cve_count: int, fix_versions: list[str]) -> dict:
    """Every advisory is fixed on each release line the versions name."""
    vulnerabilities = [
        {"id": f"CVE-2026-{index:04d}", "severity": "HIGH", "fixed_version": ", ".join(fix_versions)}
        for index in range(cve_count)
    ]
    return {
        "_id": {"component": _COMPONENT, "version": _VERSION},
        "details_list": [{"vulnerabilities": vulnerabilities}],
        "project_ids": _project_ids(project_count),
        "first_seen": None,
    }


def _hotspot(*, project_count: int, cve_count: int, fix_versions: list[str]):
    accessible = _project_ids(project_count)
    return _build_hotspot(
        _group(project_count=project_count, cve_count=cve_count, fix_versions=fix_versions),
        {},
        {},
        {},
        {pid: pid for pid in accessible},
        accessible,
    )


def test_the_project_sample_names_how_many_projects_there_are():
    hotspot = _hotspot(project_count=_MORE_PROJECTS_THAN_SHOWN, cve_count=1, fix_versions=[_NEWEST_FIX])

    assert len(hotspot.affected_projects) == _HOTSPOT_PROJECTS_SHOWN
    assert hotspot.affected_project_count == _MORE_PROJECTS_THAN_SHOWN


def test_the_cve_sample_names_how_many_cves_there_are():
    hotspot = _hotspot(project_count=1, cve_count=_MORE_CVES_THAN_SHOWN, fix_versions=[_NEWEST_FIX])

    assert len(hotspot.top_cves) == _CVES_SHOWN
    assert hotspot.cve_count == _MORE_CVES_THAN_SHOWN


def test_the_fix_version_sample_names_how_many_versions_there_are():
    versions = [f"{major}.0.0" for major in range(1, _MORE_FIX_VERSIONS_THAN_SHOWN + 1)]

    hotspot = _hotspot(project_count=1, cve_count=1, fix_versions=versions)

    assert len(hotspot.fix_versions) == _FIX_VERSIONS_SHOWN
    assert hotspot.fix_version_count == _MORE_FIX_VERSIONS_THAN_SHOWN


def test_the_fix_versions_shown_are_the_newest_ones():
    """The versions come out of a set, which has no order, so the same row samples a different
    three between runs unless they are ranked first."""
    versions = ["2.0.0", _NEWEST_FIX, "9.0.0", "1.0.1", "3.0.0"]

    hotspot = _hotspot(project_count=1, cve_count=1, fix_versions=versions)

    assert hotspot.fix_versions[0] == _NEWEST_FIX
