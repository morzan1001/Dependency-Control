"""One rule names the CVE identity of an advisory entry, for every view that counts or labels it."""

import pytest

from app.core.cve import canonical_cve, canonical_cves, display_vulnerability_id
from app.services.aggregation.merging import dedupe_vulnerability_entries, merge_vulnerability_into_list
from app.services.analysis.stats import build_epss_kev_summary


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        pytest.param({"id": "GHSA-x", "resolved_cve": "CVE-1"}, "CVE-1", id="resolved-cve-first"),
        pytest.param({"id": "GHSA-x", "aliases": ["CVE-2"]}, "CVE-2", id="cve-alias"),
        pytest.param({"id": "cve-2024-3"}, "CVE-2024-3", id="lower-case-cve-id"),
        pytest.param({"id": "GHSA-ABCD-EFGH-IJKL"}, "GHSA-abcd-efgh-ijkl", id="ghsa-body-lower-case"),
        pytest.param({"id": "RUSTSEC-2024-1"}, "RUSTSEC-2024-1", id="other-scheme-kept"),
        pytest.param({}, None, id="no-id"),
    ],
)
def test_canonical_cve(entry, expected):
    assert canonical_cve(entry) == expected


def test_a_multi_cve_advisory_counts_every_cve_it_names():
    alas = {"id": "CVE-2023-0001", "aliases": ["ALAS2-2023-2001", "CVE-2023-0002", "CVE-2023-0003"]}
    assert canonical_cves([{"vulnerabilities": [alas]}]) == ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"]


def test_one_ghsa_spelled_two_ways_counts_once():
    entries = [{"id": "GHSA-abcd-efgh-ijkl"}, {"id": "GHSA-ABCD-EFGH-IJKL"}]
    assert canonical_cves([{"vulnerabilities": entries}]) == ["GHSA-abcd-efgh-ijkl"]


def _merged(*entries):
    target: list = []
    for entry in entries:
        merge_vulnerability_into_list(target, entry)
    return target


def test_a_multi_cve_advisory_does_not_swallow_the_other_cves_entries():
    trivy = [{"id": f"CVE-2023-000{n}", "aliases": [], "scanners": ["trivy"]} for n in (1, 2, 3)]
    grype = {
        "id": "CVE-2023-0001",
        "aliases": ["ALAS2-2023-2001", "CVE-2023-0002", "CVE-2023-0003"],
        "scanners": ["grype"],
    }
    entries = _merged(*trivy, grype)
    assert sorted(e["id"] for e in entries) == ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"]
    assert canonical_cves([{"vulnerabilities": entries}]) == ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"]


def test_entries_naming_different_cves_stay_apart_after_ghsa_resolution():
    entries = [
        {"id": "GHSA-aaaa", "aliases": ["CVE-2024-0002", "CVE-2024-0001"], "resolved_cve": "CVE-2024-0002"},
        {"id": "CVE-2024-0001", "aliases": []},
    ]
    dedupe_vulnerability_entries(entries)
    assert len(entries) == 2


def test_the_kev_row_names_the_cve_the_analytics_pages_count():
    entry = {"id": "CVE-2024-0001", "resolved_cve": "CVE-2024-0002", "in_kev": True}
    finding = {"component": "c", "details": {"in_kev": True, "vulnerabilities": [entry]}}
    [row] = build_epss_kev_summary([finding])["kev_details"]
    assert row["cve"] == canonical_cve(entry) == "CVE-2024-0002"


@pytest.mark.parametrize(
    ("entries", "expected"),
    [
        pytest.param([{"id": "GHSA-x"}, {"id": "CVE-2024-1"}], "CVE-2024-1", id="a-later-cve-wins-over-a-ghsa"),
        pytest.param([{"id": "GHSA-x", "aliases": ["CVE-2024-2"]}], "CVE-2024-2", id="cve-alias"),
        pytest.param([{"id": "GHSA-ABCD"}, {"id": "RUSTSEC-1"}], "GHSA-abcd", id="no-cve-first-advisory"),
        pytest.param([], None, id="no-advisory"),
    ],
)
def test_a_finding_is_shown_under_its_first_cve(entries, expected):
    assert display_vulnerability_id({"vulnerabilities": entries}) == expected
