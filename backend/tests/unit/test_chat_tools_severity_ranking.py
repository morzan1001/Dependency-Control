"""A chat/MCP tool that answers "your worst findings" must rank before it cuts.

Against a live MongoDB, a scan holding 4 900 LOW findings written before 100 CRITICAL ones
answered with ten LOW findings and `count: 10`. The consumer is a language model relaying the
answer as prose, with no chart beside it to contradict, so the sample has to be taken per severity
tier rather than from the scan's natural order.
"""

from datetime import datetime, timezone

import pytest

from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools import registry as registry_module

_NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
_PROJECT = "checkout-service"
_SCAN = "scan-head"
_CAP = 4
_LOW_COUNT = 6
_CRITICAL_COUNT = 3
_ANSWER_LIMIT = 3
_ODD_SEVERITY = "SEVERE"

_SEV_CRITICAL = "CRITICAL"
_SEV_HIGH = "HIGH"
_SEV_LOW = "LOW"
_SEV_NEGLIGIBLE = "NEGLIGIBLE"
_SEV_INFO = "INFO"
_TOTAL = _LOW_COUNT + _CRITICAL_COUNT


def _finding(index: int, severity: str) -> dict:
    return {
        "_id": f"{_SCAN}:{severity}:{index}",
        "finding_id": f"{severity}-{index}",
        "scan_id": _SCAN,
        "project_id": _PROJECT,
        "type": "vulnerability",
        "severity": severity,
        "component": f"lib-{severity.lower()}-{index}",
        "version": "1.0.0",
        "created_at": _NOW,
        "details": {"vulnerabilities": [{"id": f"CVE-2026-{index:05d}"}], "epss_score": index / 100},
    }


@pytest.fixture
def flooded(db):
    """The ordinary shape of a SAST-plus-secrets scan: low-severity hits land before the criticals."""
    db.projects._docs[_PROJECT] = {"_id": _PROJECT, "name": _PROJECT}
    db.scans._docs[_SCAN] = {
        "_id": _SCAN,
        "project_id": _PROJECT,
        "branch": "main",
        "status": "completed",
        "created_at": _NOW,
        "stats": {"critical": _CRITICAL_COUNT},
    }
    for index in range(_LOW_COUNT):
        doc = _finding(index, _SEV_LOW)
        db.findings._docs[doc["_id"]] = doc
    for index in range(_CRITICAL_COUNT):
        doc = _finding(index, _SEV_CRITICAL)
        db.findings._docs[doc["_id"]] = doc
    return db


@pytest.mark.asyncio
async def test_criticals_survive_a_flood_of_low_findings(flooded, admin_user, monkeypatch):
    """The measured defect: a natural-order sample smaller than the LOW population held no critical."""
    monkeypatch.setattr(registry_module, "_FINDING_RANK_FETCH_CAP", _CAP)

    result = await ChatToolRegistry().execute_tool(
        "get_scan_findings", {"project_id": _PROJECT, "limit": _ANSWER_LIMIT}, admin_user, flooded
    )

    assert [f["severity"] for f in result["findings"]] == [_SEV_CRITICAL] * _CRITICAL_COUNT


@pytest.mark.asyncio
async def test_a_tier_larger_than_the_cap_says_its_order_is_a_sample(flooded, admin_user, monkeypatch):
    """The LOW tier feeds the answer once the criticals run out, and it holds more than the cap."""
    monkeypatch.setattr(registry_module, "_FINDING_RANK_FETCH_CAP", _CAP)

    result = await ChatToolRegistry().execute_tool(
        "get_scan_findings", {"project_id": _PROJECT, "limit": _LOW_COUNT}, admin_user, flooded
    )

    assert _SEV_LOW in result["ranking_note"]
    assert str(_LOW_COUNT) in result["ranking_note"]


@pytest.mark.asyncio
async def test_a_complete_tier_walk_carries_no_caveat(flooded, admin_user):
    result = await ChatToolRegistry().execute_tool(
        "get_scan_findings", {"project_id": _PROJECT, "limit": _ANSWER_LIMIT}, admin_user, flooded
    )

    assert "ranking_note" not in result


@pytest.mark.asyncio
async def test_a_requested_severity_narrows_the_walk_instead_of_being_overwritten(flooded, admin_user):
    """The tier walk replaces the query's `severity` clause, so it has to be derived from it."""
    result = await ChatToolRegistry().execute_tool(
        "get_scan_findings",
        {"project_id": _PROJECT, "severity": _SEV_LOW, "limit": _LOW_COUNT},
        admin_user,
        flooded,
    )

    assert [f["severity"] for f in result["findings"]] == [_SEV_LOW] * _LOW_COUNT


@pytest.mark.asyncio
async def test_a_severity_outside_the_ranked_set_is_still_reachable(flooded, admin_user):
    """A walk over only the known tiers would make a finding with an unrecognised severity invisible."""
    odd = _finding(0, _ODD_SEVERITY)
    flooded.findings._docs[odd["_id"]] = odd

    result = await ChatToolRegistry().execute_tool(
        "get_scan_findings",
        {"project_id": _PROJECT, "limit": _LOW_COUNT + _CRITICAL_COUNT + 1},
        admin_user,
        flooded,
    )

    assert _ODD_SEVERITY in [f["severity"] for f in result["findings"]]


@pytest.mark.asyncio
async def test_severity_ordering_survives_across_tiers(flooded, admin_user):
    """HIGH outranks LOW even though 'HIGH' sorts after 'LOW' would-be lexicographically only by luck."""
    high = _finding(0, _SEV_HIGH)
    flooded.findings._docs[high["_id"]] = high

    result = await ChatToolRegistry().execute_tool(
        "get_scan_findings",
        {"project_id": _PROJECT, "limit": _CRITICAL_COUNT + 1},
        admin_user,
        flooded,
    )

    assert result["findings"][-1]["severity"] == _SEV_HIGH


@pytest.mark.asyncio
async def test_a_tier_is_ordered_by_epss(flooded, admin_user):
    result = await ChatToolRegistry().execute_tool(
        "get_scan_findings", {"project_id": _PROJECT, "limit": _CRITICAL_COUNT}, admin_user, flooded
    )

    assert [f["finding_id"] for f in result["findings"]] == [f"{_SEV_CRITICAL}-{i}" for i in (2, 1, 0)]


@pytest.mark.asyncio
async def test_negligible_findings_rank_above_info_ones(flooded, admin_user):
    for doc in (_finding(0, _SEV_INFO), _finding(0, _SEV_NEGLIGIBLE)):
        flooded.findings._docs[doc["_id"]] = doc

    result = await ChatToolRegistry().execute_tool(
        "get_scan_findings", {"project_id": _PROJECT, "limit": _TOTAL + 2}, admin_user, flooded
    )

    assert [f["severity"] for f in result["findings"]][-2:] == [_SEV_NEGLIGIBLE, _SEV_INFO]


@pytest.mark.asyncio
async def test_a_full_page_names_the_population_it_was_cut_from(flooded, admin_user):
    result = await ChatToolRegistry().execute_tool(
        "get_scan_findings", {"project_id": _PROJECT, "limit": _ANSWER_LIMIT}, admin_user, flooded
    )

    assert (result["count"], result["findings_total"]) == (_ANSWER_LIMIT, _TOTAL)


@pytest.mark.asyncio
async def test_a_page_with_room_left_is_the_whole_population(flooded, admin_user):
    result = await ChatToolRegistry().execute_tool(
        "get_scan_findings", {"project_id": _PROJECT, "limit": _TOTAL + 1}, admin_user, flooded
    )

    assert result["count"] == result["findings_total"] == _TOTAL


@pytest.mark.asyncio
async def test_a_search_cut_short_names_how_many_matched(flooded, admin_user):
    result = await ChatToolRegistry().execute_tool(
        "search_findings", {"query": "lib-", "limit": _ANSWER_LIMIT}, admin_user, flooded
    )

    assert (result["count"], result["findings_total"]) == (_ANSWER_LIMIT, _TOTAL)
    assert result["_bounded_read"] is True


def _open_critical(index: int, finding_type: str) -> dict:
    """A long-open CRITICAL finding: a vulnerability with a fixed KEV advisory, or a license finding."""
    doc = {
        **_finding(index, _SEV_CRITICAL),
        "_id": f"{_SCAN}:{finding_type}:{index}",
        "type": finding_type,
        "first_seen_at": datetime(2025, 1, 1, tzinfo=timezone.utc),
    }
    if finding_type == "vulnerability":
        advisory = {"id": f"CVE-2026-{index:05d}", "severity": _SEV_CRITICAL, "in_kev": True, "fixed_version": "1.0.1"}
        doc["details"] = {"vulnerabilities": [advisory]}
    else:
        doc["details"] = {}
    return doc


@pytest.mark.parametrize(
    "tool_name",
    [
        "get_top_priority_findings",
        "get_kev_findings",
        "get_auto_fixable_findings",
        "get_stale_findings",
        "get_license_violations",
    ],
)
@pytest.mark.asyncio
async def test_an_estate_wide_ranked_tool_relays_that_its_tier_was_sampled(flooded, admin_user, monkeypatch, tool_name):
    monkeypatch.setattr(registry_module, "_FINDING_RANK_FETCH_CAP", _CAP)
    flooded.findings._docs.clear()
    for index in range(_CAP + 1):
        for doc in (_open_critical(index, "vulnerability"), _open_critical(index, "license")):
            flooded.findings._docs[doc["_id"]] = doc

    result = await ChatToolRegistry().execute_tool(tool_name, {}, admin_user, flooded)

    assert f"the {_SEV_CRITICAL} tier holds" in result["ranking_note"]
