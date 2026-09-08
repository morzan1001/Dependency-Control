"""A chat/MCP tool that answers "your worst findings" must rank before it cuts.

Against a live MongoDB, a scan holding 4 900 LOW findings written before 100 CRITICAL ones
answered with ten LOW findings and `count: 10`. The consumer is a language model relaying the
answer as prose, with no chart beside it to contradict, so the sample has to be taken per severity
tier rather than from the scan's natural order.
"""

from datetime import datetime, timezone

import pytest

from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools import registry as registry_module
from tests.helpers.permission_presets import PRESET_ADMIN

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


@pytest.fixture
def admin_user():
    return User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))


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
    db.projects._docs[_PROJECT] = {"_id": _PROJECT, "name": _PROJECT, "team_id": None}
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
        "get_project_findings", {"project_id": _PROJECT, "limit": _ANSWER_LIMIT}, admin_user, flooded
    )

    assert [f["severity"] for f in result["findings"]] == [_SEV_CRITICAL] * _CRITICAL_COUNT


@pytest.mark.asyncio
async def test_a_tier_larger_than_the_cap_says_its_order_is_a_sample(flooded, admin_user, monkeypatch):
    """The LOW tier feeds the answer once the criticals run out, and it holds more than the cap."""
    monkeypatch.setattr(registry_module, "_FINDING_RANK_FETCH_CAP", _CAP)

    result = await ChatToolRegistry().execute_tool(
        "get_project_findings", {"project_id": _PROJECT, "limit": _LOW_COUNT}, admin_user, flooded
    )

    assert _SEV_LOW in result["ranking_note"]
    assert str(_LOW_COUNT) in result["ranking_note"]


@pytest.mark.asyncio
async def test_a_complete_tier_walk_carries_no_caveat(flooded, admin_user):
    result = await ChatToolRegistry().execute_tool(
        "get_project_findings", {"project_id": _PROJECT, "limit": _ANSWER_LIMIT}, admin_user, flooded
    )

    assert "ranking_note" not in result


@pytest.mark.asyncio
async def test_a_requested_severity_narrows_the_walk_instead_of_being_overwritten(flooded, admin_user):
    """The tier walk replaces the query's `severity` clause, so it has to be derived from it."""
    result = await ChatToolRegistry().execute_tool(
        "get_project_findings",
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
        "get_project_findings",
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
        "get_project_findings",
        {"project_id": _PROJECT, "limit": _CRITICAL_COUNT + 1},
        admin_user,
        flooded,
    )

    assert result["findings"][-1]["severity"] == _SEV_HIGH
