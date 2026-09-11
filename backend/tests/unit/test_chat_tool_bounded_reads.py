"""A chat tool that stopped at its read ceiling must say what it stopped short of.

An LLM relaying a list has no chart beside it against which a reader could notice that the list
is a page, so a bare list is read as the whole of what was asked about.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools.registry import (
    _CVE_OCCURRENCE_READ,
    _DEPENDENCY_TREE_READ,
    _EXPIRING_WAIVER_READ,
    _REMEDIATION_FINDING_READ,
    _TEAM_PROJECT_READ,
    _WAIVER_READ,
    _WEBHOOK_DELIVERY_READ,
    _WEBHOOK_READ,
)
from tests.helpers.permission_presets import PRESET_ADMIN

_NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
_PROJECT = "checkout-service"
_SCAN = "scan-head"
_TEAM = "payments"
_WEBHOOK = "hook-1"
_CVE = "CVE-2021-44228"
_WELL_INSIDE_THE_WINDOW = 5
_OVER_THE_CEILING = 7
_INSIDE_THE_CEILING = 3


@pytest.fixture
def admin_user():
    return User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))


@pytest.fixture
def seeded(db):
    db.projects._docs[_PROJECT] = {
        "_id": _PROJECT,
        "name": _PROJECT,
        "team_ids": [_TEAM],
        "team_id": _TEAM,
        "latest_scan_id": _SCAN,
        "default_branch": "main",
    }
    db.scans._docs[_SCAN] = {
        "_id": _SCAN,
        "project_id": _PROJECT,
        "branch": "main",
        "status": "completed",
        "created_at": _NOW,
        "stats": {},
    }
    db.teams._docs[_TEAM] = {
        "_id": _TEAM,
        "name": _TEAM,
        "members": [{"user_id": "admin-1", "role": "admin"}],
    }
    return db


def _fill(collection, count, doc_for):
    for index in range(count):
        collection._docs[f"row-{index}"] = doc_for(index)


@pytest.mark.asyncio
async def test_a_dependency_tree_cut_at_its_ceiling_names_the_whole_tree(seeded, admin_user):
    population = _DEPENDENCY_TREE_READ + _OVER_THE_CEILING
    _fill(
        seeded.dependencies,
        population,
        lambda i: {"_id": f"row-{i}", "scan_id": _SCAN, "name": f"pkg-{i}", "version": "1.0.0"},
    )

    result = await ChatToolRegistry().execute_tool("get_dependency_tree", {"project_id": _PROJECT}, admin_user, seeded)

    assert result["dependencies_total"] == population
    assert result["_bounded_read"] is True
    assert f"{_DEPENDENCY_TREE_READ} of {population} dependencies" in result["_bounded_read_note"]


@pytest.mark.asyncio
async def test_a_dependency_tree_inside_its_ceiling_carries_no_caveat(seeded, admin_user):
    _fill(
        seeded.dependencies,
        _INSIDE_THE_CEILING,
        lambda i: {"_id": f"row-{i}", "scan_id": _SCAN, "name": f"pkg-{i}", "version": "1.0.0"},
    )

    result = await ChatToolRegistry().execute_tool("get_dependency_tree", {"project_id": _PROJECT}, admin_user, seeded)

    assert result["dependencies_total"] == _INSIDE_THE_CEILING
    assert "_bounded_read" not in result


@pytest.mark.asyncio
async def test_the_byte_cap_note_names_the_population_not_the_page(seeded, admin_user):
    """The read ceiling cuts first and the byte cap cuts what is left; naming the page as what
    the byte cap cut from understates the tree by the read ceiling's worth."""
    population = _DEPENDENCY_TREE_READ + _OVER_THE_CEILING
    _fill(
        seeded.dependencies,
        population,
        lambda i: {
            "_id": f"row-{i}",
            "scan_id": _SCAN,
            "name": f"pkg-{i}",
            "version": "1.0.0",
            "purl": f"pkg:npm/pkg-{i}@1.0.0",
            "description": "x" * 200,
        },
    )

    result = await ChatToolRegistry().execute_tool("get_dependency_tree", {"project_id": _PROJECT}, admin_user, seeded)

    assert result["_truncated"] is True
    assert f"from {population} to" in result["_truncation_note"]


@pytest.mark.asyncio
async def test_team_projects_cut_at_the_ceiling_names_the_team_s_whole_holding(seeded, admin_user):
    population = _TEAM_PROJECT_READ + _OVER_THE_CEILING
    for index in range(population):
        seeded.projects._docs[f"tp-{index}"] = {
            "_id": f"tp-{index}",
            "name": f"p{index}",
            "team_ids": [_TEAM],
            "team_id": _TEAM,
        }

    result = await ChatToolRegistry().execute_tool("get_team_projects", {"team_id": _TEAM}, admin_user, seeded)

    # The seeded head project also belongs to the team.
    assert result["projects_total"] == population + 1
    assert result["_bounded_read"] is True


@pytest.mark.asyncio
async def test_a_waiver_listing_cut_at_the_ceiling_names_every_waiver(seeded, admin_user):
    population = _WAIVER_READ + _OVER_THE_CEILING
    _fill(
        seeded.waivers,
        population,
        lambda i: {"_id": f"row-{i}", "project_id": _PROJECT, "finding_id": f"f-{i}", "reason": "r"},
    )

    result = await ChatToolRegistry().execute_tool(
        "list_project_waivers", {"project_id": _PROJECT}, admin_user, seeded
    )

    assert result["waivers_total"] == population
    assert result["_bounded_read"] is True


@pytest.mark.asyncio
async def test_a_global_waiver_listing_cut_at_the_ceiling_names_every_waiver(seeded, admin_user):
    population = _WAIVER_READ + _OVER_THE_CEILING
    _fill(
        seeded.waivers,
        population,
        lambda i: {"_id": f"row-{i}", "project_id": None, "finding_id": f"g-{i}", "reason": "r"},
    )

    result = await ChatToolRegistry().execute_tool("list_global_waivers", {}, admin_user, seeded)

    assert result["waivers_total"] == population
    assert result["_bounded_read"] is True


@pytest.mark.asyncio
async def test_a_webhook_listing_cut_at_the_ceiling_names_every_webhook(seeded, admin_user):
    population = _WEBHOOK_READ + _OVER_THE_CEILING
    _fill(
        seeded.webhooks,
        population,
        lambda i: {"_id": f"row-{i}", "project_id": _PROJECT, "url": f"https://example.invalid/{i}"},
    )

    result = await ChatToolRegistry().execute_tool(
        "list_project_webhooks", {"project_id": _PROJECT}, admin_user, seeded
    )

    assert result["webhooks_total"] == population
    assert result["_bounded_read"] is True


@pytest.mark.asyncio
async def test_a_delivery_history_cut_at_the_ceiling_names_every_delivery(seeded, admin_user):
    seeded.webhooks._docs[_WEBHOOK] = {"_id": _WEBHOOK, "project_id": _PROJECT, "url": "https://example.invalid"}
    population = _WEBHOOK_DELIVERY_READ + _OVER_THE_CEILING
    _fill(
        seeded.webhook_deliveries,
        population,
        lambda i: {
            "_id": f"row-{i}",
            "webhook_id": _WEBHOOK,
            "status": "success",
            "timestamp": _NOW - timedelta(minutes=i),
        },
    )

    result = await ChatToolRegistry().execute_tool(
        "get_webhook_deliveries", {"webhook_id": _WEBHOOK}, admin_user, seeded
    )

    assert result["deliveries_total"] == population
    assert result["_bounded_read"] is True


@pytest.mark.asyncio
async def test_one_call_does_not_inherit_the_previous_call_s_saturated_read(seeded, admin_user):
    population = _DEPENDENCY_TREE_READ + _OVER_THE_CEILING
    _fill(
        seeded.dependencies,
        population,
        lambda i: {"_id": f"row-{i}", "scan_id": _SCAN, "name": f"pkg-{i}", "version": "1.0.0"},
    )
    registry = ChatToolRegistry()
    await registry.execute_tool("get_dependency_tree", {"project_id": _PROJECT}, admin_user, seeded)

    result = await registry.execute_tool("get_project_details", {"project_id": _PROJECT}, admin_user, seeded)

    assert "_bounded_read" not in result


@pytest.mark.asyncio
async def test_the_occurrence_count_for_a_cve_is_the_population_not_the_page(seeded, admin_user):
    """`total_occurrences` read `len(rows)`, so a saturated read reported the ceiling as the
    number of places the CVE was found."""
    population = _CVE_OCCURRENCE_READ + _OVER_THE_CEILING
    _fill(
        seeded.findings,
        population,
        lambda i: {
            "_id": f"row-{i}",
            "scan_id": _SCAN,
            "project_id": _PROJECT,
            "severity": "HIGH",
            "component": f"pkg-{i}",
            "details": {"vulnerabilities": [{"id": _CVE}]},
        },
    )

    result = await ChatToolRegistry().execute_tool("get_findings_by_cve", {"cve_id": _CVE}, admin_user, seeded)

    assert result["occurrences_read"] == _CVE_OCCURRENCE_READ
    assert result["total_occurrences"] == population
    assert result["_bounded_read"] is True


@pytest.mark.asyncio
async def test_a_remediation_plan_names_the_finding_set_it_was_built_over(seeded, admin_user):
    """The plan's summary counts only what the page resolved, which reads as the whole backlog."""
    population = _REMEDIATION_FINDING_READ + _OVER_THE_CEILING
    _fill(
        seeded.findings,
        population,
        lambda i: {
            "_id": f"row-{i}",
            "scan_id": _SCAN,
            "project_id": _PROJECT,
            "severity": "HIGH",
            "component": f"pkg-{i}",
            "version": "1.0.0",
            "details": {"fixed_version": "2.0.0"},
        },
    )

    result = await ChatToolRegistry().execute_tool(
        "generate_remediation_plan", {"project_id": _PROJECT}, admin_user, seeded
    )

    assert result["summary"]["findings_read"] == _REMEDIATION_FINDING_READ
    assert result["summary"]["findings_total"] == population
    assert result["_bounded_read"] is True


@pytest.mark.asyncio
async def test_an_expiring_waiver_answer_names_every_waiver_in_the_window(seeded, admin_user):
    population = _EXPIRING_WAIVER_READ + _OVER_THE_CEILING
    expires = datetime.now(timezone.utc) + timedelta(days=_WELL_INSIDE_THE_WINDOW)
    _fill(
        seeded.waivers,
        population,
        lambda i: {
            "_id": f"row-{i}",
            "project_id": _PROJECT,
            "finding_id": f"f-{i}",
            "reason": "r",
            "expiration_date": expires,
        },
    )

    result = await ChatToolRegistry().execute_tool("get_expiring_waivers", {}, admin_user, seeded)

    assert result["count"] == _EXPIRING_WAIVER_READ
    assert result["waivers_total"] == population
    assert result["_bounded_read"] is True
