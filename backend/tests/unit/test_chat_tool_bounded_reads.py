"""A relayed list has no chart beside it to reveal a page, so a capped tool must name what it left out."""

from datetime import datetime, timedelta, timezone

import pytest

from app.services.chat.tools import ChatToolRegistry, registry
from app.services.chat.tools.registry import (
    _CVE_OCCURRENCE_READ,
    _EXPIRING_WAIVER_READ,
    _REMEDIATION_FINDING_READ,
    _TEAM_PROJECT_READ,
    _WAIVER_READ,
    _WEBHOOK_DELIVERY_READ,
    _WEBHOOK_READ,
)

_NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
_PROJECT = "checkout-service"
_SCAN = "scan-head"
_TEAM = "payments"
_WEBHOOK = "hook-1"
_CVE = "CVE-2021-44228"
_WELL_INSIDE_THE_WINDOW = 5
_OVER_THE_CEILING = 7
_INSIDE_THE_CEILING = 3
_ESTATE_SIZE = 8
_PROJECT_PAGE = 5
_DEPENDENCY_PAGE = 40


@pytest.fixture
def seeded(db):
    db.projects._docs[_PROJECT] = {
        "_id": _PROJECT,
        "name": _PROJECT,
        "team_ids": [_TEAM],
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
    population = _DEPENDENCY_PAGE + _OVER_THE_CEILING
    _fill(
        seeded.dependencies,
        population,
        lambda i: {"_id": f"row-{i}", "scan_id": _SCAN, "name": f"pkg-{i}", "version": "1.0.0"},
    )

    result = await ChatToolRegistry().execute_tool("get_dependency_tree", {"project_id": _PROJECT}, admin_user, seeded)

    assert result["dependencies_total"] == population
    assert result["_bounded_read"] is True
    assert f"{_DEPENDENCY_PAGE} of {population} dependencies" in result["_bounded_read_note"]


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
    """The page cuts first, so naming it as the byte cap's base would understate the tree by everything past it."""
    population = _DEPENDENCY_PAGE + _OVER_THE_CEILING
    _fill(
        seeded.dependencies,
        population,
        lambda i: {
            "_id": f"row-{i}",
            "scan_id": _SCAN,
            "name": f"pkg-{i}-" + "x" * 200,
            "version": "1.0.0",
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

    result = await ChatToolRegistry().execute_tool("list_project_waivers", {"project_id": _PROJECT}, admin_user, seeded)

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
    seeded.webhooks._docs[_WEBHOOK] = {
        "_id": _WEBHOOK,
        "project_id": _PROJECT,
        "url": "https://example.invalid",
        "events": ["scan_completed"],
    }
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
    population = _DEPENDENCY_PAGE + _OVER_THE_CEILING
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
    population = _CVE_OCCURRENCE_READ + _OVER_THE_CEILING
    _fill(
        seeded.findings,
        population,
        lambda i: {
            "_id": f"row-{i}",
            "scan_id": _SCAN,
            "project_id": _PROJECT,
            "type": "vulnerability",
            "severity": "HIGH",
            "component": f"pkg-{i}",
            "details": {"vulnerabilities": [{"id": _CVE}]},
        },
    )

    result = await ChatToolRegistry().execute_tool("get_findings_by_cve", {"cve_id": _CVE}, admin_user, seeded)

    assert result["total_occurrences"] == population
    assert result["affected_projects"][0]["occurrences"] == population
    assert len(result["affected_projects"][0]["findings"]) <= _CVE_OCCURRENCE_READ
    assert "_occurrences_note" in result


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
            "type": "vulnerability",
            "severity": "HIGH",
            "component": f"pkg-{i}",
            "version": "1.0.0",
            "details": {"fixed_version": "2.0.0", "vulnerabilities": [{"id": _CVE, "fixed_version": "2.0.0"}]},
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


@pytest.mark.asyncio
async def test_an_expiring_waiver_names_only_the_package_parts_it_holds(seeded, admin_user):
    expires = datetime.now(timezone.utc) + timedelta(days=_WELL_INSIDE_THE_WINDOW)
    for finding_id, name, version in (
        ("f-cve", None, None),
        ("f-pkg", "requests", None),
        ("f-ver", "requests", "2.26.0"),
    ):
        seeded.waivers._docs[finding_id] = {
            "_id": finding_id,
            "project_id": _PROJECT,
            "finding_id": finding_id,
            "package_name": name,
            "package_version": version,
            "reason": "r",
            "expiration_date": expires,
        }

    result = await ChatToolRegistry().execute_tool("get_expiring_waivers", {}, admin_user, seeded)

    assert {w["finding_id"]: w["package"] for w in result["waivers"]} == {
        "f-cve": None,
        "f-pkg": "requests",
        "f-ver": "requests@2.26.0",
    }


@pytest.mark.asyncio
async def test_a_capped_project_listing_holds_the_most_recently_scanned(seeded, admin_user):
    """An estate larger than the cap gets a page, which must hold the freshest projects, not collection order."""
    oldest_first = _ESTATE_SIZE - 1
    for index in range(_ESTATE_SIZE):
        seeded.projects._docs[f"ps-{index:02d}"] = {
            "_id": f"ps-{index:02d}",
            "name": f"ps-{index:02d}",
            "last_scan_at": _NOW - timedelta(days=oldest_first - index),
        }

    result = await ChatToolRegistry().execute_tool("list_projects", {"limit": _PROJECT_PAGE}, admin_user, seeded)

    freshest = [f"ps-{index:02d}" for index in range(oldest_first, oldest_first - _PROJECT_PAGE, -1)]
    assert [p["id"] for p in result["projects"]] == freshest


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "collection", "rows_key", "row", "already_seeded"),
    [
        ("list_projects", "projects", "projects", lambda i: {"_id": f"row-{i}", "name": f"p-{i}"}, 1),
        ("get_scan_history", "scans", "scans", lambda i: {"_id": f"row-{i}", "project_id": _PROJECT}, 1),
        ("list_archives", "archive_metadata", "archives", lambda i: {"_id": f"row-{i}", "project_id": _PROJECT}, 0),
    ],
)
async def test_a_capped_listing_names_the_population_it_was_cut_from(
    seeded, admin_user, tool, collection, rows_key, row, already_seeded
):
    population = _PROJECT_PAGE + _OVER_THE_CEILING
    _fill(getattr(seeded, collection), population, row)

    result = await ChatToolRegistry().execute_tool(
        tool, {"project_id": _PROJECT, "limit": _PROJECT_PAGE}, admin_user, seeded
    )

    assert len(result[rows_key]) == _PROJECT_PAGE
    assert result[f"{rows_key}_total"] == population + already_seeded
    assert result["_bounded_read"] is True


_USAGE_PAGE = 2
_USAGE_COUNT_CAP = 5


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stored", "total", "capped", "named_total"),
    [
        (_USAGE_COUNT_CAP - 1, _USAGE_COUNT_CAP - 1, False, "4"),
        (_USAGE_COUNT_CAP + 4, _USAGE_COUNT_CAP, True, "more than 5"),
    ],
    ids=["inside-the-cap", "past-the-cap"],
)
async def test_a_component_s_usage_is_counted_exactly_up_to_the_cap_and_past_it_as_a_lower_bound(
    seeded, admin_user, monkeypatch, stored, total, capped, named_total
):
    monkeypatch.setattr(registry, "_COMPONENT_USAGE_READ", _USAGE_PAGE)
    monkeypatch.setattr(registry, "_COMPONENT_USAGE_COUNT_CAP", _USAGE_COUNT_CAP)
    _fill(
        seeded.dependencies,
        stored,
        lambda i: {
            "_id": f"row-{i}",
            "scan_id": _SCAN,
            "project_id": _PROJECT,
            "name": "log4j-core",
            "version": f"2.{i}",
        },
    )

    result = await ChatToolRegistry().execute_tool(
        "find_component_usage", {"component_name": "log4j"}, admin_user, seeded
    )

    assert (result["count"], result["matches_total"], result["matches_total_capped"]) == (_USAGE_PAGE, total, capped)
    assert f"{_USAGE_PAGE} of {named_total} dependency rows naming this component" in result["_bounded_read_note"]


def _fill_oldest_first(collection, count: int, field: str, row) -> list[str]:
    """Collection order alone would keep the oldest rows; returns the ids newest first."""
    ids = [f"row-{i:03d}" for i in range(count)]
    for i, row_id in enumerate(ids):
        collection._docs[row_id] = {"_id": row_id, field: _NOW - timedelta(days=count - i), **row(i)}
    return ids[::-1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "arguments", "collection", "ceiling", "field", "row"),
    [
        (
            "list_project_waivers",
            {"project_id": _PROJECT},
            "waivers",
            _WAIVER_READ,
            "created_at",
            lambda i: {"project_id": _PROJECT, "finding_id": f"f-{i}"},
        ),
        ("list_global_waivers", {}, "waivers", _WAIVER_READ, "created_at", lambda i: {"project_id": None}),
        (
            "list_project_webhooks",
            {"project_id": _PROJECT},
            "webhooks",
            _WEBHOOK_READ,
            "created_at",
            lambda i: {"project_id": _PROJECT, "url": f"https://example.invalid/{i}"},
        ),
        (
            "get_team_projects",
            {"team_id": _TEAM},
            "projects",
            _TEAM_PROJECT_READ,
            "last_scan_at",
            lambda i: {"name": f"p{i}", "team_ids": [_TEAM]},
        ),
    ],
)
async def test_a_listing_cut_at_its_ceiling_keeps_the_newest_rows(
    seeded, admin_user, tool, arguments, collection, ceiling, field, row
):
    newest_first = _fill_oldest_first(getattr(seeded, collection), ceiling + _OVER_THE_CEILING, field, row)

    result = await ChatToolRegistry().execute_tool(tool, arguments, admin_user, seeded)

    # The byte cap may cut the page further; whatever is shown leads with the newest.
    shown = [r["id"] for r in result[collection]]
    assert shown
    assert shown == newest_first[: len(shown)]


@pytest.mark.asyncio
async def test_a_team_risk_read_cut_at_its_ceiling_sums_the_projects_first_by_id(seeded, admin_user, monkeypatch):
    monkeypatch.setattr(registry, "_TEAM_RISK_PROJECT_READ", 2)
    for project_id in ("zz-2", "zz-1", "aa-risky"):
        seeded.projects._docs[project_id] = {
            "_id": project_id,
            "name": project_id,
            "team_ids": [_TEAM],
            "default_branch": "main",
            "latest_scan_id": f"scan-{project_id}",
        }
        seeded.scans._docs[f"scan-{project_id}"] = {
            "_id": f"scan-{project_id}",
            "project_id": project_id,
            "branch": "main",
            "status": "completed",
            "created_at": _NOW,
            "stats": {"critical": 9 if project_id == "aa-risky" else 0},
        }

    result = await ChatToolRegistry().execute_tool("get_team_risk_overview", {"team_id": _TEAM}, admin_user, seeded)

    assert result["projects_summed"] == 2
    assert result["top_risky_projects"][0]["project_id"] == "aa-risky"


@pytest.mark.asyncio
async def test_a_component_s_usage_cut_at_its_ceiling_lists_rows_in_inventory_key_order(
    seeded, admin_user, monkeypatch
):
    monkeypatch.setattr(registry, "_COMPONENT_USAGE_READ", _USAGE_PAGE)
    for minor in reversed(range(5)):
        seeded.dependencies._docs[f"row-{minor}"] = {
            "_id": f"row-{minor}",
            "scan_id": _SCAN,
            "project_id": _PROJECT,
            "name": "log4j-core",
            "version": f"2.{minor}",
        }

    result = await ChatToolRegistry().execute_tool(
        "find_component_usage", {"component_name": "log4j"}, admin_user, seeded
    )

    assert [m["version"] for m in result["matches"]] == ["2.0", "2.1"]


def _finding(finding_id: str, severity: str, **extra) -> dict:
    return {
        "_id": finding_id,
        "finding_id": finding_id,
        "scan_id": _SCAN,
        "project_id": _PROJECT,
        "type": "vulnerability",
        "severity": severity,
        "component": finding_id,
        "version": "1.0.0",
        "description": "",
        "waived": False,
        "details": {"fixed_version": "2.0.0", "vulnerabilities": [{"id": _CVE, "fixed_version": "2.0.0"}]},
        **extra,
    }


@pytest.mark.asyncio
async def test_a_remediation_plan_over_a_full_read_is_built_from_the_criticals_first(seeded, admin_user):
    _fill(seeded.findings, _REMEDIATION_FINDING_READ, lambda i: _finding(f"high-{i:03d}", "HIGH"))
    seeded.findings._docs["critical"] = _finding("critical", "CRITICAL")

    result = await ChatToolRegistry().execute_tool(
        "generate_remediation_plan", {"project_id": _PROJECT}, admin_user, seeded
    )

    assert result["plan"][0]["component"] == "critical"


@pytest.mark.asyncio
async def test_a_findings_read_cut_at_its_ceiling_lists_rows_in_index_key_order(seeded, admin_user, monkeypatch):
    monkeypatch.setattr(registry, "_WAIVER_STATE_READ", 2)
    for finding_id, severity in (("pkg-c", "LOW"), ("pkg-b", "HIGH"), ("pkg-a", "LOW"), ("pkg-d", "CRITICAL")):
        seeded.findings._docs[finding_id] = _finding(finding_id, severity)

    result = await ChatToolRegistry().execute_tool(
        "get_waiver_status", {"project_id": _PROJECT, "finding_id": _CVE}, admin_user, seeded
    )

    assert [f["component"] for f in result["findings"]] == ["pkg-d", "pkg-b"]
