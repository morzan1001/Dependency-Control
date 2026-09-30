"""Tests for chat tool definitions and authorization."""

import pytest

from app.core.permissions import Permissions
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools.definitions import TOOL_DEFINITIONS
from tests.helpers.permission_presets import PRESET_ADMIN, PRESET_USER
from tests.mocks.fake_mongo import FakeDatabase


def _user(permissions: list[str]) -> User:
    return User(id="u-1", username="u", email="u@test.com", permissions=permissions)


def test_tool_definitions_valid_json_schema():
    tools = TOOL_DEFINITIONS
    assert len(tools) > 0
    for tool in tools:
        assert "type" in tool
        assert tool["type"] == "function"
        assert "function" in tool
        fn = tool["function"]
        assert "name" in fn
        assert "description" in fn
        assert "parameters" in fn


def test_admin_tools_require_admin_permission():
    registry = ChatToolRegistry()
    admin_tools = {"get_system_settings", "get_system_health"}

    available_for_user = registry.get_available_tool_names(PRESET_USER)
    for tool_name in admin_tools:
        assert tool_name not in available_for_user

    available_for_admin = registry.get_available_tool_names(PRESET_ADMIN)
    for tool_name in admin_tools:
        assert tool_name in available_for_admin


def test_user_with_chat_access_gets_basic_tools():
    registry = ChatToolRegistry()
    permissions = [*PRESET_USER, Permissions.CHAT_ACCESS]
    available = registry.get_available_tool_names(permissions)

    assert "list_projects" in available
    assert "get_scan_findings" in available
    assert "search_findings" in available
    assert "get_top_priority_findings" in available
    assert "get_kev_findings" in available
    assert "compare_scans" in available
    assert "find_component_usage" in available


def test_tool_definitions_match_registry():
    registry = ChatToolRegistry()
    definitions = TOOL_DEFINITIONS
    definition_names = {t["function"]["name"] for t in definitions}
    all_tools = registry.get_available_tool_names(PRESET_ADMIN)

    for tool_name in all_tools:
        assert tool_name in definition_names, f"Tool {tool_name} missing from definitions"


def test_dispatch_table_covers_exactly_the_declared_tools():
    """A declared tool absent from the table answers "Unknown tool" instead of failing loudly."""
    declared = {t["function"]["name"] for t in TOOL_DEFINITIONS}
    assert set(ChatToolRegistry._HANDLERS) == declared


_PROJECT_READER = [Permissions.PROJECT_READ, Permissions.CHAT_ACCESS]
_ANALYTICS_GATED_TOOLS = {
    "search_findings": Permissions.ANALYTICS_SEARCH,
    "get_findings_by_cve": Permissions.ANALYTICS_SEARCH,
    "get_cve_details": Permissions.ANALYTICS_SEARCH,
    "find_component_usage": Permissions.ANALYTICS_SEARCH,
    "generate_remediation_plan": Permissions.ANALYTICS_RECOMMENDATIONS,
    "get_analytics_summary": Permissions.ANALYTICS_SUMMARY,
}


def test_a_project_reader_without_analytics_is_not_offered_the_analytics_tools():
    available = ChatToolRegistry().get_available_tool_names(_PROJECT_READER)

    assert available.isdisjoint(_ANALYTICS_GATED_TOOLS)
    assert {"get_hotspots", "get_dependency_details", "get_scan_findings"} <= available


@pytest.mark.parametrize(("tool_name", "feature"), sorted(_ANALYTICS_GATED_TOOLS.items()))
@pytest.mark.asyncio
async def test_an_analytics_tool_is_refused_without_analytics_and_opened_by_read_or_its_feature(
    tool_name: str, feature: str
):
    registry = ChatToolRegistry()

    refused = await registry.execute_tool(tool_name, {}, _user(_PROJECT_READER), FakeDatabase())

    assert refused == {"error": f"You don't have permission to use {tool_name}"}
    for grant in (Permissions.ANALYTICS_READ, feature):
        assert tool_name in registry.get_available_tool_names([*_PROJECT_READER, grant])


def test_archive_read_all_alone_opens_the_archive_tools():
    available = ChatToolRegistry().get_available_tool_names([*_PROJECT_READER, Permissions.ARCHIVE_READ_ALL])

    assert {"list_archives", "get_archive_details"} <= available


@pytest.mark.asyncio
async def test_archive_read_all_filtered_to_a_project_lists_what_the_unfiltered_listing_holds():
    db = FakeDatabase()
    db.projects._docs["p-foreign"] = {"_id": "p-foreign", "name": "foreign", "members": []}
    db.archive_metadata._docs["a-1"] = {"_id": "a-1", "project_id": "p-foreign", "scan_id": "s-1"}
    user = _user([*_PROJECT_READER, Permissions.ARCHIVE_READ_ALL])
    registry = ChatToolRegistry()

    unfiltered = await registry.execute_tool("list_archives", {}, user, db)
    filtered = await registry.execute_tool("list_archives", {"project_id": "p-foreign"}, user, db)

    assert [a["id"] for a in unfiltered["archives"]] == ["a-1"]
    assert filtered["archives"] == unfiltered["archives"]
