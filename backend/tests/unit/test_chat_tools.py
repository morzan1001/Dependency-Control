"""Tests for chat tool definitions and authorization."""

import re

import pytest

from app.core.config import settings
from app.core.permissions import Permissions
from app.models.archive import ArchiveMetadata
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry, _inject_urls
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


def test_a_row_without_a_finding_id_links_its_scan_not_a_finding():
    row = {"id": "cg-1", "project_id": "p", "scan_id": "s"}

    _inject_urls(row)

    assert row["url"] == f"{settings.FRONTEND_BASE_URL}/projects/p/scans/s"


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


def test_no_tool_description_restates_its_permission_gate():
    """TOOL_PERMISSIONS filters the catalogue before a model reads it, so prose about the gate only drifts."""
    restating = [
        t["function"]["name"]
        for t in TOOL_DEFINITIONS
        if re.search(r"permission|admin only", t["function"]["description"], re.IGNORECASE)
    ]
    assert restating == []


@pytest.mark.asyncio
async def test_system_health_reports_only_the_cache_it_measured(monkeypatch):
    from app.core.cache import cache_service

    async def _unreachable():
        raise ConnectionError("redis down")

    monkeypatch.setattr(cache_service, "get_client", _unreachable)

    result = await ChatToolRegistry().execute_tool("get_system_health", {}, _user(list(PRESET_ADMIN)), FakeDatabase())

    assert result == {"cache": {"status": "unhealthy", "available": False, "error": "redis down"}}


_ARCHIVE_KEYS = {
    "id",
    "project_id",
    "scan_id",
    "branch",
    "commit_hash",
    "scan_created_at",
    "archived_at",
    "compressed_size_bytes",
    "findings_count",
    "critical_findings_count",
    "high_findings_count",
    "dependencies_count",
    "sbom_filenames",
    "url",
}


@pytest.mark.asyncio
async def test_archive_tools_answer_with_the_listing_fields_and_no_storage_keys():
    db = FakeDatabase()
    db.projects._docs["p-foreign"] = {"_id": "p-foreign", "name": "foreign", "members": []}
    archive = ArchiveMetadata(
        project_id="p-foreign", scan_id="s-1", s3_key="p-foreign/s-1.json.gz", s3_bucket="dc-archives"
    ).model_dump(by_alias=True)
    db.archive_metadata._docs[archive["_id"]] = archive
    user = _user([*_PROJECT_READER, Permissions.ARCHIVE_READ_ALL])
    registry = ChatToolRegistry()

    listed = await registry.execute_tool("list_archives", {}, user, db)
    details = await registry.execute_tool("get_archive_details", {"archive_id": archive["_id"]}, user, db)

    assert set(listed["archives"][0]) == _ARCHIVE_KEYS
    assert set(details["archive"]) == _ARCHIVE_KEYS
