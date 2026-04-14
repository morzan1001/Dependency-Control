"""Tests for chat tool definitions and authorization."""

import pytest

from app.core.permissions import Permissions, PRESET_USER, PRESET_ADMIN
from app.services.chat.tools import ChatToolRegistry, get_tool_definitions


def test_tool_definitions_valid_json_schema():
    """Every tool definition must be a valid Ollama tool schema."""
    tools = get_tool_definitions()
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
    """Admin-only tools must not be available to regular users."""
    registry = ChatToolRegistry()
    admin_tools = {"get_system_settings", "get_system_health", "list_global_waivers"}

    available_for_user = registry.get_available_tool_names(PRESET_USER)
    for tool_name in admin_tools:
        assert tool_name not in available_for_user

    available_for_admin = registry.get_available_tool_names(PRESET_ADMIN)
    for tool_name in admin_tools:
        assert tool_name in available_for_admin


def test_user_with_chat_access_gets_basic_tools():
    """A user with chat:access + standard permissions gets project/finding tools."""
    registry = ChatToolRegistry()
    permissions = PRESET_USER + [Permissions.CHAT_ACCESS]
    available = registry.get_available_tool_names(permissions)

    assert "list_projects" in available
    assert "get_project_findings" in available
    assert "search_findings" in available
    assert "get_recommendations" in available


def test_tool_definitions_match_registry():
    """All registered tools must appear in the Ollama tool definitions."""
    registry = ChatToolRegistry()
    definitions = get_tool_definitions()
    definition_names = {t["function"]["name"] for t in definitions}
    all_tools = registry.get_available_tool_names(PRESET_ADMIN)

    for tool_name in all_tools:
        assert tool_name in definition_names, f"Tool {tool_name} missing from definitions"
