"""Every tool call lands in dc_chat_tool_calls_total under a status that says how it ended, so a
dashboard can tell a refusal or an error answer from a success."""

import logging

import pytest
from prometheus_client import REGISTRY

from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN, PRESET_USER
from tests.mocks.fake_mongo import FakeDatabase

_METRIC = "dc_chat_tool_calls_total"


def _count(tool_name: str, status: str) -> float:
    return REGISTRY.get_sample_value(_METRIC, {"tool_name": tool_name, "status": status}) or 0.0


def _user(permissions: list[str]) -> User:
    return User(id="u-metrics", username="metrics", email="metrics@test.com", permissions=permissions)


@pytest.mark.asyncio
async def test_an_unknown_tool_is_counted_under_one_fixed_label_without_reading_the_database() -> None:
    before = _count("unknown", "unknown")

    result = await ChatToolRegistry().execute_tool("get_update_suggestions", {}, _user(PRESET_ADMIN), object())

    assert result == {"error": "Unknown tool: get_update_suggestions"}
    assert _count("unknown", "unknown") == before + 1
    assert REGISTRY.get_sample_value(_METRIC, {"tool_name": "get_update_suggestions", "status": "success"}) is None


@pytest.mark.asyncio
async def test_a_permission_refusal_is_counted_as_denied() -> None:
    before = _count("get_system_settings", "denied")

    result = await ChatToolRegistry().execute_tool("get_system_settings", {}, _user(PRESET_USER), FakeDatabase())

    assert "permission" in result["error"]
    assert _count("get_system_settings", "denied") == before + 1


@pytest.mark.asyncio
async def test_an_error_answer_is_counted_as_rejected_not_success() -> None:
    success_before = _count("get_project_details", "success")
    rejected_before = _count("get_project_details", "rejected")

    result = await ChatToolRegistry().execute_tool(
        "get_project_details", {"project_id": "p-absent"}, _user(PRESET_ADMIN), FakeDatabase()
    )

    assert "error" in result
    assert _count("get_project_details", "rejected") == rejected_before + 1
    assert _count("get_project_details", "success") == success_before


@pytest.mark.asyncio
async def test_a_scope_denial_is_a_refusal_not_a_tool_failure(caplog: pytest.LogCaptureFixture) -> None:
    before = _count("get_framework_evaluation_summary", "refused")

    with caplog.at_level(logging.ERROR):
        result = await ChatToolRegistry().execute_tool(
            "get_framework_evaluation_summary",
            {"scope": "global", "framework": "nist-sp-800-131a"},
            _user(PRESET_USER),
            FakeDatabase(),
        )

    assert result == {"error": "Global analytics requires analytics:global or system:manage"}
    assert _count("get_framework_evaluation_summary", "refused") == before + 1
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []
