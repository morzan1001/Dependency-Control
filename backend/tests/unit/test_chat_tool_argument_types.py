"""Tool arguments come from an MCP client or a model that read attacker-written SBOM text, and an
object where a string is declared is a Mongo operator: ``{"$ne": null}`` as a project_id passes the
access check on the caller's own project, then selects every tenant's rows."""

import pytest

from app.api.v1.endpoints.mcp import _handle_tool_call
from app.models.finding import FindingType, Severity
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools._arguments import checked_arguments
from app.services.chat.tools._helpers import begin_limit_ledger, clamped_limit_note
from app.services.chat.tools.definitions import TOOL_DEFINITIONS
from tests.helpers.permission_presets import PRESET_ADMIN
from tests.mocks.fake_mongo import FakeDatabase

_CALLER = "u-caller"
_MINE = "p-mine"
_THEIRS = "p-theirs"
_MY_SCAN = "scan-mine"
_MY_PRIOR_SCAN = "scan-mine-prior"
_THEIR_SCAN = "scan-theirs"
_MY_WEBHOOK = "hook-mine"
_THEIR_SECRET = "hmac-secret-of-another-team"
_OPERATOR = {"$ne": None}
_STAND_IN = "x"


def _caller() -> User:
    """Every tool permission, so only the per-project membership check can refuse."""
    return User(
        id=_CALLER,
        username="caller",
        email="caller@test.com",
        permissions=[p for p in PRESET_ADMIN if p != "project:read_all"],
    )


def _seeded() -> FakeDatabase:
    db = FakeDatabase()
    db.projects._docs[_MINE] = {
        "_id": _MINE,
        "name": "mine",
        "default_branch": "main",
        "members": [{"user_id": _CALLER, "role": "admin"}],
    }
    db.projects._docs[_THEIRS] = {
        "_id": _THEIRS,
        "name": "theirs",
        "default_branch": "main",
        "members": [{"user_id": "someone-else", "role": "admin"}],
    }
    for scan_id, project_id, created_at in (
        (_MY_PRIOR_SCAN, _MINE, "2026-09-01"),
        (_MY_SCAN, _MINE, "2026-09-02"),
        (_THEIR_SCAN, _THEIRS, "2026-09-02"),
    ):
        db.scans._docs[scan_id] = {
            "_id": scan_id,
            "project_id": project_id,
            "branch": "main",
            "status": "completed",
            "created_at": created_at,
        }
    db.webhooks._docs[_MY_WEBHOOK] = {"_id": _MY_WEBHOOK, "project_id": _MINE, "url": "https://mine.test"}
    db.webhooks._docs["hook-theirs"] = {
        "_id": "hook-theirs",
        "project_id": _THEIRS,
        "url": "https://theirs.test",
        "secret": _THEIR_SECRET,
    }
    return db


class _Tripwire:
    """A database that records every collection a call reaches for, so a refusal can be shown
    to have come before the first query."""

    def __init__(self) -> None:
        self.reached: list[str] = []

    def __getitem__(self, name: str):
        self.reached.append(name)
        raise AssertionError(f"queried {name}")

    def __getattr__(self, name: str):
        self.reached.append(name)
        raise AssertionError(f"queried {name}")


def _valid_value(schema: dict):
    if schema.get("enum"):
        return schema["enum"][0]
    if schema["type"] == "integer":
        return 1
    if schema["type"] == "boolean":
        return True
    if schema["type"] == "array":
        return [_valid_value(schema["items"])]
    return _STAND_IN


# Every (tool, parameter, schema) the registry advertises.
_DECLARED_PARAMETERS = [
    (definition["function"]["name"], name, schema)
    for definition in TOOL_DEFINITIONS
    for name, schema in definition["function"]["parameters"].get("properties", {}).items()
]


# Every bounded integer: the schema a client validates against is also the clamp the server applies.
_BOUNDED_PARAMETERS = [(tool, name, schema) for tool, name, schema in _DECLARED_PARAMETERS if "maximum" in schema]
_BOUNDED_IDS = [f"{tool}.{parameter}" for tool, parameter, _ in _BOUNDED_PARAMETERS]
# An offset has no ceiling: skipping or paging further only ever returns fewer rows.
_CEILINGED_INTEGERS = [
    (tool, name, schema)
    for tool, name, schema in _DECLARED_PARAMETERS
    if schema["type"] == "integer" and name not in {"skip", "page"}
]
_DOMAIN_VOCABULARY = {
    "type": [t.value for t in FindingType],
    "finding_type": [t.value for t in FindingType],
    "severity": [s.value for s in Severity],
}


def _required_arguments(tool_name: str) -> dict:
    parameters = next(d["function"]["parameters"] for d in TOOL_DEFINITIONS if d["function"]["name"] == tool_name)
    return {name: _valid_value(parameters["properties"][name]) for name in parameters.get("required", [])}


@pytest.mark.asyncio
async def test_an_operator_project_id_does_not_read_another_tenants_webhook_secret() -> None:
    result = await ChatToolRegistry().execute_tool(
        "list_project_webhooks", {"project_id": _OPERATOR}, _caller(), _seeded()
    )

    assert _THEIR_SECRET not in str(result)
    assert "project_id" in result["error"]


@pytest.mark.asyncio
async def test_an_operator_project_id_is_refused_before_any_query_runs() -> None:
    db = _Tripwire()

    result = await ChatToolRegistry().execute_tool("list_project_webhooks", {"project_id": _OPERATOR}, _caller(), db)

    assert db.reached == []
    assert "project_id" in result["error"]


@pytest.mark.parametrize(
    ("tool_name", "parameter", "schema"),
    _DECLARED_PARAMETERS,
    ids=[f"{tool}.{parameter}" for tool, parameter, _ in _DECLARED_PARAMETERS],
)
@pytest.mark.asyncio
async def test_an_operator_in_any_declared_argument_is_refused_before_any_query_runs(
    tool_name: str, parameter: str, schema: dict
) -> None:
    operator = [_OPERATOR] if schema["type"] == "array" else _OPERATOR
    db = _Tripwire()

    result = await ChatToolRegistry().execute_tool(
        tool_name, {**_required_arguments(tool_name), parameter: operator}, _caller(), db
    )

    assert db.reached == []
    assert parameter in result["error"]


@pytest.mark.parametrize(
    ("tool_name", "parameter", "schema"),
    _DECLARED_PARAMETERS,
    ids=[f"{tool}.{parameter}" for tool, parameter, _ in _DECLARED_PARAMETERS],
)
def test_every_declared_parameter_accepts_a_value_of_its_declared_type(
    tool_name: str, parameter: str, schema: dict
) -> None:
    """A type the check does not know would refuse every call that passes it."""
    value = _valid_value(schema)

    assert checked_arguments(tool_name, {parameter: value})[parameter] == value


@pytest.mark.parametrize(
    ("tool_name", "parameter", "schema"), _CEILINGED_INTEGERS, ids=[f"{t}.{p}" for t, p, _ in _CEILINGED_INTEGERS]
)
def test_every_integer_argument_declares_the_default_and_ceiling_it_is_held_to(
    tool_name: str, parameter: str, schema: dict
) -> None:
    assert {"default", "minimum", "maximum"} <= schema.keys()
    assert str(schema["default"]) in schema["description"]
    assert str(schema["maximum"]) in schema["description"]


@pytest.mark.parametrize(("tool_name", "parameter", "schema"), _BOUNDED_PARAMETERS, ids=_BOUNDED_IDS)
def test_an_omitted_bounded_argument_takes_its_declared_default(tool_name: str, parameter: str, schema: dict) -> None:
    assert checked_arguments(tool_name, _required_arguments(tool_name))[parameter] == schema["default"]


@pytest.mark.parametrize(("tool_name", "parameter", "schema"), _BOUNDED_PARAMETERS, ids=_BOUNDED_IDS)
def test_a_bounded_argument_past_its_declared_ceiling_is_held_to_it_and_noted(
    tool_name: str, parameter: str, schema: dict
) -> None:
    asked_for = schema["maximum"] + 1
    begin_limit_ledger()

    checked = checked_arguments(tool_name, {**_required_arguments(tool_name), parameter: asked_for})

    assert checked[parameter] == schema["maximum"]
    assert f"{asked_for} to {schema['maximum']}" in (clamped_limit_note() or "")


@pytest.mark.parametrize(
    ("tool_name", "parameter", "schema"),
    [entry for entry in _DECLARED_PARAMETERS if entry[1] in _DOMAIN_VOCABULARY],
    ids=[f"{tool}.{parameter}" for tool, parameter, _ in _DECLARED_PARAMETERS if parameter in _DOMAIN_VOCABULARY],
)
def test_every_type_and_severity_filter_offers_exactly_the_values_findings_carry(
    tool_name: str, parameter: str, schema: dict
) -> None:
    offered = schema["items"] if schema["type"] == "array" else schema

    assert offered.get("enum") == _DOMAIN_VOCABULARY[parameter]


@pytest.mark.parametrize(("parameter", "value"), [("type", "typosquat"), ("severity", "SEVERE")])
@pytest.mark.asyncio
async def test_a_filter_value_no_finding_carries_is_refused_before_any_query_runs(parameter: str, value: str) -> None:
    """Answered, it would read as 'none found' for a question the filter could never match."""
    db = _Tripwire()

    result = await ChatToolRegistry().execute_tool(
        "get_scan_findings", {"project_id": _MINE, parameter: value}, _caller(), db
    )

    assert db.reached == []
    assert parameter in result["error"]


def test_a_filter_value_is_matched_whatever_its_case() -> None:
    checked = checked_arguments("get_scan_findings", {"project_id": _MINE, "severity": "critical", "type": "Malware"})

    assert (checked["severity"], checked["type"]) == ("CRITICAL", "malware")


@pytest.mark.asyncio
async def test_a_list_where_a_string_is_declared_is_refused() -> None:
    db = _Tripwire()

    result = await ChatToolRegistry().execute_tool("get_scan_findings", {"project_id": [_MINE]}, _caller(), db)

    assert db.reached == []
    assert "project_id" in result["error"]


@pytest.mark.asyncio
async def test_arguments_that_are_not_an_object_are_refused_before_any_query_runs() -> None:
    db = _Tripwire()

    result = await ChatToolRegistry().execute_tool("list_project_webhooks", '{"project_id": "p"}', _caller(), db)

    assert db.reached == []
    assert "error" in result


@pytest.mark.asyncio
async def test_a_valid_call_is_answered() -> None:
    result = await ChatToolRegistry().execute_tool("list_project_webhooks", {"project_id": _MINE}, _caller(), _seeded())

    assert [hook["id"] for hook in result["webhooks"]] == [_MY_WEBHOOK]


@pytest.mark.asyncio
async def test_an_undeclared_argument_is_dropped_rather_than_failing_the_call() -> None:
    registry = ChatToolRegistry()
    plain = await registry.execute_tool("list_project_webhooks", {"project_id": _MINE}, _caller(), _seeded())

    chatty = await registry.execute_tool(
        "list_project_webhooks", {"project_id": _MINE, "include_secrets": _OPERATOR}, _caller(), _seeded()
    )

    assert chatty == plain


@pytest.mark.asyncio
async def test_a_numeric_string_limit_still_limits() -> None:
    result = await ChatToolRegistry().execute_tool(
        "get_scan_history", {"project_id": _MINE, "limit": "1"}, _caller(), _seeded()
    )

    assert len(result["scans"]) == 1


@pytest.mark.asyncio
async def test_a_null_optional_argument_still_means_not_given() -> None:
    result = await ChatToolRegistry().execute_tool(
        "get_scan_details", {"project_id": _MINE, "scan_id": None}, _caller(), _seeded()
    )

    assert result["scan"]["id"] == _MY_SCAN


@pytest.mark.asyncio
async def test_a_single_string_where_a_list_is_declared_is_still_accepted() -> None:
    result = await ChatToolRegistry().execute_tool(
        "compare_scans",
        {"project_id": _MINE, "from_scan_id": _MY_PRIOR_SCAN, "to_scan_id": _MY_SCAN, "severity": "critical"},
        _caller(),
        _seeded(),
    )

    assert "error" not in result


@pytest.mark.asyncio
async def test_mcp_reports_a_refused_argument_as_a_tool_error() -> None:
    response = await _handle_tool_call(
        ChatToolRegistry(),
        {"name": "list_project_webhooks", "arguments": {"project_id": _OPERATOR}},
        _caller(),
        _seeded(),
    )

    assert response["isError"] is True
    assert _THEIR_SECRET not in response["content"][0]["text"]
