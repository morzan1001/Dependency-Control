"""Every project-scoped chat/MCP tool, swept from the registry rather than enumerated by hand.

These run under the API key owner's authorization and answer a language model, which relays the
answer with no project name beside it to contradict a leak. The rule swept here is that a refusal
has to be indistinguishable from the project not existing: "you may not read it" and "there is no
such project" must produce the same answer, or the counts in the difference are the leak.

Sweeping the registry means a tool added with a project_id parameter joins the sweep instead of
waiting for someone to list it here.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools.definitions import TOOL_DEFINITIONS
from tests.helpers.permission_presets import PRESET_ADMIN
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
_EARLIER = _NOW - timedelta(days=1)
_CALLER = "u-1"
_THEIRS = "p-theirs"
_ABSENT = "p-absent"
_SENTINEL = "sentinel-only-in-the-foreign-project"
_THEIR_SCAN = "scan-theirs"
_THEIR_PRIOR_SCAN = "scan-theirs-prior"
_THEIR_CVE = "CVE-2026-99999"
_PROJECT_ID_PARAM = "project_id"
_STRING_STAND_INS = {
    "scan_id": _THEIR_SCAN,
    "base_scan_id": _THEIR_PRIOR_SCAN,
    "head_scan_id": _THEIR_SCAN,
    "cve_id": _THEIR_CVE,
    "vulnerability_id": _THEIR_CVE,
    "finding_id": _THEIR_CVE,
    "component": _SENTINEL,
    "component_name": _SENTINEL,
    "package_name": _SENTINEL,
    "algorithm": _SENTINEL,
    "asset_id": _SENTINEL,
}
# An enum value the sweep needs pinned: "system" scope is admin-gated and not project-scoped.
_ENUM_STAND_INS = {"policy_scope": "project"}


def _project_scoped_tools() -> list[str]:
    names = []
    for definition in TOOL_DEFINITIONS:
        function = definition["function"]
        if _PROJECT_ID_PARAM in function.get("parameters", {}).get("properties", {}):
            names.append(function["name"])
    return sorted(names)


_PROJECT_SCOPED_TOOLS = _project_scoped_tools()
_ALWAYS_PROJECT_SCOPED = frozenset(
    {
        "get_project_details",
        "get_project_findings",
        "get_project_members",
        "get_project_settings",
        "get_scan_history",
        "list_project_waivers",
        "list_project_webhooks",
    }
)


def _arguments(tool_name: str, project_id: str) -> dict:
    """The tool's required parameters plus project_id, which is the parameter under sweep and is
    optional on the tools that otherwise answer estate-wide."""
    function = next(d["function"] for d in TOOL_DEFINITIONS if d["function"]["name"] == tool_name)
    parameters = function.get("parameters", {})
    properties = parameters.get("properties", {})
    arguments: dict = {_PROJECT_ID_PARAM: project_id}
    for name in parameters.get("required", []):
        schema = properties.get(name, {})
        if name == _PROJECT_ID_PARAM:
            arguments[name] = project_id
        elif schema.get("enum"):
            arguments[name] = _ENUM_STAND_INS.get(name, schema["enum"][0])
        elif schema.get("type") == "integer":
            arguments[name] = 1
        elif schema.get("type") == "boolean":
            arguments[name] = True
        else:
            arguments[name] = _STRING_STAND_INS.get(name, _SENTINEL)
    return arguments


def _finding(doc_id: str, finding_type: str, **overrides) -> dict:
    finding = {
        "_id": doc_id,
        "finding_id": doc_id,
        "scan_id": _THEIR_SCAN,
        "project_id": _THEIRS,
        "type": finding_type,
        "severity": "CRITICAL",
        "component": _SENTINEL,
        "version": "1.0.0",
        "details": {"description": _SENTINEL},
        "waived": False,
    }
    finding.update(overrides)
    return finding


def _seeded(member_ids: list[str]) -> FakeDatabase:
    """One project full of sentinel-bearing data, readable only by ``member_ids``."""
    db = FakeDatabase()
    db.projects._docs[_THEIRS] = {
        "_id": _THEIRS,
        "name": _SENTINEL,
        "default_branch": "main",
        "deleted_branches": [],
        "latest_scan_id": _THEIR_SCAN,
        "retention_action": _SENTINEL,
        "active_analyzers": [_SENTINEL],
        "members": [{"user_id": uid, "role": "admin", "username": _SENTINEL} for uid in member_ids],
        "crypto_policy": {"note": _SENTINEL},
    }
    for scan_id, created_at in ((_THEIR_PRIOR_SCAN, _EARLIER), (_THEIR_SCAN, _NOW)):
        db.scans._docs[scan_id] = {
            "_id": scan_id,
            "project_id": _THEIRS,
            "branch": "main",
            "status": "completed",
            "created_at": created_at,
            "commit_hash": _SENTINEL,
            "stats": {"critical": 1, "high": 0, "risk_score": 9.9},
        }
    for finding in (
        _finding("f-vuln", "vulnerability", finding_id=_THEIR_CVE, details={"in_kev": True, "epss_score": 0.9}),
        _finding("f-license", "license", details={"license": _SENTINEL, "category": "strong_copyleft"}),
        _finding("f-outdated", "outdated", details={"fix_version": "2.0.0"}),
        _finding("f-crypto", "crypto_weak_algorithm", details={"algorithm": _SENTINEL}),
        _finding("f-prior", "vulnerability", scan_id=_THEIR_PRIOR_SCAN, finding_id="CVE-2026-11111"),
    ):
        db.findings._docs[finding["_id"]] = finding
    db.dependencies._docs["d-1"] = {
        "_id": "d-1",
        "scan_id": _THEIR_SCAN,
        "project_id": _THEIRS,
        "name": _SENTINEL,
        "version": "1.0.0",
        "direct": True,
    }
    db.waivers._docs["w-1"] = {
        "_id": "w-1",
        "project_id": _THEIRS,
        "reason": _SENTINEL,
        "created_by": "admin",
        "finding_id": _THEIR_CVE,
    }
    db.webhooks._docs["h-1"] = {"_id": "h-1", "project_id": _THEIRS, "url": f"https://{_SENTINEL}.test"}
    db.webhook_deliveries._docs["wd-1"] = {"_id": "wd-1", "project_id": _THEIRS, "status_code": 500}
    db.archive_metadata._docs["a-1"] = {
        "_id": "a-1",
        "project_id": _THEIRS,
        "scan_id": _THEIR_SCAN,
        "s3_key": _SENTINEL,
        "s3_bucket": "b",
    }
    db.callgraphs._docs["c-1"] = {"_id": "c-1", "scan_id": _THEIR_SCAN, "project_id": _THEIRS, "language": _SENTINEL}
    db.crypto_assets._docs["ca-1"] = {
        "_id": "ca-1",
        "scan_id": _THEIR_SCAN,
        "project_id": _THEIRS,
        "asset_type": "algorithm",
        "name": _SENTINEL,
    }
    db.compliance_reports._docs["cr-1"] = {"_id": "cr-1", "project_id": _THEIRS, "framework": _SENTINEL}
    db.crypto_policy_history._docs["pa-1"] = {
        "_id": "pa-1",
        "policy_type": "crypto",
        "policy_scope": "project",
        "project_id": _THEIRS,
        "version": 1,
        "action": "update",
        "actor_display_name": _SENTINEL,
        "timestamp": _NOW,
    }
    return db


@pytest.fixture
def caller() -> User:
    """Every tool-level permission, so only the per-project membership check can refuse."""
    return User(
        id=_CALLER,
        username="u",
        email="u@test.com",
        permissions=[p for p in PRESET_ADMIN if p != "project:read_all"],
    )


async def _answer(caller: User, tool_name: str, project_id: str, members: list[str]) -> str:
    db = _seeded(members)
    result = await ChatToolRegistry().execute_tool(tool_name, _arguments(tool_name, project_id), caller, db)
    return json.dumps(result, default=str, sort_keys=True)


@pytest.mark.parametrize("tool_name", _PROJECT_SCOPED_TOOLS)
@pytest.mark.asyncio
async def test_a_refusal_is_indistinguishable_from_the_project_not_existing(tool_name: str, caller: User) -> None:
    denied = await _answer(caller, tool_name, _THEIRS, members=["someone-else"])
    absent = await _answer(caller, tool_name, _ABSENT, members=["someone-else"])

    assert denied == absent
    assert _SENTINEL not in denied


@pytest.mark.parametrize("tool_name", _PROJECT_SCOPED_TOOLS)
@pytest.mark.asyncio
async def test_the_sweep_can_tell_an_authorised_answer_apart(tool_name: str, caller: User) -> None:
    """Without this every case above would pass on a tool that answers nothing to anyone."""
    granted = await _answer(caller, tool_name, _THEIRS, members=[_CALLER])
    absent = await _answer(caller, tool_name, _ABSENT, members=[_CALLER])

    assert granted != absent


def test_the_registry_walk_still_finds_the_project_scoped_tools() -> None:
    """The sweep is driven off the schema, so a change to its shape would silently empty it."""
    assert _ALWAYS_PROJECT_SCOPED <= set(_PROJECT_SCOPED_TOOLS)
