"""Handlers query by the ids of the documents the access check loaded, never the caller's arguments.
Driven through ``_dispatch``, past the argument check, so an operator id reaches the handler."""

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
_CALLER = "u-caller"
_MINE = "p-mine"
_THEIRS = "p-theirs"
_SENTINEL = "sentinel-only-in-the-foreign-project"
_OPERATOR = {"$ne": None}
_ID_PARAMETERS = frozenset(
    {"project_id", "scan_id", "finding_id", "asset_id", "scan_id_a", "scan_id_b", "from_scan_id", "to_scan_id"}
)
# "system" scope is admin-gated and not project-scoped.
_ENUM_STAND_INS = {"policy_scope": "project"}


def _caller() -> User:
    """Every tool permission, but reads only the projects and teams it is a member of."""
    return User(
        id=_CALLER,
        username="caller",
        email="caller@test.com",
        permissions=[
            p
            for p in PRESET_ADMIN
            if p not in {"project:read_all", "project:update", "team:read_all", "waiver:read_all", "archive:read_all"}
        ],
    )


def _seed_project(db: FakeDatabase, project_id: str, marker: str, member: str) -> None:
    """One project with a document in every collection a project-scoped tool reads, each carrying
    ``marker`` so an answer shows whose data it was built from."""
    head, prior = f"{project_id}-scan", f"{project_id}-prior"
    db.projects._docs[project_id] = {
        "_id": project_id,
        "name": marker,
        "default_branch": "main",
        "deleted_branches": [],
        "latest_scan_id": head,
        "members": [{"user_id": member, "role": "admin"}],
    }
    for scan_id, created_at in ((prior, _EARLIER), (head, _NOW)):
        db.scans._docs[scan_id] = {
            "_id": scan_id,
            "project_id": project_id,
            "branch": "main",
            "status": "completed",
            "created_at": created_at,
            "commit_hash": marker,
        }
    for doc_id, finding_type, scan_id in (
        ("vuln", "vulnerability", head),
        ("license", "license", head),
        ("crypto", "crypto_weak_algorithm", head),
        ("prior", "vulnerability", prior),
    ):
        db.findings._docs[f"{project_id}-{doc_id}"] = {
            "_id": f"{project_id}-{doc_id}",
            "finding_id": f"{project_id}-{doc_id}",
            "scan_id": scan_id,
            "project_id": project_id,
            "type": finding_type,
            "severity": "CRITICAL",
            "component": marker,
            "version": "1.0.0",
            "details": {"description": marker, "fixed_version": "2.0.0", "exploit_maturity": "active"},
            "waived": False,
            "created_at": _EARLIER - timedelta(days=90),
        }
    db.waivers._docs[f"{project_id}-w"] = {"_id": f"{project_id}-w", "project_id": project_id, "reason": marker}
    db.webhooks._docs[f"{project_id}-h"] = {
        "_id": f"{project_id}-h",
        "project_id": project_id,
        "url": "https://receiver.test/hook",
        "events": ["scan_completed"],
        "secret": marker,
    }
    db.webhook_deliveries._docs[f"{project_id}-d"] = {
        "_id": f"{project_id}-d",
        "webhook_id": f"{project_id}-h",
        "response_body": marker,
    }
    db.archive_metadata._docs[f"{project_id}-a"] = {
        "_id": f"{project_id}-a",
        "project_id": project_id,
        "s3_key": marker,
    }
    db.callgraphs._docs[f"{project_id}-c"] = {
        "_id": f"{project_id}-c",
        "project_id": project_id,
        "scan_id": head,
        "language": marker,
        "created_at": _NOW,
    }
    db.crypto_assets._docs[f"{project_id}-ca"] = {
        "_id": f"{project_id}-ca",
        "project_id": project_id,
        "scan_id": head,
        "bom_ref": marker,
        "asset_type": "algorithm",
        "name": marker,
    }
    db.compliance_reports._docs[f"{project_id}-cr"] = {
        "_id": f"{project_id}-cr",
        "scope": "project",
        "scope_id": project_id,
        "framework": "nist-sp-800-131a",
        "format": "pdf",
        "status": "completed",
        "requested_by": marker,
        "requested_at": _NOW,
    }
    db.crypto_policies._docs[f"{project_id}-cp"] = {
        "_id": f"{project_id}-cp",
        "scope": "project",
        "project_id": project_id,
        "rules": [
            {
                "rule_id": marker,
                "name": marker,
                "description": marker,
                "finding_type": "crypto_weak_algorithm",
                "default_severity": "LOW",
                "source": "custom",
            }
        ],
        "version": 1,
    }
    db.crypto_policy_history._docs[f"{project_id}-pa"] = {
        "_id": f"{project_id}-pa",
        "policy_type": "crypto",
        "policy_scope": "project",
        "project_id": project_id,
        "version": 1,
        "action": "update",
        "actor_display_name": marker,
        "timestamp": _NOW,
        "snapshot": {},
        "change_summary": marker,
    }


def _seeded() -> FakeDatabase:
    """The foreign project is inserted first, so an unscoped query meets its rows before the caller's."""
    db = FakeDatabase()
    db.crypto_policies._docs["system"] = {"_id": "system", "scope": "system", "project_id": None, "rules": []}
    _seed_project(db, _THEIRS, _SENTINEL, "someone-else")
    _seed_project(db, _MINE, "mine", _CALLER)
    return db


def _stand_in(name: str, schema: dict):
    if name in _ID_PARAMETERS:
        return _OPERATOR
    if name in _ENUM_STAND_INS:
        return _ENUM_STAND_INS[name]
    if schema.get("enum"):
        return schema["enum"][0]
    return 1 if schema["type"] == "integer" else "x"


def _project_scoped_cases() -> list[tuple[str, dict]]:
    """Every tool taking a project_id, with each of its id arguments set to an operator."""
    cases: list[tuple[str, dict]] = []
    for definition in TOOL_DEFINITIONS:
        function = definition["function"]
        parameters = function["parameters"]
        properties = parameters.get("properties", {})
        if "project_id" not in properties:
            continue
        wanted = set(parameters.get("required", [])) | (_ID_PARAMETERS & set(properties))
        cases.append((function["name"], {name: _stand_in(name, properties[name]) for name in sorted(wanted)}))
    return cases


async def _answer(tool_name: str, arguments: dict, db: FakeDatabase | None = None) -> str:
    result = await ChatToolRegistry()._dispatch(tool_name, arguments, _caller(), db or _seeded())
    return json.dumps(result, default=str)


_PROJECT_SCOPED_CASES = _project_scoped_cases()


@pytest.mark.parametrize(
    ("tool_name", "arguments"), _PROJECT_SCOPED_CASES, ids=[name for name, _ in _PROJECT_SCOPED_CASES]
)
@pytest.mark.asyncio
async def test_an_operator_id_reads_only_the_project_the_access_check_loaded(tool_name: str, arguments: dict) -> None:
    assert _SENTINEL not in await _answer(tool_name, arguments)


@pytest.mark.asyncio
async def test_webhook_deliveries_are_read_for_the_webhook_the_access_check_loaded() -> None:
    db = FakeDatabase()
    _seed_project(db, _MINE, "mine", _CALLER)
    _seed_project(db, _THEIRS, _SENTINEL, "someone-else")

    answer = await _answer("get_webhook_deliveries", {"webhook_id": {"$in": [f"{_MINE}-h", f"{_THEIRS}-h"]}}, db)

    assert _SENTINEL not in answer
    assert "mine" in answer


@pytest.mark.parametrize("tool_name", ["get_team_details", "get_team_projects", "get_team_risk_overview"])
@pytest.mark.asyncio
async def test_team_membership_is_checked_on_the_team_that_was_loaded(tool_name: str) -> None:
    db = _seeded()
    db.teams._docs["t-theirs"] = {"_id": "t-theirs", "name": _SENTINEL, "members": [{"user_id": "someone-else"}]}
    db.teams._docs["t-mine"] = {"_id": "t-mine", "name": "mine", "members": [{"user_id": _CALLER}]}
    db.projects._docs[_THEIRS]["team_ids"] = ["t-theirs"]

    assert _SENTINEL not in await _answer(tool_name, {"team_id": _OPERATOR}, db)
