"""The chat's get_callgraph answers with each language's most recently uploaded graph and names its build."""

from datetime import datetime, timezone

import pytest

from app.models.callgraph import Callgraph, ModuleUsage
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.databases import DATABASES
from tests.helpers.permission_presets import PRESET_ADMIN

pytestmark = [pytest.mark.asyncio, pytest.mark.parametrize("database", DATABASES)]

_PROJECT = "p-callgraph"
_JANUARY = datetime(2026, 1, 5, tzinfo=timezone.utc)
_MARCH = datetime(2026, 3, 5, tzinfo=timezone.utc)
_SEPTEMBER = datetime(2026, 9, 5, tzinfo=timezone.utc)


def _stored(language: str, module: str, *, created_at: datetime, updated_at: datetime, **build) -> dict:
    """A callgraph document as the upload endpoint stores it."""
    doc = Callgraph(
        project_id=_PROJECT,
        language=language,
        tool="generic",
        module_usage={module: ModuleUsage(module=module, import_count=2)},
        analyzed_modules=[module],
        total_imports=2,
        created_at=created_at,
        **build,
    ).model_dump(by_alias=True)
    return {**doc, "updated_at": updated_at}


async def _seed(db, *callgraphs: dict) -> None:
    await db.projects.insert_one({"_id": _PROJECT, "name": "callgraph-project"})
    await db.callgraphs.insert_many(list(callgraphs))


async def _call(db, **args) -> dict:
    admin = User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))
    return await ChatToolRegistry().execute_tool("get_callgraph", {"project_id": _PROJECT, **args}, admin, db)


async def test_every_language_s_newest_graph_is_returned_with_its_branch(db, database):
    await _seed(
        db,
        _stored("typescript", "react", created_at=_MARCH, updated_at=_MARCH, scan_id="s-2", branch="feature/ui"),
        _stored("python", "requests", created_at=_JANUARY, updated_at=_JANUARY, scan_id="s-1", branch="main"),
        _stored("python", "httpx", created_at=_MARCH, updated_at=_MARCH, scan_id="s-2", branch="feature/ui"),
    )

    result = await _call(db)

    rows = [(g["language"], list(g["module_usage"]), g["branch"]) for g in result["callgraphs"]]
    assert rows == [("python", ["httpx"], "feature/ui"), ("typescript", ["react"], "feature/ui")]


async def test_a_reuploaded_project_level_graph_outranks_a_scan_graph_first_uploaded_later(db, database):
    await _seed(
        db,
        _stored("python", "requests", created_at=_MARCH, updated_at=_MARCH, scan_id="s-2", branch="main"),
        _stored("python", "httpx", created_at=_JANUARY, updated_at=_SEPTEMBER),
    )

    result = await _call(db)

    [graph] = result["callgraphs"]
    assert list(graph["module_usage"]) == ["httpx"]
    assert graph["updated_at"] == _SEPTEMBER.isoformat()


async def test_a_named_language_narrows_the_answer_to_that_language(db, database):
    await _seed(
        db,
        _stored("python", "requests", created_at=_JANUARY, updated_at=_JANUARY),
        _stored("typescript", "react", created_at=_JANUARY, updated_at=_JANUARY),
    )

    result = await _call(db, language="TS")

    assert [g["language"] for g in result["callgraphs"]] == ["typescript"]


async def test_a_language_without_callgraph_support_is_refused(db, database):
    await _seed(db, _stored("python", "requests", created_at=_JANUARY, updated_at=_JANUARY))

    result = await _call(db, language="cobol")

    assert "unsupported callgraph language" in result["error"]
