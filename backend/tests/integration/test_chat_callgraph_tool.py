"""The chat's get_callgraph answers with each language's most recently uploaded graph and names its build."""

from datetime import datetime, timezone

import pytest

from app.models.callgraph import Callgraph, ModuleUsage
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN

_DATABASES = [
    pytest.param("attrappe", id="attrappe"),
    pytest.param("real-mongo", marks=pytest.mark.live_mongo, id="real-mongo"),
]

pytestmark = [pytest.mark.asyncio, pytest.mark.parametrize("database", _DATABASES)]

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


def _graph(modules: int, details: int) -> dict:
    """A python graph whose module pkg-{i} is imported and called i times, each with `details` files and symbols."""
    usage = {
        f"pkg-{i}": ModuleUsage(
            module=f"pkg-{i}",
            import_count=i,
            call_count=i,
            import_locations=[f"src/module_{i}/file_{j}.py" for j in range(details)],
            used_symbols=[f"symbol_{j}" for j in range(details)],
        )
        for i in range(modules)
    }
    stored = Callgraph(
        project_id=_PROJECT,
        language="python",
        tool="generic",
        module_usage=usage,
        analyzed_modules=sorted(usage),
        created_at=_MARCH,
    ).model_dump(by_alias=True)
    return {**stored, "updated_at": _MARCH}


async def test_a_graph_within_the_answer_budget_keeps_every_module_s_files_and_symbols(db, database):
    stored = _graph(30, 1)
    await _seed(db, stored)

    [graph] = (await _call(db))["callgraphs"]

    assert len(graph["module_usage"]) == 30
    assert graph["module_usage"]["pkg-0"]["import_locations"] == ["src/module_0/file_0.py"]
    assert graph["module_usage"]["pkg-0"]["used_symbols"] == ["symbol_0"]
    assert graph["analyzed_modules"] == stored["analyzed_modules"]


async def test_a_graph_past_the_answer_budget_is_summarised_by_its_busiest_modules(db, database):
    await _seed(db, _graph(60, 5))

    [graph] = (await _call(db))["callgraphs"]

    assert graph["module_usage_total"] == 60
    assert list(graph["module_usage"])[:2] == ["pkg-59", "pkg-58"]
    assert graph["module_usage"]["pkg-59"] == {"import_count": 59, "call_count": 59}
