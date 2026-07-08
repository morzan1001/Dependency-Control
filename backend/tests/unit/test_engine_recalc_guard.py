"""Unit tests for _project_has_active_waivers guard helper in engine.py."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.services.analysis.engine import _project_has_active_waivers


def _make_db(count_documents_return: int):
    waivers = SimpleNamespace(count_documents=AsyncMock(return_value=count_documents_return))
    return SimpleNamespace(waivers=waivers)


class TestProjectHasActiveWaivers:
    def test_returns_false_when_no_waivers(self):
        db = _make_db(0)
        result = asyncio.run(_project_has_active_waivers("project-123", db))  # type: ignore[arg-type]
        assert result is False
        db.waivers.count_documents.assert_awaited_once()

    def test_returns_true_when_waiver_exists(self):
        db = _make_db(1)
        result = asyncio.run(_project_has_active_waivers("project-123", db))  # type: ignore[arg-type]
        assert result is True
        db.waivers.count_documents.assert_awaited_once()

    def test_query_includes_project_id_and_global_waivers(self):
        """The query must match both project-scoped and global (project_id=None) waivers."""
        db = _make_db(0)
        asyncio.run(_project_has_active_waivers("proj-456", db))  # type: ignore[arg-type]

        call_args = db.waivers.count_documents.await_args
        query = call_args.args[0]

        assert "$and" in query

        project_id_clause = query["$and"][0]["$or"]
        assert {"project_id": "proj-456"} in project_id_clause
        assert {"project_id": None} in project_id_clause

    def test_uses_limit_1_for_efficiency(self):
        """count_documents must be called with limit=1 to short-circuit after the first match."""
        db = _make_db(0)
        asyncio.run(_project_has_active_waivers("proj-789", db))  # type: ignore[arg-type]

        call_kwargs = db.waivers.count_documents.await_args.kwargs
        assert call_kwargs.get("limit") == 1
