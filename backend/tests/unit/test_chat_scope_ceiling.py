"""Chat answers the estate-wide question analytics answers, so it refuses the same scope.

A chat tool that narrows the accessible-project list reads as an answer over the whole estate,
and the reader has no chart beside the reply to notice the projects that were dropped.
"""

import pytest

from app.models.user import User
from app.services.analytics import scopes
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN
from tests.mocks.fake_mongo import FakeDatabase

_CEILING = 3
_PAST_THE_CEILING = _CEILING + 1
_CALLER = "u-scope"
_ESTATE_TOOL = "search_findings"
_SEARCH_TERM = "openssl"


@pytest.fixture
def small_ceiling(monkeypatch):
    monkeypatch.setattr(scopes, "ANALYTICS_MAX_QUERY_LIMIT", _CEILING)


def _seed_projects(db: FakeDatabase, count: int) -> None:
    for index in range(count):
        db.projects._docs[f"p{index}"] = {
            "_id": f"p{index}",
            "name": f"project-{index}",
            "members": [{"user_id": _CALLER, "role": "owner"}],
        }


def _caller() -> User:
    return User(
        _id=_CALLER,
        username="scope-caller",
        email="scope@example.com",
        permissions=list(PRESET_ADMIN),
    )


@pytest.mark.asyncio
async def test_a_scope_at_the_ceiling_is_answered(small_ceiling):
    db = FakeDatabase()
    _seed_projects(db, _CEILING)

    result = await ChatToolRegistry().execute_tool(_ESTATE_TOOL, {"query": _SEARCH_TERM}, _caller(), db)

    assert "error" not in result


@pytest.mark.asyncio
async def test_a_scope_past_the_ceiling_is_refused_rather_than_narrowed(small_ceiling):
    db = FakeDatabase()
    _seed_projects(db, _PAST_THE_CEILING)

    result = await ChatToolRegistry().execute_tool(_ESTATE_TOOL, {"query": _SEARCH_TERM}, _caller(), db)

    assert str(_CEILING) in result["error"]


@pytest.mark.asyncio
async def test_the_refusal_names_the_ceiling_instead_of_a_generic_failure(small_ceiling):
    db = FakeDatabase()
    _seed_projects(db, _PAST_THE_CEILING)

    result = await ChatToolRegistry().execute_tool(_ESTATE_TOOL, {"query": _SEARCH_TERM}, _caller(), db)

    assert "Tool execution failed" not in result["error"]
