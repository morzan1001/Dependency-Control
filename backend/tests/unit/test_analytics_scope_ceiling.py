"""A project scope analytics cannot materialise whole is refused, not answered over a subset.

Every analytics answer at team or user scope is computed over a list of project ids, and no
analytics response carries a field naming the projects a truncated list dropped. The two
enumerations used to cap silently — one at 10 000 with a log nobody reads, one at 100 000 with
nothing at all — so a large estate got an answer that looked complete and was not.
"""

import pytest

from app.core.permissions import Permissions
from app.services.analytics import scopes
from app.services.analytics.scopes import ScopeResolver, ScopeTooLargeError, ensure_whole_scope

_CEILING = 4
_PAST_THE_CEILING = _CEILING + 1
_TEAM = "t1"
_USER = "u1"


@pytest.fixture
def small_ceiling(monkeypatch):
    monkeypatch.setattr(scopes, "ANALYTICS_MAX_QUERY_LIMIT", _CEILING)


def _seed_projects(db, count: int, *, member: bool = False, team_id: str | None = None) -> None:
    for index in range(count):
        doc: dict = {"_id": f"p{index}", "name": f"project-{index}"}
        if member:
            doc["members"] = [{"user_id": _USER}]
        if team_id:
            doc["team_id"] = team_id
        db.projects._docs[doc["_id"]] = doc


def _resolver(db, *, permissions: frozenset[str] = frozenset()) -> ScopeResolver:
    class _User:
        id = _USER

    user = _User()
    user.permissions = permissions  # type: ignore[attr-defined]
    return ScopeResolver(db, user)


def test_a_scope_at_the_ceiling_is_answered_whole(small_ceiling):
    assert len(ensure_whole_scope(list(range(_CEILING)))) == _CEILING


def test_a_scope_past_the_ceiling_is_refused_with_the_number(small_ceiling):
    with pytest.raises(ScopeTooLargeError, match=str(_CEILING)):
        ensure_whole_scope(list(range(_PAST_THE_CEILING)))


@pytest.mark.asyncio
async def test_a_user_scope_at_the_ceiling_still_resolves(db, small_ceiling):
    _seed_projects(db, _CEILING, member=True)

    ids = await _resolver(db)._list_user_project_ids()

    assert len(ids) == _CEILING


@pytest.mark.asyncio
async def test_a_user_scope_past_the_ceiling_is_refused(db, small_ceiling):
    _seed_projects(db, _PAST_THE_CEILING, member=True)

    with pytest.raises(ScopeTooLargeError):
        await _resolver(db)._list_user_project_ids()


@pytest.mark.asyncio
async def test_a_team_scope_past_the_ceiling_is_refused(db, small_ceiling):
    _seed_projects(db, _PAST_THE_CEILING, team_id=_TEAM)

    with pytest.raises(ScopeTooLargeError):
        await _resolver(db)._list_team_project_ids(_TEAM)


@pytest.mark.asyncio
async def test_a_super_user_scope_past_the_ceiling_is_refused(db, small_ceiling):
    """The super-user enumeration bounded the same concept at a different number and did not
    even log; it is the same refusal now."""
    _seed_projects(db, _PAST_THE_CEILING)

    with pytest.raises(ScopeTooLargeError):
        await _resolver(db, permissions=frozenset({Permissions.PROJECT_READ_ALL})).resolve(scope="user", scope_id=None)
