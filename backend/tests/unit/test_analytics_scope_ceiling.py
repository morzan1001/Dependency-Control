"""A scope analytics cannot materialise whole is refused, since no response could name the projects a subset drops."""

import pytest

from app.core.permissions import Permissions
from app.services.analytics import scopes
from app.services.analytics.scopes import ScopeResolver, ScopeTooLargeError

_CEILING = 4
_PAST_THE_CEILING = _CEILING + 1
_TEAM = "t1"
_USER = "u1"


@pytest.fixture
def small_ceiling(monkeypatch):
    monkeypatch.setattr(scopes, "ANALYTICS_MAX_SCOPE_PROJECTS", _CEILING)


def _seed_projects(db, count: int, *, member: bool = False, team_id: str | None = None) -> None:
    for index in range(count):
        doc: dict = {"_id": f"p{index}", "name": f"project-{index}"}
        if member:
            doc["members"] = [{"user_id": _USER}]
        if team_id:
            doc["team_ids"] = [team_id]
        db.projects._docs[doc["_id"]] = doc


def _resolver(db, *, permissions: frozenset[str] = frozenset({Permissions.PROJECT_READ})) -> ScopeResolver:
    class _User:
        id = _USER

    user = _User()
    user.permissions = permissions  # type: ignore[attr-defined]
    return ScopeResolver(db, user)


@pytest.mark.asyncio
async def test_a_user_scope_at_the_ceiling_still_resolves(db, small_ceiling):
    _seed_projects(db, _CEILING, member=True)

    projects = await _resolver(db).list_user_projects()

    assert len(projects) == _CEILING


@pytest.mark.asyncio
async def test_a_user_scope_past_the_ceiling_is_refused(db, small_ceiling):
    _seed_projects(db, _PAST_THE_CEILING, member=True)

    with pytest.raises(ScopeTooLargeError, match=str(_CEILING)):
        await _resolver(db).list_user_projects()


@pytest.mark.asyncio
async def test_a_team_scope_past_the_ceiling_is_refused(db, small_ceiling):
    _seed_projects(db, _PAST_THE_CEILING, team_id=_TEAM)
    db.teams._docs[_TEAM] = {"_id": _TEAM, "name": _TEAM, "members": []}

    with pytest.raises(ScopeTooLargeError):
        await _resolver(db, permissions=frozenset({Permissions.PROJECT_READ_ALL})).resolve(scope="team", scope_id=_TEAM)


@pytest.mark.asyncio
async def test_a_super_user_scope_past_the_ceiling_is_refused(db, small_ceiling):
    """The super-user enumeration bounded the same concept at a different number and did not
    even log; it is the same refusal now."""
    _seed_projects(db, _PAST_THE_CEILING)

    with pytest.raises(ScopeTooLargeError):
        await _resolver(db, permissions=frozenset({Permissions.PROJECT_READ_ALL})).resolve(scope="user", scope_id=None)
