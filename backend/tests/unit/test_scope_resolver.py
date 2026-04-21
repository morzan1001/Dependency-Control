from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.analytics.scopes import (
    ScopeResolutionError,
    ScopeResolver,
)


@pytest.mark.asyncio
async def test_project_scope_allowed_member():
    db = MagicMock()
    user = MagicMock(id="u1", permissions=frozenset())
    resolver = ScopeResolver(db, user)
    resolver._check_project_member = AsyncMock(return_value=True)
    result = await resolver.resolve(scope="project", scope_id="p1")
    assert result.project_ids == ["p1"]
    assert result.scope == "project"


@pytest.mark.asyncio
async def test_project_scope_denied_nonmember():
    db = MagicMock()
    user = MagicMock(id="u1", permissions=frozenset())
    resolver = ScopeResolver(db, user)
    resolver._check_project_member = AsyncMock(return_value=False)
    with pytest.raises(ScopeResolutionError):
        await resolver.resolve(scope="project", scope_id="p1")


@pytest.mark.asyncio
async def test_team_scope_expands_to_projects():
    db = MagicMock()
    user = MagicMock(id="u1", permissions=frozenset())
    resolver = ScopeResolver(db, user)
    resolver._check_team_member = AsyncMock(return_value=True)
    resolver._list_team_project_ids = AsyncMock(return_value=["p1", "p2"])
    result = await resolver.resolve(scope="team", scope_id="t1")
    assert result.project_ids == ["p1", "p2"]


@pytest.mark.asyncio
async def test_global_scope_requires_permission():
    db = MagicMock()
    user_admin = MagicMock(id="u1", permissions=frozenset({"analytics:global"}))
    user_regular = MagicMock(id="u2", permissions=frozenset())
    resolver_a = ScopeResolver(db, user_admin)
    result = await resolver_a.resolve(scope="global", scope_id=None)
    assert result.project_ids is None
    with pytest.raises(ScopeResolutionError):
        await ScopeResolver(db, user_regular).resolve(scope="global", scope_id=None)


@pytest.mark.asyncio
async def test_unknown_scope_errors():
    resolver = ScopeResolver(MagicMock(), MagicMock(id="u", permissions=frozenset()))
    with pytest.raises(ScopeResolutionError):
        await resolver.resolve(scope="nonsense", scope_id=None)
