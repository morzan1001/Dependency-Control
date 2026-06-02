"""Fixtures for integration tests.

These tests exercise endpoint behaviour end-to-end via ``httpx.AsyncClient``
against the real FastAPI app, but with the MongoDB and auth dependencies
replaced by lightweight in-process mocks so that no live database or API key
infrastructure is required.

The FakeDatabase implementation lives in ``tests/mocks/fake_mongo.py`` and is
shared with the unit-test conftest. Extend operator support there, not here.
"""

import pytest
import pytest_asyncio
from fastapi import Depends
from httpx import ASGITransport, AsyncClient

from app.models.project import Project
from tests.mocks.fake_mongo import FakeDatabase

_SET_ON_INSERT = "$setOnInsert"


def _make_project(project_id: str = "test-project-id", name: str = "test-project") -> Project:
    return Project(id=project_id, name=name)


@pytest.fixture
def _project():
    return _make_project()


@pytest_asyncio.fixture
async def db():
    """In-process fake database shared across a single test."""
    return FakeDatabase()


@pytest_asyncio.fixture
async def client(db, _project):
    """AsyncClient wired to the real FastAPI app with auth and DB overridden."""
    from app.api.deps import (
        get_current_active_user,
        get_current_user,
        get_database,
        get_project_for_ingest,
        oauth2_scheme,
    )
    from app.main import app
    from app.models.user import User

    async def _fake_project_for_ingest():
        return _project

    async def _fake_get_database():
        return db

    async def _fake_get_current_user(token: str = Depends(oauth2_scheme)) -> User:
        """Parse JWT token and return user. Used by member auth tests."""
        from fastapi import HTTPException
        from jose import jwt

        from app.core.config import settings

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username = payload.get("sub")
            permissions = payload.get("permissions", [])

            if not username:
                raise HTTPException(status_code=401, detail="Invalid token")

            return User(
                id=username,
                username=username,
                email=f"{username}@test.com",
                permissions=permissions,
                is_active=True,
            )
        except Exception as e:
            raise HTTPException(status_code=401, detail=str(e)) from e

    async def _fake_get_current_active_user(current_user: User = Depends(_fake_get_current_user)) -> User:
        if not current_user.is_active:
            from fastapi import HTTPException

            raise HTTPException(status_code=400, detail="Inactive user")
        return current_user

    app.dependency_overrides[get_project_for_ingest] = _fake_project_for_ingest
    app.dependency_overrides[get_database] = _fake_get_database
    app.dependency_overrides[get_current_user] = _fake_get_current_user
    app.dependency_overrides[get_current_active_user] = _fake_get_current_active_user

    # Pre-populate the project so tests can look it up
    project_doc = _project.model_dump(by_alias=True)
    await db.projects.update_one(
        {"_id": str(_project.id)},
        {_SET_ON_INSERT: project_doc},
        upsert=True,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.pop(get_project_for_ingest, None)
    app.dependency_overrides.pop(get_database, None)
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_current_active_user, None)


@pytest.fixture
def api_key_headers():
    """Dummy API key header value — auth is bypassed via dep override."""
    return {"X-API-Key": "test-project-id.dummy-secret"}


@pytest.fixture
def member_auth_headers(_project):
    """Create auth headers for a user who is a project member."""
    from jose import jwt

    from app.core.config import settings
    from app.core.permissions import Permissions
    from app.models.project import ProjectMember
    from app.models.user import User

    user = User(
        id="test-user-1",
        username="testuser",
        email="test@example.com",
        permissions=[Permissions.PROJECT_READ, Permissions.PROJECT_CREATE],
        is_active=True,
    )

    member = ProjectMember(user_id=str(user.id), role="viewer")
    if not _project.members:
        _project.members = []
    _project.members.append(member)

    payload = {
        "sub": user.username,
        "permissions": user.permissions,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def regular_user_no_access():
    """Create a user who is NOT a project member."""
    from tests.helpers.permission_presets import PRESET_USER

    from app.models.user import User

    return User(
        id="test-user-no-access",
        username="noaccess",
        email="noaccess@example.com",
        permissions=list(PRESET_USER),
        is_active=True,
    )


@pytest.fixture
def admin_auth_headers():
    """Create auth headers for a system admin (has system:manage permission)."""
    from jose import jwt

    from app.core.config import settings
    from tests.helpers.permission_presets import PRESET_ADMIN

    payload = {
        "sub": "admin-user",
        "permissions": list(PRESET_ADMIN),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def owner_auth_headers_proj(client, db):
    """Auth headers for a user who owns project 'p' (project-level admin role).

    The username doubles as the user id because _fake_get_current_user sets id=username.
    """
    from jose import jwt

    from app.core.config import settings
    from app.core.permissions import Permissions
    from app.models.project import Project, ProjectMember
    from tests.helpers.permission_presets import PRESET_USER

    username = "ownerp"
    permissions = list(PRESET_USER) + [Permissions.PROJECT_READ]

    project_p = Project(id="p", name="project-p")
    member = ProjectMember(user_id=username, role="admin")
    project_p.members = [member]

    project_doc = project_p.model_dump(by_alias=True)
    await db.projects.update_one(
        {"_id": "p"},
        {_SET_ON_INSERT: project_doc},
        upsert=True,
    )

    payload = {
        "sub": username,
        "permissions": permissions,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def owner_auth_headers_proj_p2(client, db):
    """Auth headers for a user who owns project 'p2' (project-level admin role)."""
    from jose import jwt

    from app.core.config import settings
    from app.core.permissions import Permissions
    from app.models.project import Project, ProjectMember
    from tests.helpers.permission_presets import PRESET_USER

    username = "ownerp2"
    permissions = list(PRESET_USER) + [Permissions.PROJECT_READ]

    project_p2 = Project(id="p2", name="project-p2")
    member = ProjectMember(user_id=username, role="admin")
    project_p2.members = [member]

    project_doc = project_p2.model_dump(by_alias=True)
    await db.projects.update_one(
        {"_id": "p2"},
        {_SET_ON_INSERT: project_doc},
        upsert=True,
    )

    payload = {
        "sub": username,
        "permissions": permissions,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"Authorization": f"Bearer {token}"}
