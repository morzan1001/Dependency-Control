import pytest

from app.core.config import settings
from app.core.permissions import Permissions
from tests.helpers.auth import bearer_headers

_NO_PERMISSIONS = ("nobody", [])
_CHAT_ACCESS_ONLY = ("chatter", [Permissions.CHAT_ACCESS])

_ARCHIVE_ROUTES = [
    ("GET", "/api/v1/projects/p/archives", Permissions.ARCHIVE_READ),
    ("GET", "/api/v1/projects/p/archives/branches", Permissions.ARCHIVE_READ),
    ("POST", "/api/v1/projects/p/archives/s/restore", Permissions.ARCHIVE_RESTORE),
    ("GET", "/api/v1/projects/p/archives/s/download", Permissions.ARCHIVE_DOWNLOAD),
    ("POST", "/api/v1/projects/p/scans/s/pin", Permissions.ARCHIVE_RESTORE),
    ("POST", "/api/v1/projects/p/scans/s/unpin", Permissions.ARCHIVE_RESTORE),
    ("GET", "/api/v1/archives/all", Permissions.ARCHIVE_READ_ALL),
]

_CHAT_ROUTES = [
    ("POST", "/api/v1/chat/conversations", _NO_PERMISSIONS, Permissions.CHAT_ACCESS),
    ("GET", "/api/v1/chat/conversations", _NO_PERMISSIONS, Permissions.CHAT_ACCESS),
    ("GET", "/api/v1/chat/conversations", _CHAT_ACCESS_ONLY, Permissions.CHAT_HISTORY_READ),
    ("GET", "/api/v1/chat/conversations/c", _CHAT_ACCESS_ONLY, Permissions.CHAT_HISTORY_READ),
    ("DELETE", "/api/v1/chat/conversations/c", _NO_PERMISSIONS, Permissions.CHAT_HISTORY_DELETE),
    ("POST", "/api/v1/chat/conversations/c/messages", _NO_PERMISSIONS, Permissions.CHAT_ACCESS),
]


def _refusal(permission: str) -> dict[str, str]:
    return {"detail": f"Not enough permissions. Required one of: {permission}"}


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path", "permission"), _ARCHIVE_ROUTES)
async def test_an_archive_route_names_the_permission_it_refuses_on(client, method, path, permission):
    resp = await client.request(method, path, headers=bearer_headers(*_NO_PERMISSIONS))

    assert resp.status_code == 403
    assert resp.json() == _refusal(permission)


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path", "caller", "permission"), _CHAT_ROUTES)
async def test_a_chat_route_names_the_permission_it_refuses_on(client, monkeypatch, method, path, caller, permission):
    monkeypatch.setattr(settings, "CHAT_ENABLED", True)
    body = {"content": "hi"} if path.endswith("/messages") else {"title": "t"} if method == "POST" else None

    resp = await client.request(method, path, headers=bearer_headers(*caller), json=body)

    assert resp.status_code == 403
    assert resp.json() == _refusal(permission)


@pytest.mark.asyncio
async def test_the_cache_statistics_need_system_management(client, monkeypatch):
    from app.api import health

    async def _stats():
        return {"status": "healthy", "total_keys": 7}

    monkeypatch.setattr(health.cache_service, "health_check", _stats)

    anonymous = await client.get("/health/cache")
    refused = await client.get("/health/cache", headers=bearer_headers(*_NO_PERMISSIONS))
    granted = await client.get("/health/cache", headers=bearer_headers("operator", [Permissions.SYSTEM_MANAGE]))

    assert (anonymous.status_code, refused.json()) == (401, _refusal(Permissions.SYSTEM_MANAGE))
    assert (granted.status_code, granted.json()) == (200, {"status": "healthy", "total_keys": 7})


def _chat_routes() -> list[tuple[str, str]]:
    from app.api.v1.endpoints import chat

    return [
        (method, f"/api/v1/chat{route.path.replace('{conversation_id}', 'c')}")
        for route in chat.router.routes
        for method in route.methods
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path"), _chat_routes())
async def test_every_chat_route_is_closed_while_the_chat_is_disabled(client, monkeypatch, method, path):
    monkeypatch.setattr(settings, "CHAT_ENABLED", False)
    body = {"content": "hi", "title": "t"} if method == "POST" else None

    resp = await client.request(method, path, headers=bearer_headers(*_NO_PERMISSIONS), json=body)

    assert (resp.status_code, resp.json()) == (403, {"detail": "Chat feature is currently disabled"})
