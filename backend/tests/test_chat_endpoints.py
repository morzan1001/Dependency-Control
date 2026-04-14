"""Integration tests for chat API endpoints."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock, MagicMock, patch

from app.main import app
from app.db.mongodb import get_database


@pytest_asyncio.fixture
async def client():
    # Patch startup-event side-effects so the test process doesn't block
    # trying to reach a real MongoDB or Redis instance.
    # Override get_database via FastAPI's dependency_overrides so that
    # route handlers receive a mock DB instead of raising RuntimeError.
    # The OAuth2PasswordBearer dependency still returns 401 for bearer-less
    # requests before any real DB interaction occurs.
    mock_db = MagicMock()

    def override_get_database():
        return mock_db

    app.dependency_overrides[get_database] = override_get_database

    with (
        patch("app.main.connect_to_mongo", new_callable=AsyncMock),
        patch("app.main.init_db", new_callable=AsyncMock),
        patch("app.main.worker_manager.start", new_callable=AsyncMock),
        patch("app.main.worker_manager.stop", new_callable=AsyncMock),
        patch("app.main.close_mongo_connection", new_callable=AsyncMock),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

    app.dependency_overrides.pop(get_database, None)


@pytest.mark.asyncio
async def test_create_conversation_requires_auth(client):
    response = await client.post("/api/v1/chat/conversations", json={})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_conversations_requires_auth(client):
    response = await client.get("/api/v1/chat/conversations")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_send_message_requires_auth(client):
    response = await client.post(
        "/api/v1/chat/conversations/fake-id/messages",
        json={"content": "hello"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_delete_conversation_requires_auth(client):
    response = await client.delete("/api/v1/chat/conversations/fake-id")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_conversation_requires_auth(client):
    response = await client.get("/api/v1/chat/conversations/fake-id")
    assert response.status_code == 401
