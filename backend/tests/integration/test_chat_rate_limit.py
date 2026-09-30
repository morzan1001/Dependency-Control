"""POST /chat/conversations/{id}/messages is rate limited per user before any conversation work."""

from typing import Any

import pytest

from app.core.config import settings
from app.core.metrics import REGISTRY
from app.core.permissions import Permissions
from app.services.chat import rate_limiter
from tests.helpers.auth import bearer_headers

_USER = "chat-user"
_MESSAGES = "/api/v1/chat/conversations/no-such-conversation/messages"
_RETRY_AFTER_SECONDS = 42
_CHAT_DENIALS = "dc_chat_rate_limited_total"


class _DenyingRedis:
    """Answers the sliding-window script with a refusal, recording the keys it is given."""

    def __init__(self, keys: list[str]) -> None:
        self._keys = keys

    async def eval(self, _script: str, _numkeys: int, key: str, *_args: Any) -> list[int]:
        self._keys.append(key)
        return [0, _RETRY_AFTER_SECONDS]


@pytest.mark.asyncio
async def test_a_chat_user_over_the_window_gets_429_with_retry_after(client, monkeypatch):
    monkeypatch.setattr(settings, "CHAT_ENABLED", True)
    keys: list[str] = []
    monkeypatch.setattr(rate_limiter, "_client", lambda: _DenyingRedis(keys))
    denials_before = REGISTRY.get_sample_value(_CHAT_DENIALS) or 0.0

    resp = await client.post(
        _MESSAGES, json={"content": "hi"}, headers=bearer_headers(_USER, [Permissions.CHAT_ACCESS])
    )

    assert resp.status_code == 429, resp.text
    assert resp.headers["Retry-After"] == str(_RETRY_AFTER_SECONDS)
    assert keys == [f"dc:chat:rl:{_USER}:minute"]
    assert REGISTRY.get_sample_value(_CHAT_DENIALS) == denials_before + 1
