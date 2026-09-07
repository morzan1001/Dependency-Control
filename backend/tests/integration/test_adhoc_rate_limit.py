"""The ad-hoc endpoint is rate limited per token owner, and a Redis outage does not block it."""

from typing import Any

import pytest
import redis.asyncio as redis

from app.core.metrics import REGISTRY
from app.repositories.adhoc_api_keys import AdhocApiKeyRepository

_ANALYZE = "/api/v1/analyze"
_RATE_LIMIT_PREFIX = "dc:adhoc:rl:"
_CHAT_PREFIX = "dc:chat:rl:"
_RETRY_AFTER_SECONDS = 42
_ALLOWED = 1
_DENIED = 0
# The minute window; the hour window is only reached once the minute one admits the request.
_WINDOWS_PER_REQUEST = 2
_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
_BODY = {"sboms": [_SBOM], "analyzers": [], "apply_global_waivers": False}
_OWNER = "adhoc-user"


async def _issue_key(db, name="ci"):
    doc, plaintext = await AdhocApiKeyRepository(db).create(_OWNER, name, 30)
    await db.users.update_one(
        {"_id": _OWNER},
        {
            "$set": {
                "username": _OWNER,
                "email": "adhoc@example.com",
                "permissions": ["analyze:adhoc"],
                "is_active": True,
                "hashed_password": "x",
            }
        },
        upsert=True,
    )
    return doc, plaintext


_CHAT_DENIALS = "dc_chat_rate_limited_total"
_ADHOC_DENIALS = "dc_adhoc_rate_limited_total"


def _denials(metric_name: str) -> float:
    return REGISTRY.get_sample_value(metric_name) or 0.0


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


class _DenyingLimiter:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.seen_key = None

    async def check_rate_limit(self, user_id, per_minute, per_hour):
        self.seen_key = user_id
        return False, _RETRY_AFTER_SECONDS


class _FakeRedisCtx:
    """A live client that answers the sliding-window script, recording the keys it is given."""

    def __init__(self, keys: list[str]) -> None:
        self._keys = keys

    async def __aenter__(self) -> "_FakeRedisCtx":
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def eval(self, _script: str, _numkeys: int, key: str, *_args: Any) -> list[int]:
        self._keys.append(key)
        return [_ALLOWED, 0]


class _DenyingRedisCtx:
    """Answers the sliding-window script with a refusal, so the real limiter runs its denial path."""

    async def __aenter__(self) -> "_DenyingRedisCtx":
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def eval(self, *_args: Any) -> list[int]:
        return [_DENIED, _RETRY_AFTER_SECONDS]


class _BrokenRedisCtx:
    def __init__(self, opened: list[str]) -> None:
        self._opened = opened

    async def __aenter__(self) -> "_BrokenRedisCtx":
        self._opened.append(_RATE_LIMIT_PREFIX)
        raise redis.RedisError("redis down")

    async def __aexit__(self, *_exc: Any) -> bool:
        return False


def _patch_from_url(monkeypatch, factory):
    """``analyze.redis`` is the ``redis.asyncio`` module itself, so this patch is process-wide
    for the duration of the test rather than a module-local alias."""
    monkeypatch.setattr(redis, "from_url", lambda *_a, **_k: factory())


@pytest.mark.asyncio
async def test_denied_request_is_429_with_retry_after(client, db, monkeypatch):
    doc, token = await _issue_key(db)
    limiter = _DenyingLimiter()
    monkeypatch.setattr("app.api.v1.endpoints.analyze.ChatRateLimiter", lambda *a, **k: limiter)
    _patch_from_url(monkeypatch, lambda: _FakeRedisCtx([]))

    resp = await client.post(_ANALYZE, json=_BODY, headers=_bearer(token))

    assert resp.status_code == 429, resp.text
    assert resp.headers["Retry-After"] == str(_RETRY_AFTER_SECONDS)
    assert limiter.seen_key == doc["user_id"]


@pytest.mark.asyncio
async def test_the_window_lives_in_its_own_namespace(client, db, monkeypatch):
    """Sharing the chat namespace would let a chat user spend an ad-hoc caller's budget."""
    doc, token = await _issue_key(db)
    keys: list[str] = []
    _patch_from_url(monkeypatch, lambda: _FakeRedisCtx(keys))

    resp = await client.post(_ANALYZE, json=_BODY, headers=_bearer(token))

    assert resp.status_code == 200, resp.text
    assert keys, "the request must reach the window, or nothing here is being tested"
    assert all(key.startswith(f"{_RATE_LIMIT_PREFIX}{doc['user_id']}:") for key in keys), keys
    assert not any(key.startswith(_CHAT_PREFIX) for key in keys)


@pytest.mark.asyncio
async def test_a_second_key_of_the_same_owner_spends_the_same_window(client, db, monkeypatch):
    """Minting is uncapped, so a window keyed on the token would be one budget per key."""
    first, first_token = await _issue_key(db)
    second, second_token = await _issue_key(db, name="ci-2")
    assert first["prefix"] != second["prefix"]
    keys: list[str] = []
    _patch_from_url(monkeypatch, lambda: _FakeRedisCtx(keys))

    for token in (first_token, second_token):
        assert (await client.post(_ANALYZE, json=_BODY, headers=_bearer(token))).status_code == 200

    assert len(set(keys)) == _WINDOWS_PER_REQUEST, keys


@pytest.mark.asyncio
async def test_an_adhoc_denial_leaves_the_chat_dashboard_counter_alone(client, db, monkeypatch):
    """A live Grafana panel sums dc_chat_rate_limited_total unfiltered."""
    _, token = await _issue_key(db)
    _patch_from_url(monkeypatch, lambda: _DenyingRedisCtx())
    chat_before = _denials(_CHAT_DENIALS)
    adhoc_before = _denials(_ADHOC_DENIALS)

    resp = await client.post(_ANALYZE, json=_BODY, headers=_bearer(token))

    assert resp.status_code == 429, resp.text
    assert _denials(_CHAT_DENIALS) == chat_before
    assert _denials(_ADHOC_DENIALS) == adhoc_before + 1


@pytest.mark.asyncio
async def test_the_window_is_checked_before_the_body_is_read(client, db, monkeypatch):
    """A flood of oversized bodies must be refused without being read into memory first."""
    _, token = await _issue_key(db)
    limiter = _DenyingLimiter()
    monkeypatch.setattr("app.api.v1.endpoints.analyze.ChatRateLimiter", lambda *a, **k: limiter)
    _patch_from_url(monkeypatch, lambda: _FakeRedisCtx([]))
    read_bodies: list[int] = []

    async def _record_read(request, limit):
        body = await request.body()
        read_bodies.append(len(body))
        return body

    monkeypatch.setattr("app.api.v1.endpoints.analyze.read_body_within_limit", _record_read)

    resp = await client.post(_ANALYZE, json=_BODY, headers=_bearer(token))

    assert resp.status_code == 429, resp.text
    assert read_bodies == []


@pytest.mark.asyncio
async def test_redis_outage_does_not_block_the_request(client, db, monkeypatch):
    _, token = await _issue_key(db)
    opened: list[str] = []
    _patch_from_url(monkeypatch, lambda: _BrokenRedisCtx(opened))

    resp = await client.post(_ANALYZE, json=_BODY, headers=_bearer(token))

    assert resp.status_code == 200, resp.text
    assert opened, "the outage path only proves anything if the limiter was actually reached"
