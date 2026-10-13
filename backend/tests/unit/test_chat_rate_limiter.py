"""Unit tests for ChatRateLimiter, exercising the real Lua script via fakeredis."""

import asyncio
import logging
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis
from fastapi import HTTPException

import app.core.cache as cache_mod
import app.services.chat.rate_limiter as rate_limiter_mod
from app.core.metrics import REGISTRY
from app.services.chat.rate_limiter import ChatRateLimiter, enforce_rate_limit

_START = 1_000_000.0


class _FrozenClock:
    """Stands in for the `time` module inside the limiter so a window can be aged deliberately."""

    def __init__(self, now: float) -> None:
        self._now = now

    def time(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


@pytest.fixture
def clock(monkeypatch):
    frozen = _FrozenClock(_START)
    monkeypatch.setattr(rate_limiter_mod, "time", frozen)
    return frozen


@pytest.fixture
def limiter(fake_cache):
    return ChatRateLimiter(fake_cache)


@pytest.mark.asyncio
async def test_allows_first_request(limiter):
    allowed, retry_after = await limiter.check_rate_limit("user-1", per_minute=5, per_hour=20)
    assert allowed is True
    assert retry_after == 0


@pytest.mark.asyncio
async def test_blocks_after_minute_limit(limiter):
    for _ in range(5):
        allowed, _ = await limiter.check_rate_limit("user-1", per_minute=5, per_hour=100)
        assert allowed is True

    allowed, retry_after = await limiter.check_rate_limit("user-1", per_minute=5, per_hour=100)
    assert allowed is False
    assert retry_after > 0


@pytest.mark.asyncio
async def test_different_users_independent(limiter):
    for _ in range(5):
        await limiter.check_rate_limit("user-1", per_minute=5, per_hour=100)

    allowed, _ = await limiter.check_rate_limit("user-2", per_minute=5, per_hour=100)
    assert allowed is True


@pytest.mark.asyncio
async def test_a_spent_minute_slot_is_held_for_a_full_minute(limiter, clock):
    await limiter.check_rate_limit("clock-user", per_minute=2, per_hour=1000)
    clock.advance(1)
    await limiter.check_rate_limit("clock-user", per_minute=2, per_hour=1000)

    clock.advance(44)
    allowed, retry_after = await limiter.check_rate_limit("clock-user", per_minute=2, per_hour=1000)
    assert allowed is False
    assert retry_after > 0

    clock.advance(17)
    allowed, _ = await limiter.check_rate_limit("clock-user", per_minute=2, per_hour=1000)
    assert allowed is True


@pytest.mark.asyncio
async def test_a_spent_hour_slot_is_held_for_a_full_hour(limiter, clock):
    await limiter.check_rate_limit("hour-user", per_minute=1000, per_hour=2)
    clock.advance(1)
    await limiter.check_rate_limit("hour-user", per_minute=1000, per_hour=2)

    clock.advance(1199)
    allowed, retry_after = await limiter.check_rate_limit("hour-user", per_minute=1000, per_hour=2)
    assert allowed is False
    assert retry_after > 0

    clock.advance(2401)
    allowed, _ = await limiter.check_rate_limit("hour-user", per_minute=1000, per_hour=2)
    assert allowed is True


@pytest.mark.asyncio
async def test_a_check_adds_no_metric_series_per_user(limiter):
    """Nothing ever removes a per-user child series, so every caller would stay in the registry."""
    await limiter.check_rate_limit("series-user", per_minute=5, per_hour=20)

    labelled = [s for metric in REGISTRY.collect() for s in metric.samples if "series-user" in s.labels.values()]
    assert labelled == []


@pytest.fixture
def shared_cache(fake_cache, monkeypatch):
    monkeypatch.setattr(rate_limiter_mod, "cache_service", fake_cache)
    return fake_cache


async def _enforce(owner_id: str = "owner-1", per_minute: int = 5) -> None:
    await enforce_rate_limit(owner_id, per_minute=per_minute, per_hour=100)


@pytest.mark.asyncio
async def test_the_windows_live_in_the_shared_cache(shared_cache):
    """A client of its own would bypass the cache's operation timeout and its pause after an outage."""
    await _enforce()

    assert await shared_cache._client.exists(shared_cache._make_key("chat:rl:owner-1:minute"))


@pytest.mark.asyncio
async def test_a_request_over_the_window_is_refused_with_retry_after(shared_cache):
    await _enforce(per_minute=1)

    with pytest.raises(HTTPException) as refused:
        await _enforce(per_minute=1)

    assert refused.value.status_code == 429
    assert int(refused.value.headers["Retry-After"]) > 0


class _UnreachableRedis:
    async def eval(self, *_args):
        raise redis.ConnectionError("redis down")


class _HungRedis:
    async def eval(self, *_args):
        await asyncio.Event().wait()


@pytest.mark.asyncio
@pytest.mark.parametrize("lost", [_UnreachableRedis, _HungRedis], ids=["unreachable", "hung"])
async def test_a_lost_redis_lets_the_request_through_and_pauses_the_cache(shared_cache, monkeypatch, caplog, lost):
    monkeypatch.setattr(shared_cache, "get_client", AsyncMock(return_value=lost()))
    monkeypatch.setattr(cache_mod, "REDIS_OPERATION_TIMEOUT_SECONDS", 0.05)

    with caplog.at_level(logging.WARNING, logger=rate_limiter_mod.__name__):
        await asyncio.wait_for(_enforce(), timeout=2)

    assert "allowing request" in caplog.text
    # Paused, the next request is admitted without waiting on Redis again.
    assert shared_cache._available is False
