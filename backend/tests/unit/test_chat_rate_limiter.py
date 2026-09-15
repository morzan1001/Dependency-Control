"""Unit tests for ChatRateLimiter, exercising the real Lua script via fakeredis."""

import fakeredis.aioredis
import pytest
import pytest_asyncio

import app.services.chat.rate_limiter as rate_limiter_mod
from app.core.metrics import REGISTRY
from app.services.chat.rate_limiter import ChatRateLimiter

_REMAINING_METRIC = "dc_chat_rate_limit_remaining"
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


def _remaining(user_id: str, window: str) -> float | None:
    return REGISTRY.get_sample_value(_REMAINING_METRIC, {"user_id": user_id, "window": window})


@pytest_asyncio.fixture
async def redis_client():
    client = fakeredis.aioredis.FakeRedis()
    yield client
    await client.flushdb()
    await client.aclose()


@pytest_asyncio.fixture
async def limiter(redis_client):
    return ChatRateLimiter(redis_client, prefix="test:chat:rl:")


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
async def test_the_remaining_gauge_counts_down_both_windows(limiter):
    await limiter.check_rate_limit("gauge-user", per_minute=5, per_hour=20)
    assert _remaining("gauge-user", "minute") == 4
    assert _remaining("gauge-user", "hour") == 19

    await limiter.check_rate_limit("gauge-user", per_minute=5, per_hour=20)
    assert _remaining("gauge-user", "minute") == 3
    assert _remaining("gauge-user", "hour") == 18


@pytest.mark.asyncio
async def test_a_minute_gauge_of_zero_means_the_next_request_is_denied(limiter):
    for _ in range(3):
        allowed, _ = await limiter.check_rate_limit("exhaust-user", per_minute=3, per_hour=100)
        assert allowed is True

    assert _remaining("exhaust-user", "minute") == 0

    allowed, _ = await limiter.check_rate_limit("exhaust-user", per_minute=3, per_hour=100)
    assert allowed is False
