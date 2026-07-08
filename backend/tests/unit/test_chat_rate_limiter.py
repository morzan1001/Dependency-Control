"""Unit tests for ChatRateLimiter, exercising the real Lua script via fakeredis."""

import fakeredis.aioredis
import pytest
import pytest_asyncio

from app.services.chat.rate_limiter import ChatRateLimiter


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
