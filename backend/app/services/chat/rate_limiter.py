"""Redis sliding-window rate limiter for chat and ad-hoc analysis requests."""

import functools
import logging
import time

import redis.asyncio as redis
from fastapi import HTTPException, status
from prometheus_client import Counter

from app.core.config import settings
from app.core.metrics import adhoc_rate_limited_total, chat_rate_limited_total

logger = logging.getLogger(__name__)

SURFACE_CHAT = "chat"
SURFACE_ADHOC = "adhoc"
CHAT_PREFIX = "dc:chat:rl:"

# One counter per surface: the two are read by different dashboards, so a denial on one
# must not move the other's series.
_SURFACE_METRICS: dict[str, Counter] = {
    SURFACE_CHAT: chat_rate_limited_total,
    SURFACE_ADHOC: adhoc_rate_limited_total,
}


@functools.cache
def _client() -> redis.Redis:
    return redis.from_url(settings.REDIS_URL)


async def enforce_rate_limit(owner_id: str, *, prefix: str, surface: str, per_minute: int, per_hour: int) -> None:
    """Raise 429 with Retry-After once the owner's window is spent; a Redis outage admits the request."""
    limiter = ChatRateLimiter(_client(), prefix=prefix, surface=surface)
    try:
        allowed, retry_after = await limiter.check_rate_limit(owner_id, per_minute=per_minute, per_hour=per_hour)
    except redis.RedisError:
        logger.warning("Redis unavailable for %s rate limiting, allowing request", surface)
        return
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )


class ChatRateLimiter:
    # Single-round-trip Lua script to avoid TOCTOU races admitting two concurrent requests.
    _WINDOW_LUA = """
-- KEYS[1] = window sorted set key
-- ARGV[1] = now (unix seconds, float)
-- ARGV[2] = window seconds
-- ARGV[3] = max requests
-- ARGV[4] = member to add (str(now))
-- Returns: {allowed (0|1), retry_after_seconds_or_remaining}
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_reqs = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window)
local count = redis.call('ZCARD', KEYS[1])

if count >= max_reqs then
    -- Compute retry-after from oldest remaining entry
    local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
    local retry = window
    if #oldest >= 2 then
        local oldest_score = tonumber(oldest[2])
        retry = math.floor(oldest_score + window - now) + 1
        if retry < 1 then retry = 1 end
    end
    return {0, retry}
end

redis.call('ZADD', KEYS[1], now, member)
redis.call('EXPIRE', KEYS[1], math.floor(window * 2))
return {1, max_reqs - count - 1}
"""

    def __init__(self, redis_client: redis.Redis, prefix: str = CHAT_PREFIX, surface: str = SURFACE_CHAT):
        self.redis = redis_client
        self.prefix = prefix
        self._denied = _SURFACE_METRICS[surface]

    async def check_rate_limit(self, user_id: str, per_minute: int, per_hour: int) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds).

        The minute window is consumed before the hour window is checked, so an hour-limit
        denial still spends a minute slot — an acceptable asymmetry as the hour limit rarely triggers.
        """
        now = time.time()
        member = f"{user_id}:{now}"

        minute_key = f"{self.prefix}{user_id}:minute"
        # eval() stubs type the result as Awaitable | str; at runtime it is the script result.
        result = await self.redis.eval(self._WINDOW_LUA, 1, minute_key, str(now), "60", str(per_minute), member)  # type: ignore[misc]
        allowed, retry_or_remaining = int(result[0]), int(result[1])
        if not allowed:
            self._denied.inc()
            return False, retry_or_remaining

        hour_key = f"{self.prefix}{user_id}:hour"
        result = await self.redis.eval(self._WINDOW_LUA, 1, hour_key, str(now), "3600", str(per_hour), member)  # type: ignore[misc]
        allowed, retry_or_remaining = int(result[0]), int(result[1])
        if not allowed:
            self._denied.inc()
            return False, retry_or_remaining

        return True, 0
