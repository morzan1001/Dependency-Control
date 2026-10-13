"""Redis sliding-window rate limiter for chat requests."""

import logging
import time

from fastapi import HTTPException, status

from app.core.cache import CacheService, cache_service
from app.core.metrics import chat_rate_limited_total

logger = logging.getLogger(__name__)

CHAT_PREFIX = "chat:rl:"


async def enforce_rate_limit(owner_id: str, *, per_minute: int, per_hour: int) -> None:
    """Raise 429 with Retry-After once the owner's window is spent; a Redis outage admits the request."""
    verdict = await ChatRateLimiter(cache_service).check_rate_limit(owner_id, per_minute=per_minute, per_hour=per_hour)
    if verdict is None:
        logger.warning("Redis unavailable for chat rate limiting, allowing request")
        return
    allowed, retry_after = verdict
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

    def __init__(self, cache: CacheService):
        self.cache = cache

    async def check_rate_limit(self, user_id: str, per_minute: int, per_hour: int) -> tuple[bool, int] | None:
        """Return (allowed, retry_after_seconds), or None while Redis is unreachable.

        The minute window is consumed before the hour window is checked, so an hour-limit
        denial still spends a minute slot — an acceptable asymmetry as the hour limit rarely triggers.
        """
        now = time.time()
        member = f"{user_id}:{now}"
        for window, seconds, limit in (("minute", 60, per_minute), ("hour", 3600, per_hour)):
            key = f"{CHAT_PREFIX}{user_id}:{window}"
            result = await self.cache.eval(self._WINDOW_LUA, key, str(now), str(seconds), str(limit), member)
            if result is None:
                return None
            if not int(result[0]):
                chat_rate_limited_total.inc()
                return False, int(result[1])
        return True, 0
