"""Redis sliding-window rate limiter for chat messages and MCP tool calls."""

import logging
import time

from fastapi import HTTPException, status

from app.core.cache import cache_service
from app.core.metrics import chat_rate_limited_total

logger = logging.getLogger(__name__)

CHAT_PREFIX = "chat:rl:"

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


async def rate_limit_retry_after(owner_id: str, *, per_minute: int, per_hour: int) -> int:
    """Seconds until the owner's windows admit a request, 0 when they admit this one; a Redis outage admits it."""
    now = time.time()
    member = f"{owner_id}:{now}"
    # An hour-window denial still spends a minute slot, acceptable as the hour limit rarely triggers.
    for window, seconds, limit in (("minute", 60, per_minute), ("hour", 3600, per_hour)):
        key = f"{CHAT_PREFIX}{owner_id}:{window}"
        result = await cache_service.eval(_WINDOW_LUA, key, str(now), str(seconds), str(limit), member)
        if result is None:
            logger.warning("Redis unavailable for rate limiting, allowing request")
            return 0
        if not int(result[0]):
            return int(result[1])
    return 0


async def enforce_rate_limit(owner_id: str, *, per_minute: int, per_hour: int) -> None:
    """Raise 429 with Retry-After once the owner's chat window is spent."""
    if retry_after := await rate_limit_retry_after(owner_id, per_minute=per_minute, per_hour=per_hour):
        chat_rate_limited_total.inc()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )
