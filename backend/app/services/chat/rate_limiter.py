"""Redis sliding-window rate limiter for chat requests.

Precedence note: Callers should read rate-limit values from the admin-tunable
SystemSettings (MongoDB) at request time, not from the startup-time
settings.CHAT_RATE_LIMIT_PER_MINUTE / _PER_HOUR. The settings values are
startup defaults; SystemSettings values are the runtime source of truth.
"""

import time

import redis.asyncio as redis

from app.core.metrics import chat_rate_limit_remaining, chat_rate_limited_total


class ChatRateLimiter:
    # Atomic Lua script: removes expired entries, checks count, and conditionally
    # adds the new entry — all in a single Redis round-trip to avoid TOCTOU races
    # where two concurrent requests both observe count < max and both get admitted.
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

    def __init__(self, redis_client: redis.Redis, prefix: str = "dc:chat:rl:"):
        self.redis = redis_client
        self.prefix = prefix

    async def check_rate_limit(
        self, user_id: str, per_minute: int, per_hour: int
    ) -> tuple[bool, int]:
        """
        Check if user is within rate limits.

        Uses a Lua script evaluated atomically on Redis to avoid TOCTOU races.
        The minute window is checked-and-incremented first; if the hour window
        then denies, the minute slot was already consumed — this is an acceptable
        minor accounting asymmetry given the hour limit is the rarer trigger.

        Returns:
            (allowed, retry_after_seconds)
        """
        now = time.time()
        member = f"{user_id}:{now}"

        minute_key = f"{self.prefix}{user_id}:minute"
        result = await self.redis.eval(self._WINDOW_LUA, 1, minute_key, str(now), "60", str(per_minute), member)
        allowed, retry_or_remaining = int(result[0]), int(result[1])
        if not allowed:
            chat_rate_limited_total.inc()
            return False, retry_or_remaining
        # Update remaining metric
        chat_rate_limit_remaining.labels(user_id=user_id, window="minute").set(retry_or_remaining)

        hour_key = f"{self.prefix}{user_id}:hour"
        result = await self.redis.eval(self._WINDOW_LUA, 1, hour_key, str(now), "3600", str(per_hour), member)
        allowed, retry_or_remaining = int(result[0]), int(result[1])
        if not allowed:
            chat_rate_limited_total.inc()
            return False, retry_or_remaining
        chat_rate_limit_remaining.labels(user_id=user_id, window="hour").set(retry_or_remaining)

        return True, 0
