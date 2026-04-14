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
    def __init__(self, redis_client: redis.Redis, prefix: str = "dc:chat:rl:"):
        self.redis = redis_client
        self.prefix = prefix

    async def check_rate_limit(
        self, user_id: str, per_minute: int, per_hour: int
    ) -> tuple[bool, int]:
        """
        Check if user is within rate limits.

        Returns:
            (allowed, retry_after_seconds)
        """
        now = time.time()

        # Check minute window
        minute_key = f"{self.prefix}{user_id}:minute"
        minute_allowed, minute_retry = await self._check_window(
            minute_key, now, window_seconds=60, max_requests=per_minute
        )
        if not minute_allowed:
            chat_rate_limited_total.inc()
            return False, minute_retry

        # Check hour window
        hour_key = f"{self.prefix}{user_id}:hour"
        hour_allowed, hour_retry = await self._check_window(
            hour_key, now, window_seconds=3600, max_requests=per_hour
        )
        if not hour_allowed:
            chat_rate_limited_total.inc()
            return False, hour_retry

        # Record this request in both windows
        pipe = self.redis.pipeline()
        pipe.zadd(minute_key, {str(now): now})
        pipe.expire(minute_key, 120)
        pipe.zadd(hour_key, {str(now): now})
        pipe.expire(hour_key, 7200)
        await pipe.execute()

        # Observability: remaining window capacity
        chat_rate_limit_remaining.labels(user_id=user_id, window="minute").set(
            max(per_minute - await self.redis.zcard(minute_key), 0)
        )
        chat_rate_limit_remaining.labels(user_id=user_id, window="hour").set(
            max(per_hour - await self.redis.zcard(hour_key), 0)
        )

        return True, 0

    async def _check_window(
        self, key: str, now: float, window_seconds: int, max_requests: int
    ) -> tuple[bool, int]:
        """Check a single sliding window."""
        window_start = now - window_seconds

        # Remove expired entries and count remaining
        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zcard(key)
        pipe.zrange(key, 0, 0, withscores=True)
        results = await pipe.execute()

        count = results[1]
        if count >= max_requests:
            # Calculate retry-after from oldest entry in window
            oldest_entries = results[2]
            if oldest_entries:
                oldest_time = oldest_entries[0][1]
                retry_after = int(oldest_time + window_seconds - now) + 1
            else:
                retry_after = window_seconds
            return False, retry_after

        return True, 0
