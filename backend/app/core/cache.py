"""
Distributed Cache Service using Redis

Provides a shared cache layer for all backend pods to reduce external API calls
and avoid rate limiting issues when running multiple replicas.

Key features:
- Automatic JSON serialization/deserialization
- TTL-based expiration
- Graceful fallback when Redis is unavailable
- Batch operations for efficiency
- Cache key prefixing for namespace isolation

When to use this cache vs. ``app.services.analytics.cache.TTLCache``
-------------------------------------------------------------------
* **This cache (cache_service)** — async, Redis-backed. Use for results
  of external API calls (OSV, deps.dev, NPM, OIDC key material, etc.)
  or any datum where cross-pod deduplication matters because the fetch
  itself has calendar-time cost or is subject to upstream rate limits.

* **TTLCache in app.services.analytics.cache** — sync, in-process. Use
  for memoizing MongoDB aggregation results that are cheap to recompute
  per-pod (crypto hotspots, trends, PQC plans, scan deltas) and where
  per-pod-per-TTL consistency is sufficient.

See ``app.services.analytics.cache`` module docstring for the full
distinction.
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional, TypeVar

import redis.asyncio as redis
from redis.asyncio.connection import ConnectionPool

from prometheus_client import Counter, Gauge, Histogram

from app.core.config import settings

logger = logging.getLogger(__name__)

T = TypeVar("T")

REDIS_CONNECTION_LOST_MSG = "Redis connection lost, disabling cache temporarily"
REDIS_OPERATION_TIMEOUT_SECONDS = 5.0

# Import metrics for cache monitoring
cache_hits_total: Optional[Counter] = None
cache_misses_total: Optional[Counter] = None
cache_operations_total: Optional[Counter] = None
cache_operation_duration_seconds: Optional[Histogram] = None
cache_keys_total: Optional[Gauge] = None
cache_connected_clients: Optional[Gauge] = None
cache_size_bytes: Optional[Gauge] = None

try:
    from app.core.metrics import (
        cache_connected_clients,
        cache_hits_total,
        cache_keys_total,
        cache_misses_total,
        cache_operation_duration_seconds,
        cache_operations_total,
        cache_size_bytes,
    )
except ImportError:
    pass


class CacheTTL:
    """Standard TTL values for different types of cached data."""

    # Lock TTL for distributed locking (prevents deadlock on pod crash)
    LOCK_DEFAULT = 30  # 30 seconds

    # Global catalogs that update daily
    KEV_CATALOG = 24 * 3600  # 24 hours
    POPULAR_PACKAGES = 24 * 3600  # 24 hours

    # Vulnerability data
    EPSS_SCORE = 24 * 3600  # 24 hours (EPSS updates daily)
    GHSA_DATA = 7 * 24 * 3600  # 7 days (GHSA rarely changes)
    OSV_VULNERABILITY = 6 * 3600  # 6 hours (more volatile)

    # Package metadata
    DEPS_DEV_METADATA = 12 * 3600  # 12 hours
    DEPS_DEV_SCORECARD = 24 * 3600  # 24 hours
    LATEST_VERSION = 12 * 3600  # 12 hours
    EOL_STATUS = 24 * 3600  # 24 hours

    # Package hashes (immutable)
    PACKAGE_HASH = 7 * 24 * 3600  # 7 days

    # Maintainer data
    MAINTAINER_INFO = 24 * 3600  # 24 hours

    # Malware check (can change, moderate TTL)
    MALWARE_CHECK = 6 * 3600  # 6 hours

    # Negative cache (when API returns no data)
    NEGATIVE_RESULT = 1 * 3600  # 1 hour

    # Update frequency analysis (changes only on new scan completion)
    UPDATE_FREQUENCY = 30 * 60  # 30 minutes


class CacheKeys:
    """Cache key builders for consistent key naming."""

    @staticmethod
    def kev_catalog() -> str:
        return "kev:catalog"

    @staticmethod
    def epss(cve_id: str) -> str:
        return f"epss:{cve_id}"

    @staticmethod
    def ghsa(ghsa_id: str) -> str:
        return f"ghsa:{ghsa_id}"

    @staticmethod
    def osv(purl: str) -> str:
        # Use hash for long PURLs
        purl_hash = hashlib.md5(purl.encode()).hexdigest()[:16]
        return f"osv:{purl_hash}"

    @staticmethod
    def deps_dev(system: str, package: str, version: str) -> str:
        return f"deps:{system}:{package}:{version}"

    @staticmethod
    def deps_dev_scorecard(project_id: str) -> str:
        return f"scorecard:{project_id}"

    @staticmethod
    def latest_version(system: str, package: str) -> str:
        return f"latest:{system}:{package}"

    @staticmethod
    def eol(product: str) -> str:
        return f"eol:{product}"

    @staticmethod
    def package_hash(system: str, package: str, version: str) -> str:
        return f"hash:{system}:{package}:{version}"

    @staticmethod
    def popular_packages(registry: str) -> str:
        return f"popular:{registry}"

    @staticmethod
    def maintainer(system: str, package: str) -> str:
        return f"maintainer:{system}:{package}"

    @staticmethod
    def malware(registry: str, package: str, version: str) -> str:
        return f"malware:{registry}:{package}:{version}"

    @staticmethod
    def update_frequency(project_id: str) -> str:
        return f"update_freq:{project_id}"

    @staticmethod
    def update_frequency_comparison(user_id: str, team_id: str = "all") -> str:
        return f"update_freq_cmp:{user_id}:{team_id}"


class CacheService:
    """
    Distributed cache service using Redis.

    Designed for horizontal scaling - all pods share the same cache,
    dramatically reducing duplicate API calls to external services.
    """

    RECONNECT_INTERVAL_SECONDS = 30

    def __init__(self) -> None:
        self._pool: Optional[ConnectionPool] = None
        self._client: Optional[redis.Redis] = None
        self._available: bool = True
        self._lock: asyncio.Lock = asyncio.Lock()
        self._unavailable_since: float = 0

    async def get_client(self) -> redis.Redis:
        """Get or create Redis client with connection pooling.

        Uses a lock to prevent race conditions when multiple coroutines
        try to initialize the client simultaneously.
        """
        if self._client is not None and self._pool is not None:
            return self._client

        async with self._lock:
            # Double-check after acquiring lock
            if self._client is not None and self._pool is not None:
                return self._client

            try:
                self._pool = ConnectionPool.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True,
                    max_connections=20,
                )
                self._client = redis.Redis(connection_pool=self._pool)
                # Test connection
                await self._client.ping()  # type: ignore[misc]
                self._available = True
                self._unavailable_since = 0
                logger.info("Redis cache connection established")
            except Exception as e:
                logger.warning(f"Redis connection failed: {e}. Cache will be disabled.")
                self._available = False
                self._unavailable_since = time.monotonic()
                raise
        return self._client

    def _should_retry_connection(self) -> bool:
        """Check if enough time has passed to retry connecting to Redis."""
        if self._available:
            return False
        if self._unavailable_since == 0:
            return True
        elapsed = time.monotonic() - self._unavailable_since
        return elapsed >= self.RECONNECT_INTERVAL_SECONDS

    def _mark_unavailable(self) -> None:
        """Mark Redis as unavailable and record the time for reconnect backoff."""
        self._available = False
        self._unavailable_since = time.monotonic()

    async def _try_reconnect(self) -> bool:
        """Attempt to reconnect to Redis. Returns True if successful."""
        try:
            # Reset client so get_client() creates a new connection
            self._client = None
            self._pool = None
            await self.get_client()
            logger.info("Redis cache reconnected successfully")
            return True
        except Exception:
            self._mark_unavailable()
            return False

    async def _ensure_available(self) -> bool:
        """Check availability and attempt reconnect if needed. Returns True if usable."""
        if self._available:
            return True
        if self._should_retry_connection():
            return await self._try_reconnect()
        return False

    async def close(self) -> None:
        """Close Redis connection pool."""
        if self._client:
            await self._client.aclose()
            self._client = None
        if self._pool:
            await self._pool.disconnect()
            self._pool = None

    def _make_key(self, key: str) -> str:
        """Create prefixed cache key."""
        return f"{settings.CACHE_PREFIX}{key}"

    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key (will be prefixed automatically)

        Returns:
            Cached value or None if not found/expired
        """
        if not await self._ensure_available():
            return None

        _start = time.time()
        try:
            client = await self.get_client()
            data = await asyncio.wait_for(
                client.get(self._make_key(key)),
                timeout=REDIS_OPERATION_TIMEOUT_SECONDS,
            )
            if data:
                if cache_hits_total:
                    cache_hits_total.inc()
                return json.loads(data)
            if cache_misses_total:
                cache_misses_total.inc()
            return None
        except (redis.ConnectionError, asyncio.TimeoutError):
            logger.warning(REDIS_CONNECTION_LOST_MSG)
            self._mark_unavailable()
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to decode cached value for {key}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Cache get error for {key}: {e}")
            return None
        finally:
            if cache_operations_total:
                cache_operations_total.labels(operation="get").inc()
            if cache_operation_duration_seconds:
                cache_operation_duration_seconds.labels(operation="get").observe(time.time() - _start)

    async def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> bool:
        """
        Set value in cache with TTL.

        Args:
            key: Cache key (will be prefixed automatically)
            value: Value to cache (must be JSON serializable)
            ttl_seconds: Time-to-live in seconds (default from settings)

        Returns:
            True if cached successfully, False otherwise
        """
        if not await self._ensure_available():
            return False

        if ttl_seconds is None:
            ttl_seconds = settings.CACHE_DEFAULT_TTL_HOURS * 3600

        _start = time.time()
        try:
            client = await self.get_client()
            serialized = json.dumps(value, default=str)
            await asyncio.wait_for(
                client.setex(self._make_key(key), ttl_seconds, serialized),
                timeout=REDIS_OPERATION_TIMEOUT_SECONDS,
            )
            return True
        except (redis.ConnectionError, asyncio.TimeoutError):
            logger.warning(REDIS_CONNECTION_LOST_MSG)
            self._mark_unavailable()
            return False
        except (TypeError, ValueError) as e:
            logger.warning(f"Failed to serialize value for {key}: {e}")
            return False
        except Exception as e:
            logger.warning(f"Cache set error for {key}: {e}")
            return False
        finally:
            if cache_operations_total:
                cache_operations_total.labels(operation="set").inc()
            if cache_operation_duration_seconds:
                cache_operation_duration_seconds.labels(operation="set").observe(time.time() - _start)

    async def delete(self, key: str) -> bool:
        """Delete a key from cache."""
        if not await self._ensure_available():
            return False

        _start = time.time()
        try:
            client = await self.get_client()
            await asyncio.wait_for(
                client.delete(self._make_key(key)),
                timeout=REDIS_OPERATION_TIMEOUT_SECONDS,
            )
            return True
        except (redis.ConnectionError, asyncio.TimeoutError):
            logger.warning(REDIS_CONNECTION_LOST_MSG)
            self._mark_unavailable()
            return False
        except Exception as e:
            logger.warning(f"Cache delete error for {key}: {e}")
            return False
        finally:
            if cache_operations_total:
                cache_operations_total.labels(operation="delete").inc()
            if cache_operation_duration_seconds:
                cache_operation_duration_seconds.labels(operation="delete").observe(time.time() - _start)

    async def mget(self, keys: List[str]) -> Dict[str, Any]:
        """
        Batch get multiple keys.

        Args:
            keys: List of cache keys

        Returns:
            Dict mapping keys to their values (None for missing keys)
        """
        if not keys:
            return {}
        if not await self._ensure_available():
            return dict.fromkeys(keys)

        _start = time.time()
        try:
            client = await self.get_client()
            prefixed_keys = [self._make_key(k) for k in keys]
            values = await asyncio.wait_for(
                client.mget(prefixed_keys),
                timeout=REDIS_OPERATION_TIMEOUT_SECONDS,
            )

            result = {}
            for key, value in zip(keys, values):
                if value:
                    try:
                        result[key] = json.loads(value)
                    except json.JSONDecodeError:
                        result[key] = None
                else:
                    result[key] = None
            return result
        except (redis.ConnectionError, asyncio.TimeoutError):
            self._mark_unavailable()
            return dict.fromkeys(keys)
        except Exception as e:
            logger.warning(f"Cache mget error: {e}")
            return dict.fromkeys(keys)
        finally:
            if cache_operations_total:
                cache_operations_total.labels(operation="mget").inc()
            if cache_operation_duration_seconds:
                cache_operation_duration_seconds.labels(operation="mget").observe(time.time() - _start)

    async def mset(self, mapping: Dict[str, Any], ttl_seconds: Optional[int] = None) -> bool:
        """
        Batch set multiple key-value pairs with TTL.

        Args:
            mapping: Dict of key-value pairs to cache
            ttl_seconds: TTL for all keys

        Returns:
            True if all cached successfully
        """
        if not mapping:
            return False
        if not await self._ensure_available():
            return False

        if ttl_seconds is None:
            ttl_seconds = settings.CACHE_DEFAULT_TTL_HOURS * 3600

        _start = time.time()
        try:
            client = await self.get_client()
            pipe = client.pipeline()

            for key, value in mapping.items():
                serialized = json.dumps(value, default=str)
                pipe.setex(self._make_key(key), ttl_seconds, serialized)

            await asyncio.wait_for(pipe.execute(), timeout=REDIS_OPERATION_TIMEOUT_SECONDS)
            return True
        except (redis.ConnectionError, asyncio.TimeoutError):
            self._mark_unavailable()
            return False
        except Exception as e:
            logger.warning(f"Cache mset error: {e}")
            return False
        finally:
            if cache_operations_total:
                cache_operations_total.labels(operation="mset").inc()
            if cache_operation_duration_seconds:
                cache_operation_duration_seconds.labels(operation="mset").observe(time.time() - _start)

    async def get_or_fetch(
        self,
        key: str,
        fetch_fn: Callable[[], Any],
        ttl_seconds: Optional[int] = None,
    ) -> Any:
        """
        Get from cache or fetch and cache if missing.

        This is the primary method for cache-through pattern:
        1. Check cache for existing value
        2. If not found, call fetch_fn to get fresh data
        3. Cache the result for future requests

        Args:
            key: Cache key
            fetch_fn: Async function to call if cache miss
            ttl_seconds: TTL for cached value

        Returns:
            Cached or freshly fetched value
        """
        # Try cache first
        cached = await self.get(key)
        if cached is not None:
            return cached

        # Cache miss - fetch fresh data
        try:
            data = await fetch_fn()
            if data is not None:
                await self.set(key, data, ttl_seconds)
            return data
        except Exception as e:
            logger.warning(f"Fetch function failed for {key}: {e}")
            raise

    async def get_or_fetch_with_lock(
        self,
        key: str,
        fetch_fn: Callable[[], Any],
        ttl_seconds: Optional[int] = None,
        lock_ttl_seconds: int = 30,
        max_wait_seconds: float = 5.0,
    ) -> Optional[Any]:
        """
        Get from cache or fetch with distributed lock to prevent cache stampede.

        In a multi-pod deployment, when cache expires, all pods would normally
        try to fetch the same data simultaneously. This method uses a Redis lock
        to ensure only one pod fetches while others wait for the result.

        Flow:
        1. Check cache - return if hit
        2. Try to acquire lock
        3. If lock acquired: fetch, cache, release lock
        4. If lock not acquired: wait and retry cache

        Args:
            key: Cache key
            fetch_fn: Async function to call if cache miss
            ttl_seconds: TTL for cached value
            lock_ttl_seconds: TTL for the lock (prevents deadlock if pod crashes)
            max_wait_seconds: Max time to wait for another pod's fetch

        Returns:
            Cached or freshly fetched value, or None if fetch fails
        """
        # Try cache first
        cached = await self.get(key)
        if cached is not None:
            return cached

        if not self._available:
            # Redis unavailable - just fetch without locking
            try:
                return await fetch_fn()
            except Exception as e:
                logger.warning(f"Fetch failed (no cache): {key}: {e}")
                return None

        lock_key = f"lock:{key}"
        try:
            client = await self.get_client()

            # Try to acquire distributed lock using SETNX
            lock_acquired = await client.set(
                self._make_key(lock_key),
                "1",
                nx=True,  # Only set if not exists
                ex=lock_ttl_seconds,  # Auto-expire to prevent deadlock
            )

            if lock_acquired:
                # This pod won the race - fetch the data
                try:
                    data = await fetch_fn()
                    if data is not None:
                        await self.set(key, data, ttl_seconds)
                    else:
                        # Cache negative result with short TTL
                        await self.set(key, {}, CacheTTL.NEGATIVE_RESULT)
                    return data
                finally:
                    # Always release lock
                    await client.delete(self._make_key(lock_key))
            else:
                # Another pod is fetching - wait and check cache
                wait_interval = 0.1  # 100ms
                waited = 0.0

                while waited < max_wait_seconds:
                    await asyncio.sleep(wait_interval)
                    waited += wait_interval

                    # Check if data is now in cache
                    cached = await self.get(key)
                    if cached is not None:
                        return cached

                    # Check if lock was released (fetch completed but cache empty)
                    lock_exists = await client.exists(self._make_key(lock_key))
                    if not lock_exists:
                        # Lock released but no data - return None (negative cache)
                        return await self.get(key)

                # Timeout - try fetching ourselves as fallback
                logger.warning(f"Lock wait timeout for {key}, fetching anyway")
                try:
                    data = await fetch_fn()
                    if data is not None:
                        await self.set(key, data, ttl_seconds)
                    return data
                except Exception as e:
                    logger.warning(f"Fallback fetch failed for {key}: {e}")
                    return None

        except redis.ConnectionError:
            self._available = False
            # Fallback to direct fetch
            try:
                return await fetch_fn()
            except Exception as e:
                logger.warning(f"Fetch failed (redis down): {key}: {e}")
                return None
        except Exception as e:
            logger.warning(f"get_or_fetch_with_lock error for {key}: {e}")
            # Fallback to direct fetch
            try:
                return await fetch_fn()
            except Exception:
                return None

    async def health_check(self) -> Dict[str, Any]:
        """
        Get cache health status and statistics.

        Returns:
            Dict with health info and Redis stats
        """
        try:
            client = await self.get_client()
            info = await client.info(section="memory")
            stats = await client.info(section="stats")

            # Update Prometheus metrics
            total_keys = await client.dbsize()
            connected_clients_count = stats.get("connected_clients", 0)

            if cache_keys_total:
                cache_keys_total.set(total_keys)
            if cache_connected_clients:
                cache_connected_clients.set(connected_clients_count)

            return {
                "status": "healthy",
                "available": self._available,
                "used_memory": info.get("used_memory_human", "unknown"),
                "used_memory_peak": info.get("used_memory_peak_human", "unknown"),
                "connected_clients": connected_clients_count,
                "total_keys": total_keys,
                "keyspace_hits": stats.get("keyspace_hits", 0),
                "keyspace_misses": stats.get("keyspace_misses", 0),
                "hit_rate": self._calculate_hit_rate(stats.get("keyspace_hits", 0), stats.get("keyspace_misses", 0)),
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "available": False,
                "error": str(e),
            }

    def _calculate_hit_rate(self, hits: int, misses: int) -> float:
        """Calculate cache hit rate as percentage."""
        total = hits + misses
        if total == 0:
            return 0.0
        return round((hits / total) * 100, 2)

    async def invalidate_pattern(self, pattern: str) -> int:
        """
        Delete all keys matching a pattern.

        Args:
            pattern: Redis pattern (e.g., "epss:*" to clear all EPSS cache)

        Returns:
            Number of keys deleted
        """
        if not self._available:
            return 0

        try:
            client = await self.get_client()
            full_pattern = self._make_key(pattern)

            # Use SCAN to avoid blocking on large keyspaces
            deleted = 0
            cursor = 0
            while True:
                cursor, keys = await client.scan(cursor, match=full_pattern, count=100)
                if keys:
                    await client.delete(*keys)
                    deleted += len(keys)
                if cursor == 0:
                    break

            logger.info(f"Invalidated {deleted} keys matching pattern: {pattern}")
            return deleted
        except Exception as e:
            logger.warning(f"Pattern invalidation error for {pattern}: {e}")
            return 0


# Global cache service instance
cache_service = CacheService()


async def update_cache_stats() -> None:
    """
    Update cache statistics Prometheus metrics.

    This function should be called periodically (e.g., in housekeeping loop)
    to keep cache metrics current for Prometheus scraping.
    """
    try:
        if not cache_service._available:
            return

        client = await cache_service.get_client()

        # Get various info sections
        stats = await client.info(section="stats")
        memory_info = await client.info(section="memory")
        clients_info = await client.info(section="clients")

        total_keys = await client.dbsize()

        # Extract metrics from info sections
        # connected_clients is in the clients section for DragonflyDB
        connected_clients_count = clients_info.get("connected_clients", stats.get("connected_clients", 0))
        # used_memory is in bytes
        used_memory = memory_info.get("used_memory", 0)

        if cache_keys_total:
            cache_keys_total.set(total_keys)
        if cache_connected_clients:
            cache_connected_clients.set(connected_clients_count)
        if cache_size_bytes:
            cache_size_bytes.set(used_memory)

        logger.debug(
            f"Updated cache stats: keys={total_keys}, clients={connected_clients_count}, memory={used_memory} bytes"
        )
    except Exception as e:
        logger.warning(f"Failed to update cache statistics metrics: {e}")
