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
"""

import asyncio
import json
import logging
from typing import Any, Callable, Dict, List, Optional, TypeVar

import redis.asyncio as redis
from redis.asyncio.connection import ConnectionPool

from app.core.config import settings

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CacheService:
    """
    Distributed cache service using Redis.
    
    Designed for horizontal scaling - all pods share the same cache,
    dramatically reducing duplicate API calls to external services.
    """

    def __init__(self):
        self._pool: Optional[ConnectionPool] = None
        self._client: Optional[redis.Redis] = None
        self._available: bool = True
        self._lock: asyncio.Lock = asyncio.Lock()

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
                await self._client.ping()
                self._available = True
                logger.info("Redis cache connection established")
            except Exception as e:
                logger.warning(f"Redis connection failed: {e}. Cache will be disabled.")
                self._available = False
                raise
        return self._client

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
        if not self._available:
            return None
            
        try:
            client = await self.get_client()
            data = await client.get(self._make_key(key))
            if data:
                return json.loads(data)
            return None
        except redis.ConnectionError:
            logger.warning("Redis connection lost, disabling cache temporarily")
            self._available = False
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to decode cached value for {key}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Cache get error for {key}: {e}")
            return None

    async def set(
        self, 
        key: str, 
        value: Any, 
        ttl_seconds: Optional[int] = None
    ) -> bool:
        """
        Set value in cache with TTL.
        
        Args:
            key: Cache key (will be prefixed automatically)
            value: Value to cache (must be JSON serializable)
            ttl_seconds: Time-to-live in seconds (default from settings)
            
        Returns:
            True if cached successfully, False otherwise
        """
        if not self._available:
            return False
            
        if ttl_seconds is None:
            ttl_seconds = settings.CACHE_DEFAULT_TTL_HOURS * 3600
            
        try:
            client = await self.get_client()
            serialized = json.dumps(value, default=str)
            await client.setex(
                self._make_key(key),
                ttl_seconds,
                serialized
            )
            return True
        except redis.ConnectionError:
            logger.warning("Redis connection lost, disabling cache temporarily")
            self._available = False
            return False
        except (TypeError, ValueError) as e:
            logger.warning(f"Failed to serialize value for {key}: {e}")
            return False
        except Exception as e:
            logger.warning(f"Cache set error for {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete a key from cache."""
        if not self._available:
            return False
            
        try:
            client = await self.get_client()
            await client.delete(self._make_key(key))
            return True
        except Exception as e:
            logger.warning(f"Cache delete error for {key}: {e}")
            return False

    async def mget(self, keys: List[str]) -> Dict[str, Any]:
        """
        Batch get multiple keys.
        
        Args:
            keys: List of cache keys
            
        Returns:
            Dict mapping keys to their values (None for missing keys)
        """
        if not self._available or not keys:
            return {k: None for k in keys}
            
        try:
            client = await self.get_client()
            prefixed_keys = [self._make_key(k) for k in keys]
            values = await client.mget(prefixed_keys)
            
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
        except redis.ConnectionError:
            self._available = False
            return {k: None for k in keys}
        except Exception as e:
            logger.warning(f"Cache mget error: {e}")
            return {k: None for k in keys}

    async def mset(
        self, 
        mapping: Dict[str, Any], 
        ttl_seconds: Optional[int] = None
    ) -> bool:
        """
        Batch set multiple key-value pairs with TTL.
        
        Args:
            mapping: Dict of key-value pairs to cache
            ttl_seconds: TTL for all keys
            
        Returns:
            True if all cached successfully
        """
        if not self._available or not mapping:
            return False
            
        if ttl_seconds is None:
            ttl_seconds = settings.CACHE_DEFAULT_TTL_HOURS * 3600
            
        try:
            client = await self.get_client()
            pipe = client.pipeline()
            
            for key, value in mapping.items():
                serialized = json.dumps(value, default=str)
                pipe.setex(self._make_key(key), ttl_seconds, serialized)
            
            await pipe.execute()
            return True
        except Exception as e:
            logger.warning(f"Cache mset error: {e}")
            return False

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
            
            return {
                "status": "healthy",
                "available": self._available,
                "used_memory": info.get("used_memory_human", "unknown"),
                "used_memory_peak": info.get("used_memory_peak_human", "unknown"),
                "connected_clients": stats.get("connected_clients", 0),
                "total_keys": await client.dbsize(),
                "keyspace_hits": stats.get("keyspace_hits", 0),
                "keyspace_misses": stats.get("keyspace_misses", 0),
                "hit_rate": self._calculate_hit_rate(
                    stats.get("keyspace_hits", 0),
                    stats.get("keyspace_misses", 0)
                ),
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


# Cache TTL constants (in seconds) for different data types
class CacheTTL:
    """Standard TTL values for different types of cached data."""
    
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
        import hashlib
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
