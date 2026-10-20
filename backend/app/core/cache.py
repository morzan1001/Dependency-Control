"""Redis cache shared across pods; in-process memoization of Mongo aggregations belongs in analytics.cache.TTLCache."""

import asyncio
import hashlib
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable, Iterator
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from itertools import batched
from types import TracebackType
from typing import Any, TypeVar, cast

import redis.asyncio as redis
from redis.asyncio.connection import BlockingConnectionPool

from app.core.config import settings
from app.core.http_utils import gather_bounded
from app.core.metrics import (
    cache_connected_clients,
    cache_hits_total,
    cache_keys_total,
    cache_misses_total,
    cache_operation_duration_seconds,
    cache_size_bytes,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")

REDIS_CONNECTION_LOST_MSG = "Redis connection lost, disabling cache temporarily"
REDIS_OPERATION_TIMEOUT_SECONDS = 5.0
# Each round trip has its own timeout, so a large batch cannot outlast one and pause the cache.
_KEYS_PER_ROUND_TRIP = 500
_LOCK_POLL_INTERVAL_SECONDS = 0.1
# The wait outlasts a 30 s upstream fetch and the lock the wait, so peers wait for the holder instead of re-fetching.
STAMPEDE_LOCK_TTL_SECONDS = 60
STAMPEDE_MAX_WAIT_SECONDS = 35.0

# Compare-and-delete, so a slow fetch cannot delete a lock another pod has re-acquired since.
_UNLOCK_LUA = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"


_writes_suppressed: ContextVar[bool] = ContextVar("cache_writes_suppressed", default=False)


@contextmanager
def suppress_cache_writes() -> Iterator[None]:
    """Context-local, as a flag on the process-wide singleton would also silence concurrent scans that populate it."""
    token = _writes_suppressed.set(True)
    try:
        yield
    finally:
        _writes_suppressed.reset(token)


class _FetchFailed(Exception):
    """Carries a fetch_fn failure past the handlers that retry on cache-infrastructure errors."""

    def __init__(self, cause: BaseException):
        super().__init__(cause)
        self.cause = cause


class CacheTTL:
    # Global catalogs that update daily
    KEV_CATALOG = 24 * 3600
    POPULAR_PACKAGES = 24 * 3600

    EPSS_SCORE = 24 * 3600  # EPSS updates daily
    GHSA_DATA = 7 * 24 * 3600  # GHSA rarely changes
    OSV_VULNERABILITY = 6 * 3600  # more volatile
    OSV_VULN_RECORD = 7 * 24 * 3600  # keyed on the record's modified stamp

    DEPS_DEV_METADATA = 12 * 3600
    LATEST_VERSION = 12 * 3600
    EOL_STATUS = 24 * 3600

    # Package hashes are immutable.
    PACKAGE_HASH = 7 * 24 * 3600

    MAINTAINER_INFO = 24 * 3600

    # A malware verdict can change.
    MALWARE_CHECK = 6 * 3600

    NEGATIVE_RESULT = 1 * 3600

    # Changes only when a scan completes.
    UPDATE_FREQUENCY = 30 * 60

    # Keyed by the scan's completion, so the TTL only bounds staleness of the cross-project signal.
    RECOMMENDATIONS = 10 * 60

    # Long TTL: version histories almost never change retroactively; new releases append.
    RELEASE_HISTORY = 24 * 3600


def scope_digest(ids: Iterable[str] | None) -> str:
    """None (global scope) gets a sentinel no id set's digest can equal."""
    if ids is None:
        return "*"
    return hashlib.sha256(",".join(sorted(ids)).encode()).hexdigest()[:16]


class CacheKeys:
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
        purl_hash = hashlib.md5(purl.encode(), usedforsecurity=False).hexdigest()[:16]
        # Holds only the querybatch stubs; the records they name are cached under osv_vuln.
        return f"osv4:{purl_hash}"

    @staticmethod
    def osv_vuln(vuln_id: str, modified: str) -> str:
        # The modified stamp is part of the key, so a revised OSV record can never be served stale.
        return f"osvrec:{vuln_id}:{modified}"

    @staticmethod
    def deps_dev(system: str, package: str, version: str) -> str:
        return f"deps:{system}:{package}:{version}"

    @staticmethod
    def deps_dev_project(project_id: str) -> str:
        return f"depsproj:{project_id}"

    @staticmethod
    def latest_version(system: str, package: str) -> str:
        return f"latest3:{system}:{package}"

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
        return f"maintainer2:{system}:{package}"

    @staticmethod
    def maintainer_github(repo: str) -> str:
        return f"maintainer_gh:{repo.lower()}"

    @staticmethod
    def malware(registry: str, package: str, version: str) -> str:
        return f"malware:{registry}:{package}:{version}"

    @staticmethod
    def update_frequency(project_id: str) -> str:
        return f"update_freq:{project_id}"

    @staticmethod
    def release_history(system: str, package: str) -> str:
        return f"releases:{system}:{package}"

    @staticmethod
    def update_frequency_comparison(scope_hash: str, team_id: str | None) -> str:
        # Keyed on the scope digest, so callers that see the same projects share one entry and no one else reads it.
        return f"update_freq_cmp:{scope_hash}:" + (f"team={team_id}" if team_id else "all-teams")

    @staticmethod
    def recommendations(project_id: str, scan_id: str, analysis_stamp: str, scope_hash: str) -> str:
        # scope_hash keeps users with different project access from sharing cross-project recommendation data.
        return f"recommendations:{project_id}:{scan_id}:{analysis_stamp}:{scope_hash}"


class _CacheOp:
    """Times one Redis call and swallows its failure, so the caller falls through to its default."""

    def __init__(self, cache: "CacheService", operation: str) -> None:
        self._cache = cache
        self._operation = operation

    def __enter__(self) -> None:
        self._start = time.perf_counter()

    # Typed bool, unlike @contextmanager's exit, so mypy sees the callers' default returns as reachable.
    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> bool:
        cache_operation_duration_seconds.labels(operation=self._operation).observe(time.perf_counter() - self._start)
        if isinstance(exc, (redis.ConnectionError, asyncio.TimeoutError)):
            logger.warning(REDIS_CONNECTION_LOST_MSG)
            self._cache._mark_unavailable()
        elif isinstance(exc, Exception):
            logger.warning(f"Cache {self._operation} error: {exc}")
        return isinstance(exc, Exception)


class CacheService:
    RECONNECT_INTERVAL_SECONDS = 30

    def __init__(self) -> None:
        self._pool: BlockingConnectionPool | None = None
        self._client: redis.Redis | None = None
        self._available: bool = True
        self._lock: asyncio.Lock = asyncio.Lock()
        self._unavailable_since: float = 0

    async def get_client(self) -> redis.Redis:
        if self._client is not None and self._pool is not None:
            return self._client

        async with self._lock:
            if self._client is not None and self._pool is not None:
                return self._client

            try:
                # A burst waits for a free connection; a non-blocking pool would fail it and disable the cache.
                self._pool = BlockingConnectionPool.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True,
                    max_connections=20,
                    timeout=REDIS_OPERATION_TIMEOUT_SECONDS,
                )
                self._client = redis.Redis(connection_pool=self._pool)
                await asyncio.wait_for(self._client.ping(), timeout=REDIS_OPERATION_TIMEOUT_SECONDS)
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
        if self._available:
            return False
        if self._unavailable_since == 0:
            return True
        elapsed = time.monotonic() - self._unavailable_since
        return elapsed >= self.RECONNECT_INTERVAL_SECONDS

    def _mark_unavailable(self) -> None:
        self._available = False
        self._unavailable_since = time.monotonic()

    async def _try_reconnect(self) -> bool:
        try:
            self._client = None
            self._pool = None
            await self.get_client()
            logger.info("Redis cache reconnected successfully")
            return True
        except Exception:
            self._mark_unavailable()
            return False

    async def _ensure_available(self) -> bool:
        if self._available:
            return True
        if self._should_retry_connection():
            return await self._try_reconnect()
        return False

    def _make_key(self, key: str) -> str:
        return f"{settings.CACHE_PREFIX}{key}"

    async def get(self, key: str) -> Any | None:
        if not await self._ensure_available():
            return None

        with _CacheOp(self, "get"):
            client = await self.get_client()
            data = await asyncio.wait_for(client.get(self._make_key(key)), timeout=REDIS_OPERATION_TIMEOUT_SECONDS)
            if data:
                cache_hits_total.inc()
                return json.loads(data)
            cache_misses_total.inc()
        return None

    async def set(self, key: str, value: Any, ttl_seconds: int) -> bool:
        if _writes_suppressed.get() or not await self._ensure_available():
            return False

        with _CacheOp(self, "set"):
            client = await self.get_client()
            await asyncio.wait_for(
                client.set(self._make_key(key), json.dumps(value, default=str), ex=ttl_seconds),
                timeout=REDIS_OPERATION_TIMEOUT_SECONDS,
            )
            return True
        return False

    async def mget(self, keys: list[str]) -> dict[str, Any]:
        if not keys:
            return {}
        if not await self._ensure_available():
            return dict.fromkeys(keys)

        with _CacheOp(self, "mget"):
            client = await self.get_client()
            values: list[Any] = []
            for batch in batched(keys, _KEYS_PER_ROUND_TRIP, strict=False):
                values += await asyncio.wait_for(
                    client.mget([self._make_key(k) for k in batch]),
                    timeout=REDIS_OPERATION_TIMEOUT_SECONDS,
                )
            result: dict[str, Any] = dict.fromkeys(keys)
            for key, value in zip(keys, values, strict=True):
                if value:
                    with suppress(json.JSONDecodeError):
                        result[key] = json.loads(value)
            hits = sum(1 for value in values if value)
            cache_hits_total.inc(hits)
            cache_misses_total.inc(len(values) - hits)
            return result
        return dict.fromkeys(keys)

    async def mset(self, mapping: dict[str, Any], ttl_seconds: int) -> bool:
        if _writes_suppressed.get() or not mapping or not await self._ensure_available():
            return False

        with _CacheOp(self, "mset"):
            client = await self.get_client()
            for batch in batched(mapping.items(), _KEYS_PER_ROUND_TRIP, strict=False):
                pipe = client.pipeline(transaction=False)
                for key, value in batch:
                    pipe.set(self._make_key(key), json.dumps(value, default=str), ex=ttl_seconds)
                await asyncio.wait_for(pipe.execute(), timeout=REDIS_OPERATION_TIMEOUT_SECONDS)
            return True
        return False

    async def incr(self, key: str, ttl_seconds: int) -> int | None:
        """Count one hit atomically in a window the first hit opens; None while Redis is unreachable."""
        if not await self._ensure_available():
            return None

        with _CacheOp(self, "incr"):
            client = await self.get_client()
            full_key = self._make_key(key)
            pipe = client.pipeline(transaction=True)
            pipe.incr(full_key)
            pipe.expire(full_key, ttl_seconds, nx=True)
            count, _ = await asyncio.wait_for(pipe.execute(), timeout=REDIS_OPERATION_TIMEOUT_SECONDS)
            return int(count)
        return None

    async def pop(self, key: str) -> Any | None:
        """Read and delete in one step, so only one caller receives the value; None if absent or unreachable."""
        if not await self._ensure_available():
            return None

        with _CacheOp(self, "pop"):
            client = await self.get_client()
            data = await asyncio.wait_for(client.getdel(self._make_key(key)), timeout=REDIS_OPERATION_TIMEOUT_SECONDS)
            return json.loads(data) if data else None
        return None

    async def eval(self, script: str, key: str, *args: str) -> Any | None:
        if not await self._ensure_available():
            return None

        with _CacheOp(self, "eval"):
            client = await self.get_client()
            reply = cast(Awaitable[Any], client.eval(script, 1, self._make_key(key), *args))
            return await asyncio.wait_for(reply, timeout=REDIS_OPERATION_TIMEOUT_SECONDS)
        return None

    async def get_or_fetch_with_lock(
        self,
        key: str,
        fetch_fn: Callable[[], Any],
        ttl_seconds: int,
        lock_ttl_seconds: int = STAMPEDE_LOCK_TTL_SECONDS,
        max_wait_seconds: float = STAMPEDE_MAX_WAIT_SECONDS,
        reraise_fetch_errors: bool = False,
    ) -> Any | None:
        """One pod fetches a miss while its peers wait on the lock, so a multi-pod deploy cannot stampede upstream."""
        cached = await self.get(key)
        if cached is not None:
            return cached

        # The stampede lock is itself a key, so a suppressed caller skips the whole locked path, not only the set.
        if not self._available or _writes_suppressed.get():
            return await self._fetch_bypassing_cache(key, fetch_fn, reraise_fetch_errors)

        lock_name = f"lock:{key}"
        lock_key = self._make_key(lock_name)
        try:
            client = await self.get_client()
            deadline = time.monotonic() + max_wait_seconds

            # Re-acquired each pass, so a waiter takes over from a holder that died without publishing.
            while time.monotonic() < deadline:
                # Unique per-acquisition token so we only release a lock we still own.
                lock_token = uuid.uuid4().hex
                # The lock expires, so a holder whose pod crashed cannot deadlock its peers.
                lock_acquired = await asyncio.wait_for(
                    client.set(lock_key, lock_token, nx=True, ex=lock_ttl_seconds),
                    timeout=REDIS_OPERATION_TIMEOUT_SECONDS,
                )

                if lock_acquired:
                    try:
                        try:
                            data = await fetch_fn()
                        except Exception as e:
                            raise _FetchFailed(e) from e
                        if data is not None:
                            await self.set(key, data, ttl_seconds)
                        else:
                            # Negative cache so peers don't all retry the failed fetch.
                            await self.set(key, {}, CacheTTL.NEGATIVE_RESULT)
                        return data
                    finally:
                        await self.eval(_UNLOCK_LUA, lock_name, lock_token)

                cached = await self._wait_for_lock_holder(client, key, lock_key, deadline)
                if cached is not None:
                    return cached

            cached = await self.get(key)
            if cached is not None:
                return cached
            logger.warning(f"Lock wait timeout for {key}, fetching anyway")
            try:
                data = await fetch_fn()
            except Exception as e:
                raise _FetchFailed(e) from e
            if data is not None:
                await self.set(key, data, ttl_seconds)
            return data

        except _FetchFailed as e:
            if reraise_fetch_errors:
                raise e.cause from None
            logger.warning(f"Fetch failed for {key}", exc_info=e.cause)
            return None
        except (redis.ConnectionError, asyncio.TimeoutError):
            logger.warning(REDIS_CONNECTION_LOST_MSG)
            self._mark_unavailable()
            return await self._fetch_bypassing_cache(key, fetch_fn, reraise_fetch_errors)
        except Exception as e:
            logger.warning(f"get_or_fetch_with_lock error for {key}: {e}")
            return await self._fetch_bypassing_cache(key, fetch_fn, reraise_fetch_errors)

    async def get_many_or_fetch(
        self, keys: Iterable[str], fetch_fn: Callable[[str], Awaitable[Any]], ttl_seconds: int, concurrency: int
    ) -> dict[str, Any]:
        """Misses are fetched as get_or_fetch_with_lock does; a failed fetch leaves its exception as the key's value."""
        wanted = list(dict.fromkeys(keys))
        values = {key: value for key, value in (await self.mget(wanted)).items() if value is not None}
        missing = [key for key in wanted if key not in values]
        fetched = await gather_bounded(
            missing,
            lambda key: self.get_or_fetch_with_lock(
                key=key, fetch_fn=lambda: fetch_fn(key), ttl_seconds=ttl_seconds, reraise_fetch_errors=True
            ),
            concurrency,
        )
        return values | dict(zip(missing, fetched, strict=True))

    @staticmethod
    async def _fetch_bypassing_cache(key: str, fetch_fn: Callable[[], Any], reraise_fetch_errors: bool) -> Any | None:
        try:
            return await fetch_fn()
        except Exception as e:
            if reraise_fetch_errors:
                raise
            logger.warning(f"Uncached fetch failed for {key}: {e}")
            return None

    async def _wait_for_lock_holder(
        self, client: "redis.Redis", key: str, full_lock_key: str, deadline: float
    ) -> Any | None:
        while time.monotonic() < deadline:
            await asyncio.sleep(_LOCK_POLL_INTERVAL_SECONDS)
            cached = await self.get(key)
            if cached is not None:
                return cached
            if not await asyncio.wait_for(client.exists(full_lock_key), timeout=REDIS_OPERATION_TIMEOUT_SECONDS):
                return None
        return None

    async def health_check(self) -> dict[str, Any]:
        try:
            client = await self.get_client()
            info = await client.info(section="memory")
            stats = await client.info(section="stats")
            clients_info = await client.info(section="clients")

            return {
                "status": "healthy",
                "available": self._available,
                "used_memory": info.get("used_memory_human", "unknown"),
                "used_memory_peak": info.get("used_memory_peak_human", "unknown"),
                "connected_clients": clients_info.get("connected_clients", 0),
                "total_keys": await client.dbsize(),
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
        total = hits + misses
        if total == 0:
            return 0.0
        return round((hits / total) * 100, 2)


cache_service = CacheService()


async def update_cache_stats() -> None:
    if not cache_service._available:
        return

    client = await cache_service.get_client()

    memory_info = await client.info(section="memory")
    clients_info = await client.info(section="clients")

    total_keys = await client.dbsize()

    connected_clients_count = clients_info.get("connected_clients", 0)
    used_memory = memory_info.get("used_memory", 0)

    cache_keys_total.set(total_keys)
    cache_connected_clients.set(connected_clients_count)
    cache_size_bytes.set(used_memory)

    logger.debug(
        f"Updated cache stats: keys={total_keys}, clients={connected_clients_count}, memory={used_memory} bytes"
    )
