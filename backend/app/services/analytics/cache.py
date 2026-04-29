"""
In-process analytics cache — a minimal LRU cache with per-entry TTL.

Used to memoize the output of expensive MongoDB aggregation queries
(crypto hotspots, trends, PQC migration plans, scan deltas). Entries are
tied to a cache key that combines `(scope, scope_id, query-parameters,
data-fingerprint)`; see `CryptoHotspotService.hotspots` for the typical
shape.

When to use this cache vs. ``app.core.cache.cache_service``
----------------------------------------------------------
* **This cache (TTLCache / get_analytics_cache)** — for hot,
  process-local reads that are recomputed from MongoDB. Sync API.
  Values can be arbitrary Python objects (including Pydantic models).
  Does NOT share state across pods — each replica computes on miss.
  Appropriate when the cost of recomputation is small per-pod and
  per-pod consistency (e.g. "always returns current DB state within
  TTL") is sufficient.

* **``app.core.cache.cache_service``** — for results of external calls
  (OSV, deps.dev, NPM license lookups, OIDC key material) where
  cross-pod deduplication matters or upstream rate-limits apply.
  Async API, Redis-backed, JSON-serialized. Use when the fetch itself
  is expensive in calendar time or subject to external rate-limits.

Invalidation
------------
Callers that mutate the underlying MongoDB state (policy changes,
waiver add/remove, crypto asset upsert) MUST call
``get_analytics_cache().clear()`` to avoid serving stale aggregations.
See ``app.services.audit.history.record_policy_change`` for the
canonical example.
"""

from collections import OrderedDict
from dataclasses import dataclass
import time
from typing import Any, Hashable, Optional, Tuple


@dataclass
class _Entry:
    value: Any
    expires_at: float


class TTLCache:
    """
    Least-Recently-Used cache with per-entry time-to-live.

    Not thread-safe — analytics service callers are async/single-threaded
    per event-loop, so locking is not required.
    """

    def __init__(self, maxsize: int = 512, ttl_seconds: int = 300):
        self.maxsize = maxsize
        self.ttl_seconds = ttl_seconds
        self._store: "OrderedDict[Hashable, _Entry]" = OrderedDict()

    def get(self, key: Hashable) -> Tuple[bool, Any]:
        """
        Return (hit, value).  If the entry is missing or expired returns
        (False, None) and removes the stale entry from the store.
        """
        now = time.monotonic()
        if key not in self._store:
            return False, None
        entry = self._store[key]
        if entry.expires_at < now:
            self._store.pop(key, None)
            return False, None
        self._store.move_to_end(key)
        return True, entry.value

    def set(self, key: Hashable, value: Any) -> None:
        """Insert or update an entry, evicting the LRU entry if over capacity."""
        self._store[key] = _Entry(
            value=value,
            expires_at=time.monotonic() + self.ttl_seconds,
        )
        self._store.move_to_end(key)
        while len(self._store) > self.maxsize:
            self._store.popitem(last=False)

    def clear(self) -> None:
        """Remove all cached entries."""
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


_default_cache: Optional[TTLCache] = None


def get_analytics_cache() -> TTLCache:
    """Return the process-level analytics cache singleton.

    Prefer this over creating a local TTLCache so that all analytics
    services share the same invalidation surface — ``clear()`` called
    from one mutation path invalidates every aggregation.
    """
    global _default_cache
    if _default_cache is None:
        _default_cache = TTLCache(maxsize=512, ttl_seconds=300)
    return _default_cache


def reset_analytics_cache_for_tests() -> None:
    """Drop the process-level cache singleton — test-only helper.

    Tests that patch the cache (e.g. to substitute a spy) should call
    this in teardown so subsequent tests see a fresh singleton.
    """
    global _default_cache
    _default_cache = None
