"""In-process LRU cache with per-entry TTL for expensive MongoDB analytics aggregations.

Process-local (not shared across pods). Callers that mutate underlying state must
call ``get_analytics_cache().clear()`` to avoid serving stale aggregations.
"""

import asyncio
import functools
import time
from collections import OrderedDict
from collections.abc import Callable, Coroutine, Hashable
from dataclasses import dataclass
from typing import Any

_MAXSIZE = 512
_TTL_SECONDS = 300
# A delta item takes about 1.7 KiB, so the cached comparisons stay under ~90 MB per pod.
_DELTA_ROW_BUDGET = 50_000


@dataclass
class _Entry:
    value: Any
    expires_at: float
    size: int


class TTLCache:
    """LRU cache with per-entry TTL whose values' summed ``size_of`` stays within ``maxsize``; not thread-safe
    (callers are single-threaded per event-loop)."""

    def __init__(self, maxsize: int, ttl_seconds: int, size_of: Callable[[Any], int] = lambda _value: 1):
        self.maxsize = maxsize
        self.ttl_seconds = ttl_seconds
        self.size_of = size_of
        self._size = 0
        self._store: OrderedDict[Hashable, _Entry] = OrderedDict()
        self._in_flight: dict[Hashable, asyncio.Task[Any]] = {}

    def get(self, key: Hashable) -> tuple[bool, Any]:
        """Return (hit, value); drops the entry if missing or expired."""
        now = time.monotonic()
        if key not in self._store:
            return False, None
        entry = self._store[key]
        if entry.expires_at < now:
            self._pop(key)
            return False, None
        self._store.move_to_end(key)
        return True, entry.value

    def _pop(self, key: Hashable) -> None:
        self._size -= self._store.pop(key).size

    def set(self, key: Hashable, value: Any) -> None:
        """Insert or update an entry after dropping expired ones, then evict LRU entries over capacity."""
        now = time.monotonic()
        # get() reorders without refreshing expiry, so LRU order is not expiry order.
        for stale in [k for k, entry in self._store.items() if entry.expires_at < now or k == key]:
            self._pop(stale)
        entry = _Entry(value=value, expires_at=now + self.ttl_seconds, size=self.size_of(value))
        self._store[key] = entry
        self._size += entry.size
        while self._size > self.maxsize:
            self._pop(next(iter(self._store)))

    async def get_or_compute[T](self, key: Hashable, compute: Callable[[], Coroutine[Any, Any, T]]) -> T:
        """The cached value, else one computation shared by every concurrent miss on ``key``."""
        hit, value = self.get(key)
        if hit:
            return value  # type: ignore[no-any-return]
        task = self._in_flight.get(key)
        if task is None:
            task = asyncio.create_task(compute())
            self._in_flight[key] = task
            task.add_done_callback(functools.partial(self._settle, key))
        # The shield keeps one caller's disconnect from cancelling the computation the others await.
        return await asyncio.shield(task)

    def _settle(self, key: Hashable, task: asyncio.Task[Any]) -> None:
        if self._in_flight.get(key) is not task:
            return
        del self._in_flight[key]
        if not task.cancelled() and task.exception() is None:
            self.set(key, task.result())

    def clear(self) -> None:
        self._store.clear()
        self._size = 0
        self._in_flight.clear()


@functools.cache
def get_analytics_cache() -> TTLCache:
    """Return the shared process-level analytics cache singleton."""
    return TTLCache(_MAXSIZE, _TTL_SECONDS)


@functools.cache
def get_delta_cache() -> TTLCache:
    """Scan-delta comparisons, weighed by their items since one can hold up to two capped sides' worth."""
    return TTLCache(_DELTA_ROW_BUDGET, _TTL_SECONDS, size_of=lambda comparison: 1 + len(comparison.items))
