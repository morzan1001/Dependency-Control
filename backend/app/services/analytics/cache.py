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


@dataclass
class _Entry:
    value: Any
    expires_at: float


class TTLCache:
    """LRU cache with per-entry TTL; not thread-safe (callers are single-threaded per event-loop)."""

    def __init__(self, maxsize: int, ttl_seconds: int):
        self.maxsize = maxsize
        self.ttl_seconds = ttl_seconds
        self._store: OrderedDict[Hashable, _Entry] = OrderedDict()
        self._in_flight: dict[Hashable, asyncio.Task[Any]] = {}

    def get(self, key: Hashable) -> tuple[bool, Any]:
        """Return (hit, value); drops the entry if missing or expired."""
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
        """Insert or update an entry after dropping expired ones, then evict LRU entries over capacity."""
        now = time.monotonic()
        # get() reorders without refreshing expiry, so LRU order is not expiry order.
        for stale in [k for k, entry in self._store.items() if entry.expires_at < now]:
            del self._store[stale]
        self._store[key] = _Entry(value=value, expires_at=now + self.ttl_seconds)
        self._store.move_to_end(key)
        while len(self._store) > self.maxsize:
            self._store.popitem(last=False)

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
        self._in_flight.clear()


@functools.cache
def get_analytics_cache() -> TTLCache:
    """Return the shared process-level analytics cache singleton."""
    return TTLCache(_MAXSIZE, _TTL_SECONDS)
