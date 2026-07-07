"""In-process LRU cache with per-entry TTL for expensive MongoDB analytics aggregations.

Process-local (not shared across pods). Callers that mutate underlying state must
call ``get_analytics_cache().clear()`` to avoid serving stale aggregations.
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
    """LRU cache with per-entry TTL; not thread-safe (callers are single-threaded per event-loop)."""

    def __init__(self, maxsize: int = 512, ttl_seconds: int = 300):
        self.maxsize = maxsize
        self.ttl_seconds = ttl_seconds
        self._store: "OrderedDict[Hashable, _Entry]" = OrderedDict()

    def get(self, key: Hashable) -> Tuple[bool, Any]:
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
        """Insert or update an entry, evicting the LRU entry if over capacity."""
        self._store[key] = _Entry(
            value=value,
            expires_at=time.monotonic() + self.ttl_seconds,
        )
        self._store.move_to_end(key)
        while len(self._store) > self.maxsize:
            self._store.popitem(last=False)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


_default_cache: Optional[TTLCache] = None


def get_analytics_cache() -> TTLCache:
    """Return the shared process-level analytics cache singleton."""
    global _default_cache
    if _default_cache is None:
        _default_cache = TTLCache(maxsize=512, ttl_seconds=300)
    return _default_cache


def reset_analytics_cache_for_tests() -> None:
    """Drop the cache singleton so tests see a fresh instance."""
    global _default_cache
    _default_cache = None
