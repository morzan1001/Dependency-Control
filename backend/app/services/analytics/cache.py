"""
TTLCache — minimal thread-unsafe LRU cache with per-entry TTL.

Used to cache expensive analytics aggregation query results so repeated
requests within the TTL window are served without hitting MongoDB.
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


_default_cache: Optional[TTLCache] = None


def get_analytics_cache() -> TTLCache:
    """Return the process-level analytics cache singleton."""
    global _default_cache
    if _default_cache is None:
        _default_cache = TTLCache(maxsize=512, ttl_seconds=300)
    return _default_cache
