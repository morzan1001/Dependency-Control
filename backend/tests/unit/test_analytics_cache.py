import asyncio
import time

import pytest

from app.services.analytics.cache import TTLCache


def test_cache_hit_returns_stored_value():
    cache = TTLCache(maxsize=8, ttl_seconds=60)
    cache.set(("a", "b"), {"data": 1})
    hit, value = cache.get(("a", "b"))
    assert hit is True
    assert value == {"data": 1}


def test_cache_miss_returns_none():
    cache = TTLCache(maxsize=8, ttl_seconds=60)
    hit, value = cache.get(("missing",))
    assert hit is False
    assert value is None


def test_cache_expires_after_ttl(monkeypatch):
    cache = TTLCache(maxsize=8, ttl_seconds=1)
    t = {"now": 1000.0}
    monkeypatch.setattr(time, "monotonic", lambda: t["now"])
    cache.set(("k",), "v")
    assert cache.get(("k",)) == (True, "v")
    t["now"] += 2.0
    assert cache.get(("k",)) == (False, None)


def test_cache_lru_eviction():
    cache = TTLCache(maxsize=2, ttl_seconds=60)
    cache.set(("a",), 1)
    cache.set(("b",), 2)
    cache.get(("a",))
    cache.set(("c",), 3)
    assert cache.get(("a",))[0] is True
    assert cache.get(("b",))[0] is False
    assert cache.get(("c",))[0] is True


def test_a_weighed_cache_evicts_until_the_summed_size_fits():
    cache = TTLCache(maxsize=3, ttl_seconds=60, size_of=len)
    cache.set(("a",), [1, 2])
    cache.set(("a",), [1])
    cache.set(("b",), [1, 2])
    assert (cache.get(("a",))[0], cache.get(("b",))[0]) == (True, True)
    cache.set(("c",), [1])
    assert (cache.get(("a",))[0], cache.get(("b",))[0], cache.get(("c",))[0]) == (False, True, True)


def test_a_value_heavier_than_the_whole_cache_is_not_kept():
    cache = TTLCache(maxsize=3, ttl_seconds=60, size_of=len)
    cache.set(("huge",), [1, 2, 3, 4])
    cache.set(("small",), [1])
    assert (cache.get(("huge",))[0], cache.get(("small",))[0]) == (False, True)


def test_a_write_drops_expired_entries_before_evicting_a_live_one(monkeypatch):
    """A read moves an entry to the back without extending its life, so the LRU head can be live."""
    cache = TTLCache(maxsize=2, ttl_seconds=10)
    t = {"now": 0.0}
    monkeypatch.setattr(time, "monotonic", lambda: t["now"])
    cache.set(("old",), 1)
    t["now"] = 5.0
    cache.set(("live",), 2)
    cache.get(("old",))
    t["now"] = 11.0
    cache.set(("new",), 3)
    assert cache.get(("live",)) == (True, 2)


async def _counted(calls: list[int], value: object, gate: asyncio.Event | None = None) -> object:
    calls.append(1)
    if gate is not None:
        await gate.wait()
    return value


@pytest.mark.asyncio
async def test_concurrent_misses_share_one_computation():
    cache = TTLCache(maxsize=8, ttl_seconds=60)
    calls: list[int] = []
    gate = asyncio.Event()
    waiters = [asyncio.create_task(cache.get_or_compute(("k",), lambda: _counted(calls, "v", gate))) for _ in range(3)]
    await asyncio.sleep(0)
    gate.set()
    assert await asyncio.gather(*waiters) == ["v", "v", "v"]
    assert await cache.get_or_compute(("k",), lambda: _counted(calls, "other")) == "v"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_a_failed_computation_is_not_cached():
    cache = TTLCache(maxsize=8, ttl_seconds=60)

    async def fail() -> object:
        raise RuntimeError("mongo down")

    with pytest.raises(RuntimeError):
        await cache.get_or_compute(("k",), fail)
    assert await cache.get_or_compute(("k",), lambda: _counted([], "v")) == "v"


@pytest.mark.asyncio
async def test_a_disconnected_caller_does_not_cancel_the_shared_computation():
    cache = TTLCache(maxsize=8, ttl_seconds=60)
    gate = asyncio.Event()
    first = asyncio.create_task(cache.get_or_compute(("k",), lambda: _counted([], "v", gate)))
    second = asyncio.create_task(cache.get_or_compute(("k",), lambda: _counted([], "unused")))
    await asyncio.sleep(0)
    first.cancel()
    gate.set()
    assert await second == "v"
    assert cache.get(("k",)) == (True, "v")


@pytest.mark.asyncio
async def test_a_computation_that_straddles_a_clear_is_not_cached():
    """clear() marks what was read before it as stale, including a read still in flight."""
    cache = TTLCache(maxsize=8, ttl_seconds=60)
    gate = asyncio.Event()
    before = asyncio.create_task(cache.get_or_compute(("k",), lambda: _counted([], "stale", gate)))
    await asyncio.sleep(0)
    cache.clear()
    gate.set()
    assert await before == "stale"
    assert await cache.get_or_compute(("k",), lambda: _counted([], "fresh")) == "fresh"
