import time


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
