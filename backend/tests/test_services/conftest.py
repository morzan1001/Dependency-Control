import fakeredis.aioredis
import pytest

from app.core.cache import CacheService


@pytest.fixture
def fake_cache():
    """A CacheService backed by an in-memory fakeredis async client."""
    svc = CacheService()
    svc._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    svc._pool = object()  # non-None so get_client() short-circuits to the fake
    svc._available = True
    return svc
