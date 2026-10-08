"""The per-project view's upstream release cadence: how it is read, and that every read path keeps it."""

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

from app.api.v1.endpoints.analytics import update_frequency as endpoint_module
from app.core.config import settings
from app.services import release_history as release_history_module
from app.services.update_frequency_rollup import record_scan_update_delta

_PATH = "/api/v1/analytics/projects/p/update-frequency"
_PACKAGES = ("alpha", "beta", "gone")


class _MemoryCache:
    """The cache calls the view makes, over a dict, with every Redis round trip recorded."""

    def __init__(self) -> None:
        self.stored: dict[str, Any] = {}
        self.round_trips: list[str] = []

    async def get_or_fetch_with_lock(self, _key: str, fetch_fn: Any, **_kwargs: Any) -> Any:
        return await fetch_fn()

    async def get(self, key: str) -> Any:
        self.round_trips.append("get")
        return self.stored.get(key)

    async def set(self, key: str, value: Any, ttl_seconds: int | None = None) -> bool:
        self.round_trips.append("set")
        self.stored[key] = value
        return True

    async def mget(self, keys: list[str]) -> dict[str, Any]:
        self.round_trips.append("mget")
        return {key: self.stored.get(key) for key in keys}

    async def mset(self, mapping: dict[str, Any], ttl_seconds: int | None = None) -> bool:
        self.round_trips.append("mset")
        self.stored.update(mapping)
        return True


@pytest.fixture
def cache(monkeypatch) -> _MemoryCache:
    memory = _MemoryCache()
    monkeypatch.setattr(endpoint_module, "cache_service", memory)
    monkeypatch.setattr(release_history_module, "cache_service", memory, raising=False)
    return memory


@pytest.fixture
def deps_dev(monkeypatch) -> tuple[list[int], list[str]]:
    """Every client opened and every path requested while the view reads release histories."""
    opened: list[int] = []
    requested: list[str] = []
    real_client = httpx.AsyncClient

    def _answer(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        if request.url.path.endswith("/gone"):
            return httpx.Response(404, request=request)
        versions = [{"versionKey": {"version": "2.0.0"}, "publishedAt": "2026-01-01T00:00:00Z"}]
        return httpx.Response(200, json={"versions": versions}, request=request)

    def _client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        opened.append(1)
        return real_client(*args, transport=httpx.MockTransport(_answer), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _client)
    return opened, requested


async def _seed_upgrade(db) -> None:
    now = datetime.now(timezone.utc)
    for index, version in enumerate(("1.0.0", "2.0.0")):
        scan_id = f"s{index}"
        await db.scans.insert_one(
            {
                "_id": scan_id,
                "project_id": "p",
                "branch": "main",
                "status": "completed",
                "is_rescan": False,
                "commit_hash": f"c{index}",
                "created_at": now - timedelta(days=10 - index),
            }
        )
        for name in _PACKAGES:
            await db.dependencies.insert_one(
                {
                    "_id": f"{scan_id}:{name}",
                    "scan_id": scan_id,
                    "project_id": "p",
                    "name": name,
                    "version": version,
                    "type": "library",
                    "purl": f"pkg:npm/{name}@{version}",
                }
            )


@pytest.mark.asyncio
async def test_release_lookups_share_one_client_and_one_read_and_remember_a_404(
    client, db, owner_auth_headers_proj, cache, deps_dev
):
    opened, requested = deps_dev
    await _seed_upgrade(db)

    first = await client.get(_PATH, headers=owner_auth_headers_proj)

    assert first.status_code == 200, first.text
    assert first.json()["adoption_latency_days_median"] is not None
    assert len(opened) == 1
    assert cache.round_trips == ["mget", "mset"]

    requested.clear()
    cache.round_trips.clear()
    second = await client.get(_PATH, headers=owner_auth_headers_proj)

    assert second.status_code == 200, second.text
    assert requested == []
    assert cache.round_trips == ["mget"]


@pytest.mark.asyncio
async def test_the_project_view_keeps_its_upstream_cadence_when_the_comparison_reads_the_ledger(
    client, db, owner_auth_headers_proj, cache, deps_dev, monkeypatch
):
    """The ledger holds no release history, so only the walk can fill the cadence card."""
    monkeypatch.setattr(settings, "UPDATE_FREQUENCY_USE_ROLLUP", True)
    await _seed_upgrade(db)
    for scan_id in ("s0", "s1"):
        await record_scan_update_delta(db, scan_id)

    response = await client.get(_PATH, params={"window_days": 90}, headers=owner_auth_headers_proj)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["scan_count"], body["total_updates"]) == (2, 3)
    assert body["adoption_latency_days_median"] is not None
    assert body["upstream_releases_last_12m_median"] is not None
