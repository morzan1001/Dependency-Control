import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, call

import pytest
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from app.main import app


@pytest.fixture
def deps(monkeypatch):
    deps = MagicMock()
    for name in ("connect_to_mongo", "init_db", "close_mongo_connection"):
        setattr(deps, name, AsyncMock())
        monkeypatch.setattr(f"app.main.{name}", getattr(deps, name))
    deps.worker_manager.start = AsyncMock()
    deps.worker_manager.stop = AsyncMock()
    monkeypatch.setattr("app.main.worker_manager", deps.worker_manager)
    deps.sleep = AsyncMock()
    monkeypatch.setattr("app.main.asyncio.sleep", deps.sleep)
    monkeypatch.setattr("app.core.s3.is_archive_enabled", lambda: False)
    # A real WeasyPrint import inside a running loop can segfault (see tests/conftest.py).
    monkeypatch.setitem(sys.modules, "weasyprint", ModuleType("weasyprint"))
    return deps


@pytest.mark.asyncio
async def test_lifespan_starts_before_serving_and_stops_after(deps):
    async with app.router.lifespan_context(app):
        assert deps.mock_calls == [call.connect_to_mongo(), call.init_db(), call.worker_manager.start()]
    assert deps.mock_calls[3:] == [call.worker_manager.stop(), call.close_mongo_connection()]


@pytest.mark.asyncio
async def test_lifespan_retries_an_unreachable_database(deps):
    deps.connect_to_mongo.side_effect = [ServerSelectionTimeoutError("down"), None]
    async with app.router.lifespan_context(app):
        assert deps.mock_calls == [
            call.connect_to_mongo(),
            call.close_mongo_connection(),
            call.sleep(5),
            call.connect_to_mongo(),
            call.init_db(),
            call.worker_manager.start(),
        ]


@pytest.mark.asyncio
async def test_lifespan_gives_up_after_30_attempts(deps):
    deps.connect_to_mongo.side_effect = ConnectionFailure("down")
    with pytest.raises(ConnectionFailure):
        async with app.router.lifespan_context(app):
            pytest.fail("served without a database")
    assert deps.connect_to_mongo.await_count == 30
    assert deps.sleep.await_count == 29
    deps.worker_manager.start.assert_not_awaited()
    deps.worker_manager.stop.assert_not_awaited()


@pytest.mark.asyncio
async def test_lifespan_stops_the_workers_when_serving_ends_abnormally(deps):
    with pytest.raises(RuntimeError):
        async with app.router.lifespan_context(app):
            raise RuntimeError("serving task cancelled")
    deps.worker_manager.stop.assert_awaited_once()
    deps.close_mongo_connection.assert_awaited_once()
