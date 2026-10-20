import asyncio
import importlib
import inspect
import pkgutil
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import app.repositories
from app.core.init_db import create_indexes

# The worker, the ad-hoc endpoints and housekeeping read this collection straight off the database.
_WITHOUT_REPOSITORY = {"adhoc_jobs"}


class _NamingDatabase:
    """Records each collection name it hands out, whether asked for by item or by attribute."""

    def __init__(self) -> None:
        self.names: set[str] = set()

    def __getitem__(self, name: str) -> Any:
        self.names.add(name)
        return MagicMock(create_index=AsyncMock())

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return self[name]


def _repository_collections() -> set[str]:
    db = _NamingDatabase()
    for module_info in pkgutil.iter_modules(app.repositories.__path__):
        module = importlib.import_module(f"{app.repositories.__name__}.{module_info.name}")
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if cls.__module__ == module.__name__ and cls.__name__.endswith("Repository") and not cls.__type_params__:
                cls(db)
    return db.names


def test_every_collection_given_indexes_is_one_a_repository_reads():
    db = _NamingDatabase()

    asyncio.run(create_indexes(db))

    assert db.names - _repository_collections() == _WITHOUT_REPOSITORY
