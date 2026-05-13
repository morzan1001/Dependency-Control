"""Fixtures for unit tests — provides the shared in-process FakeDatabase.

The FakeDatabase implementation lives in ``tests/mocks/fake_mongo.py`` and is
shared with the integration test conftest, so changes to operator support land
in one place. See that module's docstring for the supported operator list.
"""

import pytest_asyncio

from tests.mocks.fake_mongo import FakeDatabase


@pytest_asyncio.fixture
async def db():
    """In-process fake database scoped to a single test."""
    return FakeDatabase()
