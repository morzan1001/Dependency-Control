"""Fixtures for service-level analytics tests.

Reuses the shared FakeDatabase from ``tests/mocks/fake_mongo.py`` so service
tests run in-process without a real MongoDB.
"""

import pytest_asyncio

from tests.mocks.fake_mongo import FakeDatabase


@pytest_asyncio.fixture
async def db():
    """In-process fake database for analytics service tests."""
    return FakeDatabase()
