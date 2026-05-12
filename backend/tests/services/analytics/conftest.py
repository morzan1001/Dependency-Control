"""Fixtures for service-level analytics tests.

Reuses the in-process fake database defined in tests/unit/conftest.py so
service tests do not require a real MongoDB instance.
"""

import pytest_asyncio

from tests.unit.conftest import _FakeDb


@pytest_asyncio.fixture
async def db():
    """In-process fake database for analytics service tests."""
    return _FakeDb()
