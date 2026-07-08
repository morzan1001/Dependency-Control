import pytest_asyncio

from tests.mocks.fake_mongo import FakeDatabase


@pytest_asyncio.fixture
async def db():
    return FakeDatabase()
