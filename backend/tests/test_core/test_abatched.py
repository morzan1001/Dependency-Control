"""abatched cuts an async stream into full batches and flushes the short remainder once."""

import pytest

from app.core import abatched


async def _stream(n: int):
    for i in range(n):
        yield i


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("n", "expected"),
    [(0, []), (2, [[0, 1]]), (3, [[0, 1, 2]]), (7, [[0, 1, 2], [3, 4, 5], [6]])],
)
async def test_batches_are_full_except_the_last(n, expected):
    assert [batch async for batch in abatched(_stream(n), 3)] == expected
