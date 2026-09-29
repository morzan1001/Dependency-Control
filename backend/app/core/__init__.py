from collections.abc import AsyncIterable, AsyncIterator
from datetime import datetime, timezone
from typing import overload

# Sorts last on a recency tie-break.
UNDATED = datetime.min.replace(tzinfo=timezone.utc)


@overload
def ensure_utc(dt: datetime) -> datetime: ...
@overload
def ensure_utc(dt: None) -> None: ...
def ensure_utc(dt: datetime | None) -> datetime | None:
    """Treat a naive datetime as UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def abatched[T](items: AsyncIterable[T], size: int) -> AsyncIterator[list[T]]:
    """The async counterpart of itertools.batched, as lists."""
    batch: list[T] = []
    async for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch
