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
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def parse_iso_utc(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return ensure_utc(datetime.fromisoformat(value))
    except ValueError:
        return None


async def abatched[T](items: AsyncIterable[T], size: int) -> AsyncIterator[list[T]]:
    batch: list[T] = []
    async for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch
