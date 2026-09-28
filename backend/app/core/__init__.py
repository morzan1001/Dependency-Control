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
