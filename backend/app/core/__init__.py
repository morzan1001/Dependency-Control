from datetime import datetime, timezone
from typing import Optional


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Add UTC tzinfo to naive datetimes (MongoDB returns UTC without tzinfo) for safe comparison."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
