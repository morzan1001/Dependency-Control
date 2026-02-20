from datetime import datetime, timezone
from typing import Optional


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure a datetime is timezone-aware (UTC).

    MongoDB returns naive datetimes (always UTC but without tzinfo).
    This adds UTC tzinfo if missing, enabling safe comparison with
    timezone-aware datetimes like datetime.now(timezone.utc).
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
