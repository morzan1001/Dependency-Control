"""Response models shared by the API-key listings."""

from pydantic import BaseModel


class KeyListTruncation(BaseModel):
    """What a saturated key listing left out. A credential the owner cannot see is one they
    cannot revoke, so the page may not end without the response saying that it did."""

    limit: int
    returned: int
    total: int


def key_list_truncation(*, returned: int, total: int, limit: int) -> KeyListTruncation | None:
    """The disclosure for a key listing, or None when the listing is the whole of it."""
    return KeyListTruncation(limit=limit, returned=returned, total=total) if total > returned else None
