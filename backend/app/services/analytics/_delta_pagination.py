"""Shared in-memory pagination helper and per-scan fetch cap for scan-delta services."""

from __future__ import annotations

from typing import TypeVar

from app.schemas.scan_delta import DeltaTruncation

# Per-scan cap on documents loaded into memory, bounding worker memory. The findings projection
# measures 2.14 KiB per document, and a findings delta holds four of these fetches at once.
MAX_FETCH = 50_000

T = TypeVar("T")


def paginate(items: list[T], page: int, page_size: int) -> tuple[list[T], int]:
    """Slice ``items`` for the 1-indexed ``page``; returns (slice, total_pages >= 1). Assumes page/page_size >= 1."""
    total = len(items)
    total_pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    return items[start : start + page_size], total_pages


def delta_truncation(
    limit: int,
    *,
    from_compared: int,
    from_total: int,
    to_compared: int,
    to_total: int,
) -> DeltaTruncation | None:
    """The record a caller needs to tell a windowed comparison from a whole one; None when neither
    side was windowed."""
    if from_compared >= from_total and to_compared >= to_total:
        return None
    return DeltaTruncation(
        limit=limit,
        from_compared=from_compared,
        from_total=from_total,
        to_compared=to_compared,
        to_total=to_total,
    )
