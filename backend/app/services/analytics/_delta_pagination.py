"""Shared in-memory pagination helper and per-scan fetch cap for scan-delta services."""

from __future__ import annotations

from typing import List, Tuple, TypeVar

# Per-scan cap on documents loaded into memory, bounding worker memory.
MAX_FETCH = 50_000

T = TypeVar("T")


def paginate(items: List[T], page: int, page_size: int) -> Tuple[List[T], int]:
    """Slice ``items`` for the 1-indexed ``page``; returns (slice, total_pages >= 1). Assumes page/page_size >= 1."""
    total = len(items)
    total_pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    return items[start : start + page_size], total_pages
