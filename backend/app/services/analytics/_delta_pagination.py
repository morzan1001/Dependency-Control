"""
Shared pagination helper and per-scan fetch cap for the scan-delta services.

Each per-category service (findings, components, crypto) does an identical
in-memory paginate over its built ``items`` list before returning the
envelope. Centralising the math here avoids three off-by-one risks.
"""

from __future__ import annotations

from typing import List, Tuple, TypeVar

# Per-scan cap on documents loaded into memory for delta computation. Keeps
# pathological scans from exhausting the worker.
MAX_FETCH = 50_000

T = TypeVar("T")


def paginate(items: List[T], page: int, page_size: int) -> Tuple[List[T], int]:
    """Slice ``items`` for the requested 1-indexed page.

    Returns the page slice and total page count (>= 1 even when empty).
    Assumes ``page >= 1`` and ``page_size >= 1`` — the orchestrator's
    ``_validate_query`` rejects out-of-range values before reaching here.
    """
    total = len(items)
    total_pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    return items[start : start + page_size], total_pages
