"""Shared in-memory pagination, side grouping, version pairing and per-scan fetch cap for scan-delta services."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import TypeVar

from app.schemas.scan_delta import DeltaTruncation

# Per-scan cap on documents loaded into memory, bounding worker memory. The findings projection
# measures 2.14 KiB per document, and a findings delta holds four of these fetches at once.
MAX_FETCH = 50_000

T = TypeVar("T")
K = TypeVar("K")


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


def by_side(key: Callable[[T], K], from_items: Iterable[T], to_items: Iterable[T]) -> dict[K, tuple[list[T], list[T]]]:
    """Both sides' items grouped under one key, as (from items, to items)."""
    groups: dict[K, tuple[list[T], list[T]]] = defaultdict(lambda: ([], []))
    for side, items in enumerate((from_items, to_items)):
        for item in items:
            groups[key(item)][side].append(item)
    return groups


def pair_versions(from_docs: list[dict], to_docs: list[dict]) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """Pair the documents both sides hold under one identity: a lone document per side pairs whatever
    its version, otherwise equal versions pair. Returns the pairs and the unpaired removed and added."""
    if len(from_docs) == len(to_docs) == 1:
        return [(from_docs[0], to_docs[0])], [], []
    by_version: dict[str, list[dict]] = defaultdict(list)
    for doc in to_docs:
        by_version[doc.get("version") or ""].append(doc)
    pairs, removed = [], []
    for doc in from_docs:
        partners = by_version.get(doc.get("version") or "")
        if partners:
            pairs.append((doc, partners.pop()))
        else:
            removed.append(doc)
    return pairs, removed, [doc for partners in by_version.values() for doc in partners]
