"""Shared side reads, paging, side grouping and version pairing for scan-delta services."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterable
from typing import TypeVar

from app.schemas.scan_delta import ScanDeltaResponse

# Component items split `changed` into two kinds; the filter vocabulary keeps one.
_FILTER_OF = {"version_changed": "changed", "license_changed": "changed"}

T = TypeVar("T")
K = TypeVar("K")


async def both_sides(read: Callable[[str], Awaitable[T]], from_scan: str, to_scan: str) -> tuple[T, T]:
    """Each side's read, concurrently; a pair resolved onto one scan is read once."""
    if from_scan == to_scan:
        side = await read(from_scan)
        return side, side
    return await asyncio.gather(read(from_scan), read(to_scan))


def page_of(comparison: ScanDeltaResponse, change: str | None, page: int, page_size: int) -> ScanDeltaResponse:
    """One 1-indexed page of a sorted comparison's items of the ``change`` kind; assumes page/page_size >= 1."""
    items = [i for i in comparison.items if change in (None, "all", _FILTER_OF.get(i.change, i.change))]
    start = (page - 1) * page_size
    return comparison.model_copy(
        update={
            "items": items[start : start + page_size],
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, -(-len(items) // page_size)),
        }
    )


def by_side(key: Callable[[T], K], from_items: Iterable[T], to_items: Iterable[T]) -> dict[K, tuple[list[T], list[T]]]:
    """Both sides' items grouped under one key, as (from items, to items)."""
    groups: dict[K, tuple[list[T], list[T]]] = defaultdict(lambda: ([], []))
    for side, items in enumerate((from_items, to_items)):
        for item in items:
            groups[key(item)][side].append(item)
    return groups


def pair_versions(from_docs: list[dict], to_docs: list[dict]) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """A lone doc per side pairs whatever its version, else equal versions pair; returns pairs, removed, added."""
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
