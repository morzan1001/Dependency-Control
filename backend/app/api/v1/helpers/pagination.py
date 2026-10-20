from typing import Any


def page_meta(total: int, skip: int, limit: int) -> dict[str, Any]:
    """An empty list is page 1 of 1, so no consumer needs its own fallback."""
    return {"total": total, "page": skip // limit + 1, "size": limit, "pages": max(1, -(-total // limit))}


def build_pagination_response(
    items: list[Any],
    total: int,
    skip: int,
    limit: int,
) -> dict[str, Any]:
    return {"items": items, **page_meta(total, skip, limit)}


def page_facet(page: list[dict[str, Any]]) -> dict[str, Any]:
    return {"$facet": {"metadata": [{"$count": "total"}], "data": page}}


def unpack_page_facet(result: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    bucket = result[0]
    data = bucket.get("data") or []
    metadata = bucket.get("metadata") or []
    total = metadata[0]["total"] if metadata else 0
    return data, total
