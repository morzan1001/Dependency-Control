"""
Pagination Helper Functions

Shared utilities for building paginated responses.
"""

from typing import Any, Dict, List


def build_pagination_response(
    items: List[Any],
    total: int,
    skip: int,
    limit: int,
) -> Dict[str, Any]:
    """
    Build a standardized pagination response.

    Args:
        items: List of items for the current page
        total: Total number of items across all pages
        skip: Number of items skipped
        limit: Maximum items per page

    Returns:
        Dictionary with items, total, page, size, and pages
    """
    return {
        "items": items,
        "total": total,
        "page": (skip // limit) + 1 if limit > 0 else 1,
        "size": limit,
        "pages": (total + limit - 1) // limit if limit > 0 else 0,
    }
