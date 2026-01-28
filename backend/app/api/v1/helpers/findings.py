"""
Findings Helper Functions

Shared utilities for finding-related operations.
"""

from typing import Any, Dict, Optional

# Category to finding types mapping
CATEGORY_TYPE_MAP: Dict[str, Any] = {
    "security": {"$in": ["vulnerability", "malware", "typosquatting"]},
    "secret": "secret",
    "sast": {"$in": ["sast", "iac"]},
    "compliance": {"$in": ["license", "eol"]},
    "quality": {"$in": ["outdated", "quality"]},
}

# Reverse mapping: finding type to category
TYPE_CATEGORY_MAP: Dict[str, str] = {
    "vulnerability": "security",
    "malware": "security",
    "typosquatting": "security",
    "secret": "secret",
    "sast": "sast",
    "iac": "sast",
    "license": "compliance",
    "eol": "compliance",
    "outdated": "quality",
    "quality": "quality",
}


def get_category_type_filter(category: str) -> Optional[Any]:
    """
    Get the MongoDB type filter for a finding category.

    Args:
        category: The category name (security, secret, sast, compliance, quality)

    Returns:
        MongoDB filter value for the 'type' field, or None if category not found
    """
    return CATEGORY_TYPE_MAP.get(category)


def get_category_for_type(finding_type: str) -> str:
    """
    Get the category for a finding type.

    Args:
        finding_type: The finding type (vulnerability, secret, sast, etc.)

    Returns:
        Category name (security, secret, sast, compliance, quality, or 'other')
    """
    return TYPE_CATEGORY_MAP.get(finding_type, "other")


def aggregate_stats_by_category(type_counts: list) -> Dict[str, int]:
    """
    Aggregate finding counts by category from type counts.

    Args:
        type_counts: List of dicts with '_id' (type) and 'count' keys

    Returns:
        Dictionary with category counts
    """
    stats = {
        "security": 0,
        "secret": 0,
        "sast": 0,
        "compliance": 0,
        "quality": 0,
        "other": 0,
    }

    for item in type_counts:
        finding_type = item["_id"]
        count = item["count"]
        category = get_category_for_type(finding_type)
        stats[category] += count

    return stats
