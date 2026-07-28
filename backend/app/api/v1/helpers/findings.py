"""Shared utilities for finding-related operations."""

from typing import Any

CATEGORY_TYPE_MAP: dict[str, Any] = {
    "security": {"$in": ["vulnerability", "malware", "typosquatting"]},
    "secret": "secret",
    "sast": {"$in": ["sast", "iac"]},
    "compliance": {"$in": ["license", "eol"]},
    "quality": {"$in": ["outdated", "quality"]},
}

TYPE_CATEGORY_MAP: dict[str, str] = {
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


def get_category_type_filter(category: str) -> Any | None:
    """Get the MongoDB 'type' filter for a finding category, or None if unknown."""
    return CATEGORY_TYPE_MAP.get(category)


def get_category_for_type(finding_type: str) -> str:
    """Get the category for a finding type, or 'other' if unknown."""
    return TYPE_CATEGORY_MAP.get(finding_type, "other")


def aggregate_stats_by_category(type_counts: list) -> dict[str, int]:
    """Aggregate finding counts by category from a list of {_id: type, count} dicts."""
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
