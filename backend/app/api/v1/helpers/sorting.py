"""
Sorting Helper Functions

Shared utilities for sorting and pagination across endpoints.
"""

from typing import Dict, Literal

# Sort field mappings for different entity types
SORT_FIELDS: Dict[str, Dict[str, str]] = {
    "projects": {
        "name": "name",
        "created_at": "created_at",
        "last_scan_at": "last_scan_at",
        "critical": "stats.critical",
        "high": "stats.high",
        "risk_score": "stats.risk_score",
    },
    "scans": {
        "created_at": "created_at",
        "pipeline_iid": "pipeline_iid",
        "branch": "branch",
        "status": "status",
    },
    "project_scans": {
        "created_at": "created_at",
        "pipeline_iid": "pipeline_iid",
        "branch": "branch",
        "findings_count": "findings_count",
        "status": "status",
    },
    "findings": {
        "severity": "severity_rank",
        "component": "component",
        "type": "type",
        "created_at": "created_at",
    },
}


def parse_sort_direction(sort_order: str) -> int:
    """
    Convert sort order string to MongoDB sort direction.

    Args:
        sort_order: "asc" or "desc"

    Returns:
        1 for ascending, -1 for descending
    """
    return -1 if sort_order.lower() == "desc" else 1


def get_sort_field(
    entity_type: Literal["projects", "scans", "project_scans", "findings"],
    sort_by: str,
    default: str = "created_at",
) -> str:
    """
    Get validated sort field for an entity type.

    Args:
        entity_type: Type of entity being sorted
        sort_by: Requested sort field
        default: Default field if sort_by is invalid

    Returns:
        Valid MongoDB field path for sorting
    """
    fields = SORT_FIELDS.get(entity_type, {})
    return fields.get(sort_by, fields.get(default, default))
