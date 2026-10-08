"""Shared utilities for sorting across endpoints."""

from typing import Annotated, Literal

from fastapi import Query

SORT_FIELDS: dict[str, dict[str, str]] = {
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
}


SortOrder = Literal["asc", "desc"]
SortOrderQuery = Annotated[SortOrder, Query(description="Sort order: asc or desc")]


def parse_sort_direction(sort_order: SortOrder) -> int:
    """The MongoDB direction (1/-1) of a sort order."""
    return -1 if sort_order == "desc" else 1


def get_sort_field(
    entity_type: Literal["projects", "scans", "project_scans"],
    sort_by: str,
    default: str = "created_at",
) -> str:
    """Get the validated MongoDB sort field path for an entity type."""
    fields = SORT_FIELDS.get(entity_type, {})
    return fields.get(sort_by, fields.get(default, default))
