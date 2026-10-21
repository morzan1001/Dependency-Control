import unicodedata
from collections.abc import Collection, Sequence
from typing import Annotated, Any, Literal

from fastapi import Query
from pymongo.collation import Collation, CollationStrength

CASE_INSENSITIVE = Collation(locale="en", strength=CollationStrength.SECONDARY)


def case_insensitive_key(text: str) -> tuple[str, str]:
    """Case and combining accents decide only between otherwise equal texts, as under CASE_INSENSITIVE."""
    base = "".join(c for c in unicodedata.normalize("NFD", text) if not unicodedata.combining(c))
    return base.casefold(), text


# $toLower folds ASCII only; the letters and combining marks below U+0370 fold through this table.
_FOLDS = [{"f": c, "t": folded} for c in map(chr, range(0x80, 0x370)) if (folded := case_insensitive_key(c)[0]) != c]


def _folded_expr(text: str) -> dict[str, Any]:
    replaced = {
        "$reduce": {
            "input": {"$literal": _FOLDS},
            "initialValue": text,
            "in": {"$replaceAll": {"input": "$$value", "find": "$$this.f", "replacement": "$$this.t"}},
        }
    }
    return {"$toLower": {"$cond": [{"$regexMatch": {"input": text, "regex": "[\u0080-\u036f]"}}, replaced, text]}}


# Digit runs up to this long compare by value, as under a numericOrdering collation.
_NUMBER_WIDTH = 20


def _numbered_expr(text: dict[str, Any]) -> dict[str, Any]:
    pad = {"$max": [0, {"$subtract": [_NUMBER_WIDTH, {"$strLenCP": "$$this.match"}]}]}
    padded = {"$concat": [{"$substrCP": ["0" * _NUMBER_WIDTH, 0, pad]}, "$$this.match"]}
    return {
        "$reduce": {
            "input": {"$regexFindAll": {"input": text, "regex": "[0-9]+|[^0-9]+"}},
            "initialValue": "",
            "in": {
                "$concat": [
                    "$$value",
                    {"$cond": [{"$regexMatch": {"input": "$$this.match", "regex": "^[0-9]"}}, padded, "$$this.match"]},
                ]
            },
        }
    }


def case_insensitive_sort(
    order: Sequence[tuple[str, int]], text_fields: Collection[str], numbered_fields: Collection[str] = ()
) -> list[dict[str, Any]]:
    """case_insensitive_key's order as pipeline stages, for reads a query collation would take off their indexes."""
    folded = {
        f"_folded.{field}": _numbered_expr(_folded_expr(f"${field}"))
        if field in numbered_fields
        else _folded_expr(f"${field}")
        for field, _ in order
        if field in text_fields
    }
    spec: dict[str, int] = {}
    for field, direction in order:
        if field in text_fields:
            spec.setdefault(f"_folded.{field}", direction)
        spec.setdefault(field, direction)
    return [{"$addFields": folded}, {"$sort": spec}]


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
    return -1 if sort_order == "desc" else 1


def get_sort_field(
    entity_type: Literal["projects", "scans", "project_scans"],
    sort_by: str,
    default: str = "created_at",
) -> str:
    fields = SORT_FIELDS.get(entity_type, {})
    return fields.get(sort_by, fields.get(default, default))
