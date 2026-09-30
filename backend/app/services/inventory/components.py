"""Row builder for the components inventory (dependencies + license + lifecycle)."""

import re
from collections.abc import AsyncIterator
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.finding import FindingType
from app.models.project import Scan
from app.repositories.dependencies import DependencyRepository
from app.repositories.findings import FindingRepository
from app.schemas.inventory import ComponentItem
from app.services.aggregation.cross_link import is_ahead_of_default

COMPONENT_COLUMNS = [
    "name",
    "version",
    "latest_version",
    "ecosystem",
    "license",
    "license_category",
    "direct",
    "eol",
    "outdated",
    "purl",
]

_SORT_FIELDS = {"name", "version", "type", "license", "direct"}

_DEP_PROJECTION = {"name": 1, "version": 1, "type": 1, "license": 1, "license_category": 1, "direct": 1, "purl": 1}


async def _lifecycle_by_component(db: AsyncIOMotorDatabase, scan_id: str) -> dict[str, dict[str, Any]]:
    lifecycle: dict[str, dict[str, Any]] = {}
    docs = FindingRepository(db).iterate_raw(
        {"scan_id": scan_id, "type": {"$in": [FindingType.EOL.value, FindingType.OUTDATED.value]}},
        {"component": 1, "version": 1, "type": 1, "details.fixed_version": 1, "details.ahead_of_default": 1},
    )
    async for doc in docs:
        if is_ahead_of_default(doc["type"], doc.get("details")):
            continue
        key = f"{doc.get('component')}@{doc.get('version')}"
        entry = lifecycle.setdefault(key, {})
        if doc.get("type") == FindingType.EOL.value:
            entry["eol"] = True
        else:
            entry["outdated"] = True
            # The lifecycle normalizer stores the newest version as fixed_version.
            entry["latest_version"] = (doc.get("details") or {}).get("fixed_version")
    return lifecycle


def _to_item(doc: dict[str, Any], lifecycle: dict[str, dict[str, Any]]) -> ComponentItem:
    life = lifecycle.get(f"{doc.get('name')}@{doc.get('version')}", {})
    return ComponentItem(
        name=doc.get("name", ""),
        version=doc.get("version", ""),
        latest_version=life.get("latest_version"),
        ecosystem=doc.get("type") or "unknown",
        # The scan's own record is authoritative; the estate-wide enrichment describes other scans too.
        license=doc.get("license") or None,
        license_category=doc.get("license_category"),
        direct=bool(doc.get("direct")),
        eol=bool(life.get("eol")),
        outdated=bool(life.get("outdated")),
        purl=doc.get("purl"),
    )


def _query(scan_id: str, search: str | None) -> dict[str, Any]:
    query: dict[str, Any] = {"scan_id": scan_id}
    if search:
        query["name"] = {"$regex": re.escape(search), "$options": "i"}
    return query


async def get_components_page(
    db: AsyncIOMotorDatabase,
    scan: Scan,
    *,
    page: int,
    page_size: int,
    search: str | None,
    sort_by: str,
    direction: int,
) -> tuple[list[ComponentItem], int]:
    deps = DependencyRepository(db)
    query = _query(scan.id, search)
    total = await deps.count(query)
    sort_field = sort_by if sort_by in _SORT_FIELDS else "name"

    # The unique (scan_id, name, version, purl) index serves the name sort in either direction;
    # the other sorts are blocking anyway, so a unique tail costs nothing.
    sort_spec = (
        [("name", direction), ("version", direction), ("purl", direction)]
        if sort_field == "name"
        else [(sort_field, direction), ("name", 1), ("version", 1), ("_id", 1)]
    )
    cursor = deps.collection.find(query, _DEP_PROJECTION).sort(sort_spec).skip((page - 1) * page_size).limit(page_size)
    docs = await cursor.to_list(page_size)

    lifecycle = await _lifecycle_by_component(db, scan.id)
    return [_to_item(d, lifecycle) for d in docs], total


async def iter_component_rows(db: AsyncIOMotorDatabase, scan: Scan) -> AsyncIterator[dict[str, Any]]:
    lifecycle = await _lifecycle_by_component(db, scan.id)
    async for doc in DependencyRepository(db).iterate_raw(_query(scan.id, None), _DEP_PROJECTION, [("name", 1)]):
        yield _to_item(doc, lifecycle).model_dump()
