"""Row builder for the components inventory (dependencies + license + lifecycle)."""

import re
from collections.abc import AsyncIterator
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.finding import FindingType
from app.models.project import Scan
from app.repositories.dependencies import DependencyRepository
from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.repositories.findings import FindingRepository
from app.schemas.inventory import ComponentItem

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
_ENRICHMENT_CHUNK = 500

_DEP_PROJECTION = {"name": 1, "version": 1, "type": 1, "license": 1, "license_category": 1, "direct": 1, "purl": 1}


async def _lifecycle_by_component(db: AsyncIOMotorDatabase, scan_id: str) -> dict[str, dict[str, Any]]:
    lifecycle: dict[str, dict[str, Any]] = {}
    cursor = FindingRepository(db).collection.find(
        {"scan_id": scan_id, "type": {"$in": [FindingType.EOL.value, FindingType.OUTDATED.value]}},
        {"component": 1, "version": 1, "type": 1, "details.latest_version": 1},
    )
    async for doc in cursor:
        key = f"{doc.get('component')}@{doc.get('version')}"
        entry = lifecycle.setdefault(key, {})
        if doc.get("type") == FindingType.EOL.value:
            entry["eol"] = True
        else:
            entry["outdated"] = True
            entry["latest_version"] = (doc.get("details") or {}).get("latest_version")
    return lifecycle


async def _enrichment_by_purl(db: AsyncIOMotorDatabase, purls: list[str]) -> dict[str, dict[str, Any]]:
    repo = DependencyEnrichmentRepository(db)
    result: dict[str, dict[str, Any]] = {}
    for start in range(0, len(purls), _ENRICHMENT_CHUNK):
        result.update(await repo.get_many_by_purls(purls[start : start + _ENRICHMENT_CHUNK]))
    return result


def _to_item(
    doc: dict[str, Any],
    lifecycle: dict[str, dict[str, Any]],
    enrichment: dict[str, dict[str, Any]],
) -> ComponentItem:
    enriched = enrichment.get(doc.get("purl") or "", {})
    life = lifecycle.get(f"{doc.get('name')}@{doc.get('version')}", {})
    return ComponentItem(
        name=doc.get("name", ""),
        version=doc.get("version", ""),
        latest_version=life.get("latest_version"),
        ecosystem=doc.get("type") or "unknown",
        license=doc.get("license") or enriched.get("license"),
        license_category=doc.get("license_category") or enriched.get("license_category"),
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


def _effective_license(doc: dict[str, Any], enrichment: dict[str, dict[str, Any]]) -> str:
    enriched = enrichment.get(doc.get("purl") or "", {})
    return doc.get("license") or enriched.get("license") or ""


async def _license_sorted_page(
    db: AsyncIOMotorDatabase,
    deps: DependencyRepository,
    query: dict[str, Any],
    reverse: bool,
    page: int,
    page_size: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    # The displayed license falls back to the enrichment doc, so a Mongo-side
    # sort on dependency.license alone would misorder enrichment-only licenses.
    all_docs = await deps.collection.find(query, _DEP_PROJECTION).to_list(None)
    enrichment = await _enrichment_by_purl(db, [d["purl"] for d in all_docs if d.get("purl")])
    all_docs.sort(key=lambda d: (_effective_license(d, enrichment), d.get("name", "")), reverse=reverse)
    start = (page - 1) * page_size
    return all_docs[start : start + page_size], enrichment


async def get_components_page(
    db: AsyncIOMotorDatabase,
    scan: Scan,
    *,
    page: int,
    page_size: int,
    search: str | None,
    sort_by: str,
    sort_order: str,
) -> tuple[list[ComponentItem], int]:
    deps = DependencyRepository(db)
    query = _query(scan.id, search)
    total = await deps.count(query)
    sort_field = sort_by if sort_by in _SORT_FIELDS else "name"
    direction = -1 if sort_order == "desc" else 1

    if sort_field == "license":
        docs, enrichment = await _license_sorted_page(db, deps, query, direction == -1, page, page_size)
    else:
        sort_spec = [(sort_field, direction)] if sort_field == "name" else [(sort_field, direction), ("name", 1)]
        cursor = (
            deps.collection.find(query, _DEP_PROJECTION).sort(sort_spec).skip((page - 1) * page_size).limit(page_size)
        )
        docs = await cursor.to_list(page_size)
        enrichment = await _enrichment_by_purl(db, [d["purl"] for d in docs if d.get("purl")])

    lifecycle = await _lifecycle_by_component(db, scan.id)
    return [_to_item(d, lifecycle, enrichment) for d in docs], total


async def iter_component_rows(db: AsyncIOMotorDatabase, scan: Scan) -> AsyncIterator[dict[str, Any]]:
    deps = DependencyRepository(db)
    lifecycle = await _lifecycle_by_component(db, scan.id)
    cursor = deps.collection.find(_query(scan.id, None), _DEP_PROJECTION).sort("name", 1)
    batch: list[dict[str, Any]] = []
    async for doc in cursor:
        batch.append(doc)
        if len(batch) >= _ENRICHMENT_CHUNK:
            for row in await _rows_for_batch(db, batch, lifecycle):
                yield row
            batch = []
    for row in await _rows_for_batch(db, batch, lifecycle):
        yield row


async def _rows_for_batch(
    db: AsyncIOMotorDatabase,
    batch: list[dict[str, Any]],
    lifecycle: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not batch:
        return []
    enrichment = await _enrichment_by_purl(db, [d["purl"] for d in batch if d.get("purl")])
    return [_to_item(doc, lifecycle, enrichment).model_dump() for doc in batch]
