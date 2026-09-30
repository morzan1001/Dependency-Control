"""Components-delta: match SBOM components across two scans by version-free package identity,
so a version bump reads as ``version_changed`` (with both transitions) rather than
added+removed, and a license-only change reads as ``license_changed``.
"""

from __future__ import annotations

import asyncio

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.purl import package_identity
from app.repositories.base import find_window
from app.schemas.scan_delta import (
    ComponentDeltaItem,
    DeltaCategory,
    ScanDeltaResponse,
    ScanDeltaTotals,
)
from app.services.analytics._delta_pagination import MAX_FETCH, by_side, delta_truncation, pair_versions

# Served by the {scan_id, name, version} index, so a capped side is cut at the same point in the
# component namespace on both sides instead of at two arbitrary points in natural order.
_SIDE_SORT: list[tuple[str, int]] = [("name", 1), ("version", 1)]


async def _fetch_components(
    db: AsyncIOMotorDatabase,
    project_id: str,
    scan_id: str,
) -> tuple[list[dict], int]:
    query = {"project_id": project_id, "scan_id": scan_id}
    return await find_window(db["dependencies"], query, MAX_FETCH, sort=_SIDE_SORT)


def _one_per_version(rows: list[dict]) -> list[dict]:
    """Qualifier variants of one version (arch, classifier) are the same version."""
    return list({row.get("version") or "": row for row in rows}.values())


def _to_added_or_removed(doc: dict, change: str) -> ComponentDeltaItem:
    return ComponentDeltaItem(
        change=change,
        name=doc.get("name") or "",
        purl=doc.get("purl"),
        version=doc.get("version"),
        license=doc.get("license"),
    )


def _to_changed(from_doc: dict, to_doc: dict, change: str) -> ComponentDeltaItem:
    return ComponentDeltaItem(
        change=change,
        name=to_doc.get("name") or from_doc.get("name") or "",
        purl=to_doc.get("purl") or from_doc.get("purl"),
        from_version=from_doc.get("version"),
        to_version=to_doc.get("version"),
        from_license=from_doc.get("license"),
        to_license=to_doc.get("license"),
    )


async def compare_components(
    db: AsyncIOMotorDatabase, *, project_id: str, from_scan: str, to_scan: str
) -> ScanDeltaResponse:
    """Every component change between two scans, sorted, with totals and coverage."""
    (from_docs, from_total), (to_docs, to_total) = await asyncio.gather(
        _fetch_components(db, project_id, from_scan), _fetch_components(db, project_id, to_scan)
    )

    groups = by_side(
        lambda d: package_identity(d.get("purl"), d.get("name") or "", d.get("type"), d.get("group")),
        from_docs,
        to_docs,
    )
    added: list[ComponentDeltaItem] = []
    removed: list[ComponentDeltaItem] = []
    changed: list[ComponentDeltaItem] = []
    unchanged = 0
    for from_rows, to_rows in groups.values():
        pairs, gone, new = pair_versions(_one_per_version(from_rows), _one_per_version(to_rows))
        added += (_to_added_or_removed(d, "added") for d in new)
        removed += (_to_added_or_removed(d, "removed") for d in gone)
        for f, t in pairs:
            if (f.get("version") or "") != (t.get("version") or ""):
                changed.append(_to_changed(f, t, "version_changed"))
            elif (f.get("license") or "") != (t.get("license") or ""):
                changed.append(_to_changed(f, t, "license_changed"))
            else:
                unchanged += 1

    items = [*added, *removed, *changed]
    # Sort with purl and version tiebreakers so pagination does not depend on fetch order.
    items.sort(key=lambda i: (i.change, i.name, i.purl or "", i.version or ""))

    return ScanDeltaResponse(
        from_scan_id=from_scan,
        to_scan_id=to_scan,
        project_id=project_id,
        category=DeltaCategory.COMPONENTS,
        totals=ScanDeltaTotals(
            added=len(added),
            removed=len(removed),
            changed=len(changed),
            unchanged=unchanged,
        ),
        items=items,
        truncation=delta_truncation(
            MAX_FETCH,
            from_compared=len(from_docs),
            from_total=from_total,
            to_compared=len(to_docs),
            to_total=to_total,
        ),
    )
