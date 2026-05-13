"""
Components-delta computation: matches SBOM components across two scans by
purl with the version stripped, so that a version bump appears as
``version_changed`` rather than added+removed. License changes on an
otherwise-stable component appear as ``license_changed``. A component that
changed both version and license is emitted as a single ``version_changed``
entry with both transitions populated.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.schemas.scan_delta import (
    ComponentDeltaItem,
    DeltaCategory,
    ScanDeltaResponse,
    ScanDeltaTotals,
)
from app.services.analytics._delta_pagination import MAX_FETCH, paginate


def component_identity_key(comp: Dict) -> Tuple[str, str]:
    """Component identity for cross-scan matching.

    Strips version from purl so that a version bump appears as
    ``version_changed`` instead of added+removed.
    """
    purl = comp.get("purl")
    if purl and purl.startswith("pkg:"):
        # pkg:<type>/<namespace>/<name>@<version>?qualifiers#subpath
        body = purl[4:].split("@", 1)[0]  # drop version
        body = body.split("?", 1)[0].split("#", 1)[0]
        segments = body.split("/")
        if len(segments) == 1:
            return (segments[0], "")
        ptype = segments[0]
        name = unquote(segments[-1])
        namespace = "/".join(unquote(s) for s in segments[1:-1])
        type_key = f"{ptype}:{namespace}" if namespace else ptype
        return (type_key, name)

    return (comp.get("type") or "unknown", comp.get("name") or "")


async def _fetch_components(
    db: AsyncIOMotorDatabase,
    project_id: str,
    scan_id: str,
) -> List[dict]:
    cursor = db["dependencies"].find({"project_id": project_id, "scan_id": scan_id}).limit(MAX_FETCH)
    return [doc async for doc in cursor]


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


async def compute_components_delta(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    from_scan: str,
    to_scan: str,
    page: int,
    page_size: int,
    change: Optional[str],
) -> ScanDeltaResponse:
    """Compute the delta between two scans' components.

    Fetches dependency documents for both scans, matches them via the
    semantic identity key, and produces an envelope summarising
    added/removed/changed/unchanged counts plus a paginated item list.
    """
    from_docs = await _fetch_components(db, project_id, from_scan)
    to_docs = await _fetch_components(db, project_id, to_scan)

    from_map = {component_identity_key(d): d for d in from_docs}
    to_map = {component_identity_key(d): d for d in to_docs}

    added_keys = to_map.keys() - from_map.keys()
    removed_keys = from_map.keys() - to_map.keys()
    common_keys = to_map.keys() & from_map.keys()

    version_changed: List[ComponentDeltaItem] = []
    license_changed: List[ComponentDeltaItem] = []
    unchanged = 0
    for k in common_keys:
        f, t = from_map[k], to_map[k]
        v_diff = (f.get("version") or "") != (t.get("version") or "")
        l_diff = (f.get("license") or "") != (t.get("license") or "")
        if v_diff:
            version_changed.append(_to_changed(f, t, "version_changed"))
        elif l_diff:
            license_changed.append(_to_changed(f, t, "license_changed"))
        else:
            unchanged += 1

    items: List[ComponentDeltaItem] = []
    if change in (None, "all", "added"):
        items.extend(_to_added_or_removed(to_map[k], "added") for k in added_keys)
    if change in (None, "all", "removed"):
        items.extend(_to_added_or_removed(from_map[k], "removed") for k in removed_keys)
    if change in (None, "all", "changed"):
        items.extend(version_changed)
        items.extend(license_changed)

    # Sort by (change, name) with purl as a final tiebreaker so pagination is
    # deterministic regardless of set-iteration order.
    items.sort(key=lambda i: (i.change, i.name, i.purl or ""))

    paged, total_pages = paginate(items, page, page_size)

    return ScanDeltaResponse(
        from_scan_id=from_scan,
        to_scan_id=to_scan,
        project_id=project_id,
        category=DeltaCategory.COMPONENTS,
        totals=ScanDeltaTotals(
            added=len(added_keys),
            removed=len(removed_keys),
            changed=len(version_changed) + len(license_changed),
            unchanged=unchanged,
        ),
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        items=paged,
    )
