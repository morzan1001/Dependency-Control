from datetime import datetime, timezone
import re
from typing import Annotated, Any, Dict, Optional

from fastapi import BackgroundTasks, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_404
from app.api.v1.helpers import (
    build_pagination_response,
    check_project_access,
    get_user_project_ids,
    parse_sort_direction,
)
from app.core.constants import (
    PROJECT_ROLE_ADMIN,
    PROJECT_ROLE_EDITOR,
    PROJECT_ROLE_VIEWER,
)
from app.core.permissions import Permissions, has_permission
from app.models.waiver import Waiver
from app.repositories import WaiverRepository
from app.schemas.waiver import WaiverCreate, WaiverResponse, WaiverUpdate
from app.services.analytics.cache import get_analytics_cache
from app.services.stats import _build_waiver_query, recalculate_all_projects, recalculate_project_stats


def _invalidate_analytics_cache() -> None:
    """Best-effort flush of the analytics TTL cache; waiver mutations change waived-derived counts."""
    try:
        get_analytics_cache().clear()
    except Exception:  # pragma: no cover
        pass


_MSG_NO_MATCHING_FINDING = (
    "Waiver criteria do not match any finding in the project's latest scan. "
    "Verify finding_id, finding_type, package_name and package_version. "
    "Use scope='rule' or 'file' to pre-emptively waive future findings."
)


async def _ensure_waiver_matches_finding(waiver_in: WaiverCreate, db: AsyncIOMotorDatabase) -> Optional[dict]:
    """Reject finding-scope project waivers matching no finding in the latest scan; return the matched finding doc, or None when validation is skipped."""
    if not waiver_in.project_id:
        return None
    if waiver_in.scope != "finding":
        return None
    if waiver_in.vulnerability_id:
        return None

    project = await db.projects.find_one({"_id": waiver_in.project_id}, {"latest_scan_id": 1})
    if not project:
        return None
    latest_scan_id = project.get("latest_scan_id")
    if not latest_scan_id:
        return None

    probe = Waiver(**waiver_in.model_dump(), created_by="__validation__")
    finding_query = _build_waiver_query(probe)
    if not finding_query:
        return None  # nothing concrete to validate against

    finding_query["scan_id"] = latest_scan_id
    finding: Optional[dict] = await db.findings.find_one(finding_query, {"match": 1, "type": 1, "component": 1})
    if finding is None:
        raise HTTPException(status_code=422, detail=_MSG_NO_MATCHING_FINDING)
    return finding


router = CustomAPIRouter()

_MSG_NOT_ENOUGH_PERMISSIONS = "Not enough permissions"
_MSG_WAIVER_NOT_FOUND = "Waiver not found"


@router.post("/", response_model=WaiverResponse, status_code=201, responses=RESP_AUTH)
async def create_waiver(
    waiver_in: WaiverCreate,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> Waiver:
    """Create a new waiver/exception for a vulnerability."""
    if waiver_in.project_id:
        await check_project_access(waiver_in.project_id, current_user, db, required_role=PROJECT_ROLE_EDITOR)
    else:
        if not has_permission(current_user.permissions, Permissions.WAIVER_MANAGE):
            raise HTTPException(status_code=403, detail="Only admins can create global waivers")

    # Reject zombie waivers early, before consuming a write and recalculating stats.
    matched_finding = await _ensure_waiver_matches_finding(waiver_in, db)

    if waiver_in.scope == "rule" and not waiver_in.rule_id and waiver_in.finding_id and waiver_in.package_name:
        from app.services.stats import _extract_rule_prefix

        rule_prefix = _extract_rule_prefix(waiver_in.finding_id, waiver_in.package_name)
        if rule_prefix:
            # Strip scanner prefix (e.g. "BEARER-rule_name" → "rule_name")
            parts = rule_prefix.split("-", 1)
            waiver_in.rule_id = parts[1] if len(parts) > 1 else rule_prefix

    waiver_repo = WaiverRepository(db)
    waiver = Waiver(**waiver_in.model_dump(), created_by=current_user.username)
    if matched_finding and matched_finding.get("match"):
        from app.models.match_signature import MatchSignature

        waiver.match = MatchSignature(**matched_finding["match"])

    await waiver_repo.create(waiver)
    _invalidate_analytics_cache()

    if waiver.project_id:
        background_tasks.add_task(recalculate_project_stats, waiver.project_id, db)
    else:
        background_tasks.add_task(recalculate_all_projects, db)

    return waiver


@router.get("/", responses=RESP_AUTH)
async def list_waivers(
    db: DatabaseDep,
    current_user: CurrentUserDep,
    project_id: Optional[str] = None,
    global_only: Annotated[bool, Query(description="Only return global waivers (project_id=None)")] = False,
    finding_id: Optional[str] = None,
    package_name: Optional[str] = None,
    search: Annotated[Optional[str], Query(description="Search in package name, reason, or finding ID")] = None,
    orphaned: Annotated[bool, Query(description="Only return orphaned waivers (evaluated but matching 0 findings)")] = False,
    sort_by: Annotated[str, Query(description="Field to sort by")] = "created_at",
    sort_order: Annotated[str, Query(description="Sort order: asc or desc")] = "desc",
    skip: Annotated[int, Query(ge=0, description="Number of items to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=500, description="Number of items to return")] = 50,
) -> Dict[str, Any]:
    """List waivers with pagination."""
    query: Dict[str, Any] = {}

    has_read_all = has_permission(current_user.permissions, Permissions.WAIVER_READ_ALL)
    has_read_own = has_permission(current_user.permissions, Permissions.WAIVER_READ)

    if not (has_read_all or has_read_own):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    if global_only:
        if not (has_read_all or has_permission(current_user.permissions, Permissions.WAIVER_MANAGE)):
            raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)
        query["project_id"] = None
    elif project_id:
        await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_VIEWER)
        query["project_id"] = project_id
    elif not has_read_all:
        accessible_project_ids = await get_user_project_ids(current_user, db)

        query["$or"] = [
            {"project_id": None},
            {"project_id": {"$in": accessible_project_ids}},
        ]

    if finding_id:
        query["finding_id"] = finding_id

    if package_name:
        query["package_name"] = package_name

    if search:
        search_query = {"$regex": re.escape(search), "$options": "i"}
        search_or = [
            {"package_name": search_query},
            {"reason": search_query},
            {"finding_id": search_query},
        ]
        if "$or" in query:
            # $and-wrap so an existing $or is preserved.
            query = {"$and": [query, {"$or": search_or}]}
        else:
            query["$or"] = search_or

    if orphaned:
        # Mirror the UI badge: evaluated, suppressing 0 findings, and not expired.
        now = datetime.now(timezone.utc)
        orphaned_clause: Dict[str, Any] = {
            "last_eval_scan_id": {"$ne": None},
            "last_match_count": 0,
            "$or": [
                {"expiration_date": {"$exists": False}},
                {"expiration_date": None},
                {"expiration_date": {"$gt": now}},
            ],
        }
        query = {"$and": [query, orphaned_clause]} if query else orphaned_clause

    waiver_repo = WaiverRepository(db)

    total = await waiver_repo.count(query)
    sort_direction = parse_sort_direction(sort_order)
    waivers = await waiver_repo.find_many(query, skip=skip, limit=limit, sort_by=sort_by, sort_order=sort_direction)

    items = [Waiver(**w).model_dump() for w in waivers]
    return build_pagination_response(items, total, skip, limit)


@router.get("/{waiver_id}", response_model=WaiverResponse, responses=RESP_AUTH_404)
async def get_waiver(
    waiver_id: str,
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> Waiver:
    """Retrieve a single waiver by ID."""
    has_read_all = has_permission(current_user.permissions, Permissions.WAIVER_READ_ALL)
    has_read_own = has_permission(current_user.permissions, Permissions.WAIVER_READ)

    if not (has_read_all or has_read_own):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    waiver_repo = WaiverRepository(db)
    waiver = await waiver_repo.get_by_id(waiver_id)
    if not waiver:
        raise HTTPException(status_code=404, detail=_MSG_WAIVER_NOT_FOUND)

    if waiver.project_id:
        await check_project_access(waiver.project_id, current_user, db, required_role=PROJECT_ROLE_VIEWER)
    else:
        if not (has_read_all or has_permission(current_user.permissions, Permissions.WAIVER_MANAGE)):
            raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    return waiver


@router.patch("/{waiver_id}", response_model=WaiverResponse, responses=RESP_AUTH_404)
async def update_waiver(
    waiver_id: str,
    waiver_in: WaiverUpdate,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> Waiver:
    """Update a waiver (reason, status, expiration_date)."""
    waiver_repo = WaiverRepository(db)
    waiver = await waiver_repo.get_by_id(waiver_id)
    if not waiver:
        raise HTTPException(status_code=404, detail=_MSG_WAIVER_NOT_FOUND)

    if waiver.project_id:
        await check_project_access(waiver.project_id, current_user, db, required_role=PROJECT_ROLE_EDITOR)
    else:
        if not has_permission(current_user.permissions, Permissions.WAIVER_MANAGE):
            raise HTTPException(status_code=403, detail="Only admins can update global waivers")

    update_data = waiver_in.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    updated = await waiver_repo.update(waiver_id, update_data)
    if not updated:
        raise HTTPException(status_code=404, detail=_MSG_WAIVER_NOT_FOUND)
    _invalidate_analytics_cache()

    # Recalculate when a field that gates waiver application (status/expiration) changes.
    if {"status", "expiration_date"} & update_data.keys():
        if updated.project_id:
            background_tasks.add_task(recalculate_project_stats, updated.project_id, db)
        else:
            background_tasks.add_task(recalculate_all_projects, db)

    return updated


@router.delete("/{waiver_id}", status_code=204, responses=RESP_AUTH_404)
async def delete_waiver(
    waiver_id: str,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> None:
    """Delete a waiver."""
    waiver_repo = WaiverRepository(db)
    waiver = await waiver_repo.get_by_id(waiver_id)
    if not waiver:
        raise HTTPException(status_code=404, detail=_MSG_WAIVER_NOT_FOUND)

    if waiver.project_id:
        if not has_permission(current_user.permissions, Permissions.WAIVER_DELETE):
            await check_project_access(waiver.project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)
    else:
        if not has_permission(current_user.permissions, [Permissions.WAIVER_MANAGE, Permissions.WAIVER_DELETE]):
            raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    await waiver_repo.delete(waiver_id)
    _invalidate_analytics_cache()

    if waiver.project_id:
        background_tasks.add_task(recalculate_project_stats, waiver.project_id, db)
    else:
        background_tasks.add_task(recalculate_all_projects, db)

    return None
