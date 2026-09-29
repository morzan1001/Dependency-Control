import contextlib
import re
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import BackgroundTasks, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers import (
    authorize_waiver_read,
    build_pagination_response,
    check_project_access,
    get_user_project_ids,
    parse_sort_direction,
)
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_404
from app.core.constants import PROJECT_ROLE_ADMIN, PROJECT_ROLE_EDITOR
from app.core.permissions import Permissions, has_permission
from app.models.finding import LOCATION_FINDING_TYPES
from app.models.match_signature import MatchSignature
from app.models.user import User
from app.repositories.base import and_filters
from app.models.waiver import Waiver
from app.repositories import ScanRepository, WaiverRepository
from app.repositories.waivers import non_expired_waiver_filter
from app.schemas.waiver import WaiverCreate, WaiverResponse, WaiverUpdate
from app.services.analytics.cache import get_analytics_cache
from app.services.stats import recalculate_all_projects, recalculate_project_stats
from app.services.waivers.matching import finding_rule_id, waiver_query


def _invalidate_analytics_cache() -> None:
    """Best-effort flush of the analytics TTL cache; waiver mutations change waived-derived counts."""
    with contextlib.suppress(Exception):
        get_analytics_cache().clear()


_MSG_NO_MATCHING_FINDING = (
    "Waiver criteria do not match any finding on the project's current build. "
    "Verify finding_id, finding_type, package_name and package_version. "
    "Use scope='rule' or 'file' to pre-emptively waive future findings."
)


# finding_id is not unique within a scan for these types (one document per affected
# component), so a waiver carrying only a finding_id blankets every one of them.
_BROAD_FINDING_ID_TYPES = ("license", "eol")

_MSG_NEEDS_PACKAGE_SCOPE = (
    "A {finding_type} finding_id is shared by every affected component, so this waiver would "
    "suppress all of them. Add package_name (and package_version) to scope it."
)


_MSG_SCOPE_NEEDS_RULE = (
    "A file or rule scope waiver needs its rule_id, or the finding_id of a finding this project stores, "
    "to name the rule it widens to."
)
_MSG_SCOPE_NEEDS_FILE = "A file scope waiver needs the file (package_name) it covers."
_MSG_SCOPE_NEEDS_LOCATION = "File and rule scope apply only to findings a scanner places in a file."


async def _resolve_widened_rule(waiver_in: WaiverCreate, db: AsyncIOMotorDatabase) -> None:
    """A file or rule scope widens to a rule, so it must name one: as given, else the rule a stored copy of the
    finding it was taken from reports."""
    if waiver_in.finding_type is not None and waiver_in.finding_type not in LOCATION_FINDING_TYPES:
        raise HTTPException(status_code=422, detail=_MSG_SCOPE_NEEDS_LOCATION)
    if waiver_in.scope == "file" and not waiver_in.package_name:
        raise HTTPException(status_code=422, detail=_MSG_SCOPE_NEEDS_FILE)
    if waiver_in.rule_id:
        return
    finding = None
    if waiver_in.project_id and waiver_in.finding_id:
        finding = await db.findings.find_one(
            {"project_id": waiver_in.project_id, "finding_id": waiver_in.finding_id}, {"details": 1}
        )
    waiver_in.rule_id = finding_rule_id(finding.get("details")) if finding else None
    if not waiver_in.rule_id:
        raise HTTPException(status_code=422, detail=_MSG_SCOPE_NEEDS_RULE)


def _reject_unscoped_broad_waiver(waiver_in: WaiverCreate) -> None:
    """Refuse a waiver whose criteria would blanket findings nobody picked."""
    if waiver_in.finding_type not in _BROAD_FINDING_ID_TYPES or waiver_in.package_name or not waiver_in.finding_id:
        return
    raise HTTPException(
        status_code=422,
        detail=_MSG_NEEDS_PACKAGE_SCOPE.format(finding_type=waiver_in.finding_type),
    )


async def _ensure_waiver_matches_finding(waiver_in: WaiverCreate, db: AsyncIOMotorDatabase) -> dict | None:
    """Reject finding-scope project waivers matching no finding on the head build; return the matched finding doc, or None when validation is skipped."""
    if not waiver_in.project_id:
        return None
    if waiver_in.scope != "finding":
        return None
    if waiver_in.vulnerability_id:
        return None

    project = await db.projects.find_one(
        {"_id": waiver_in.project_id}, {"latest_scan_id": 1, "default_branch": 1, "deleted_branches": 1}
    )
    if not project:
        return None
    head_scan_id = await ScanRepository(db).get_latest_active_scan_id(project)
    if not head_scan_id:
        return None

    probe = Waiver(**waiver_in.model_dump(), created_by="__validation__")
    finding_query = waiver_query(probe)
    if not finding_query:
        return None  # nothing concrete to validate against

    finding_query["scan_id"] = head_scan_id
    finding: dict | None = await db.findings.find_one(finding_query, {"match": 1, "type": 1, "component": 1})
    if finding is None:
        raise HTTPException(status_code=422, detail=_MSG_NO_MATCHING_FINDING)
    return finding


router = CustomAPIRouter()

_MSG_NOT_ENOUGH_PERMISSIONS = "Not enough permissions"
_MSG_WAIVER_NOT_FOUND = "Waiver not found"


async def _authorize_waiver_write(project_id: str | None, user: User, db: AsyncIOMotorDatabase) -> None:
    """A project waiver is written by a project editor, a global one by a waiver:manage holder."""
    if project_id:
        await check_project_access(project_id, user, db, required_role=PROJECT_ROLE_EDITOR)
    elif not has_permission(user.permissions, Permissions.WAIVER_MANAGE):
        raise HTTPException(status_code=403, detail="Only admins can manage global waivers")


@router.post("/", response_model=WaiverResponse, status_code=201, responses=RESP_AUTH)
async def create_waiver(
    waiver_in: WaiverCreate,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> Waiver:
    """Create a new waiver/exception for a vulnerability."""
    await _authorize_waiver_write(waiver_in.project_id, current_user, db)

    # Reject zombie and over-broad waivers early, before consuming a write and recalculating stats.
    _reject_unscoped_broad_waiver(waiver_in)
    if waiver_in.scope != "finding":
        await _resolve_widened_rule(waiver_in, db)
    matched_finding = await _ensure_waiver_matches_finding(waiver_in, db)

    waiver_repo = WaiverRepository(db)
    waiver = Waiver(**waiver_in.model_dump(), created_by=current_user.username)
    # Only a named finding is one location; criteria without a finding_id describe every finding they match.
    if matched_finding and matched_finding.get("match") and waiver_in.finding_id:
        waiver.match = MatchSignature(**matched_finding["match"])

    await waiver_repo.create(waiver)
    _invalidate_analytics_cache()

    if waiver.project_id:
        background_tasks.add_task(recalculate_project_stats, waiver.project_id, db)
    else:
        background_tasks.add_task(recalculate_all_projects, db, waiver)

    return waiver


@router.get("/", responses=RESP_AUTH)
async def list_waivers(
    db: DatabaseDep,
    current_user: CurrentUserDep,
    project_id: str | None = None,
    global_only: Annotated[bool, Query(description="Only return global waivers (project_id=None)")] = False,
    finding_id: str | None = None,
    package_name: str | None = None,
    search: Annotated[str | None, Query(description="Search in package name, reason, or finding ID")] = None,
    orphaned: Annotated[
        bool, Query(description="Only return orphaned waivers (evaluated but matching 0 findings)")
    ] = False,
    sort_by: Annotated[str, Query(description="Field to sort by")] = "created_at",
    sort_order: Annotated[str, Query(description="Sort order: asc or desc")] = "desc",
    skip: Annotated[int, Query(ge=0, description="Number of items to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=500, description="Number of items to return")] = 50,
) -> dict[str, Any]:
    """List waivers with pagination."""
    query: dict[str, Any] = {}

    scoped_project = None if global_only else project_id
    await authorize_waiver_read(scoped_project, current_user, db)

    if global_only or project_id:
        query["project_id"] = scoped_project
    elif not has_permission(current_user.permissions, Permissions.WAIVER_READ_ALL):
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
        orphaned_clause: dict[str, Any] = {
            "last_eval_scan_id": {"$ne": None},
            "last_match_count": 0,
            **non_expired_waiver_filter(now),
        }
        query = and_filters(query, orphaned_clause)

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
    # Refused before the read, so a caller with no waiver permission cannot probe which ids exist.
    await authorize_waiver_read(None, current_user, db)

    waiver = await WaiverRepository(db).get_by_id(waiver_id)
    if not waiver:
        raise HTTPException(status_code=404, detail=_MSG_WAIVER_NOT_FOUND)

    await authorize_waiver_read(waiver.project_id, current_user, db)
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

    await _authorize_waiver_write(waiver.project_id, current_user, db)

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
            background_tasks.add_task(recalculate_all_projects, db, updated)

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
        background_tasks.add_task(recalculate_all_projects, db, waiver)
