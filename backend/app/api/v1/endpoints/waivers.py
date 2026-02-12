import re
from typing import Annotated, Any, Dict, Optional

from fastapi import BackgroundTasks, HTTPException, Query

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
from app.schemas.waiver import WaiverCreate, WaiverResponse
from app.services.stats import recalculate_all_projects, recalculate_project_stats

router = CustomAPIRouter()


@router.post("/", response_model=WaiverResponse, status_code=201, responses={**RESP_AUTH})
async def create_waiver(
    waiver_in: WaiverCreate,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    current_user: CurrentUserDep,
):
    """
    Create a new waiver/exception for a vulnerability.
    """
    if waiver_in.project_id:
        # Check if user has access to the project (editor or admin)
        await check_project_access(waiver_in.project_id, current_user, db, required_role=PROJECT_ROLE_EDITOR)
    else:
        # Global waiver requires waiver:manage permission
        if not has_permission(current_user.permissions, Permissions.WAIVER_MANAGE):
            raise HTTPException(status_code=403, detail="Only admins can create global waivers")

    waiver_repo = WaiverRepository(db)
    waiver = Waiver(**waiver_in.model_dump(), created_by=current_user.username)

    await waiver_repo.create(waiver)

    # Trigger stats recalculation
    if waiver.project_id:
        background_tasks.add_task(recalculate_project_stats, waiver.project_id, db)
    else:
        background_tasks.add_task(recalculate_all_projects, db)

    return waiver


@router.get("/", response_model=Dict[str, Any], responses={**RESP_AUTH})
async def list_waivers(
    db: DatabaseDep,
    current_user: CurrentUserDep,
    project_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    package_name: Optional[str] = None,
    search: Annotated[Optional[str], Query(description="Search in package name, reason, or finding ID")] = None,
    sort_by: Annotated[str, Query(description="Field to sort by")] = "created_at",
    sort_order: Annotated[str, Query(description="Sort order: asc or desc")] = "desc",
    skip: Annotated[int, Query(ge=0, description="Number of items to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=500, description="Number of items to return")] = 50,
):
    """
    List waivers with pagination.
    """
    query: Dict[str, Any] = {}

    # Permission check logic
    has_read_all = has_permission(current_user.permissions, Permissions.WAIVER_READ_ALL)
    has_read_own = has_permission(current_user.permissions, Permissions.WAIVER_READ)

    if not (has_read_all or has_read_own):
        raise HTTPException(status_code=403, detail="Not enough permissions")

    if project_id:
        # Check access to specific project
        await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_VIEWER)
        query["project_id"] = project_id
    elif not has_read_all:
        # User can only see waivers from their projects + global waivers
        accessible_project_ids = await get_user_project_ids(current_user, db)

        # Query: Global waivers (project_id=None) OR waivers in accessible projects
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
        # Need to combine with existing $or if present
        search_or = [
            {"package_name": search_query},
            {"reason": search_query},
            {"finding_id": search_query},
        ]
        if "$or" in query:
            # Wrap existing query with $and to combine with search
            query = {"$and": [query, {"$or": search_or}]}
        else:
            query["$or"] = search_or

    waiver_repo = WaiverRepository(db)

    # Get total count
    total = await waiver_repo.count(query)

    # Sort direction
    sort_direction = parse_sort_direction(sort_order)

    # Fetch paginated results
    waivers = await waiver_repo.find_many(query, skip=skip, limit=limit, sort_by=sort_by, sort_order=sort_direction)

    items = [Waiver(**w).model_dump() for w in waivers]
    return build_pagination_response(items, total, skip, limit)


@router.delete("/{waiver_id}", status_code=204, responses={**RESP_AUTH_404})
async def delete_waiver(
    waiver_id: str,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> None:
    """
    Delete a waiver.

    For project waivers: requires waiver:delete permission or admin role on the project.
    For global waivers: requires waiver:manage or waiver:delete permission.
    """
    waiver_repo = WaiverRepository(db)
    waiver = await waiver_repo.get_by_id(waiver_id)
    if not waiver:
        raise HTTPException(status_code=404, detail="Waiver not found")

    if waiver.project_id:
        if not has_permission(current_user.permissions, Permissions.WAIVER_DELETE):
            await check_project_access(waiver.project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)
    else:
        if not has_permission(current_user.permissions, [Permissions.WAIVER_MANAGE, Permissions.WAIVER_DELETE]):
            raise HTTPException(status_code=403, detail="Not enough permissions")

    await waiver_repo.delete(waiver_id)

    # Trigger stats recalculation
    if waiver.project_id:
        background_tasks.add_task(recalculate_project_stats, waiver.project_id, db)
    else:
        background_tasks.add_task(recalculate_all_projects, db)

    return None
