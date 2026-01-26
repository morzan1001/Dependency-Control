from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.api.v1.endpoints.projects import check_project_access
from app.db.mongodb import get_database
from app.models.user import User
from app.models.waiver import Waiver
from app.schemas.waiver import WaiverCreate, WaiverResponse
from app.services.stats import recalculate_all_projects, recalculate_project_stats

router = APIRouter()


@router.post("/", response_model=WaiverResponse, status_code=201)
async def create_waiver(
    waiver_in: WaiverCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Create a new waiver/exception for a vulnerability.
    """
    if waiver_in.project_id:
        # Check if user has access to the project (editor or admin)
        await check_project_access(
            waiver_in.project_id, current_user, db, required_role="editor"
        )
    else:
        # Global waiver requires superuser or specific permission
        if (
            "*" not in current_user.permissions
            and "waiver:manage" not in current_user.permissions
        ):
            raise HTTPException(
                status_code=403, detail="Only admins can create global waivers"
            )

    waiver = Waiver(**waiver_in.model_dump(), created_by=current_user.username)

    await db.waivers.insert_one(waiver.model_dump(by_alias=True))

    # Trigger stats recalculation
    if waiver.project_id:
        background_tasks.add_task(recalculate_project_stats, waiver.project_id, db)
    else:
        background_tasks.add_task(recalculate_all_projects, db)

    return waiver


@router.get("/", response_model=Dict[str, Any])
async def list_waivers(
    project_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    package_name: Optional[str] = None,
    search: Optional[str] = Query(None, description="Search in package name, reason, or finding ID"),
    sort_by: str = Query("created_at", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(50, ge=1, le=500, description="Number of items to return"),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List waivers with pagination.
    """
    query: Dict[str, Any] = {}

    # Permission check logic
    has_read_all = (
        "*" in current_user.permissions or "waiver:read_all" in current_user.permissions
    )
    has_read_own = "waiver:read" in current_user.permissions

    if not (has_read_all or has_read_own):
        raise HTTPException(status_code=403, detail="Not enough permissions")

    if project_id:
        # Check access to specific project
        await check_project_access(project_id, current_user, db, required_role="viewer")
        query["project_id"] = project_id
    elif not has_read_all:
        # User can only see waivers from their projects + global waivers
        # 1. Get all project IDs user has access to
        user_teams = await db.teams.find(
            {"members.user_id": str(current_user.id)}
        ).to_list(1000)
        team_ids = [t["_id"] for t in user_teams]

        projects = await db.projects.find(
            {
                "$or": [
                    {"owner_id": str(current_user.id)},
                    {"members.user_id": str(current_user.id)},
                    {"team_id": {"$in": team_ids}},
                ]
            },
            {"_id": 1},
        ).to_list(10000)

        accessible_project_ids = [p["_id"] for p in projects]

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
        search_query = {"$regex": search, "$options": "i"}
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

    # Get total count
    total = await db.waivers.count_documents(query)

    # Sort direction
    sort_direction = 1 if sort_order == "asc" else -1

    # Fetch paginated results
    cursor = db.waivers.find(query).sort(sort_by, sort_direction).skip(skip).limit(limit)
    waivers = await cursor.to_list(limit)

    return {
        "items": [Waiver(**w).model_dump() for w in waivers],
        "total": total,
        "page": (skip // limit) + 1,
        "size": limit,
        "pages": (total + limit - 1) // limit if limit > 0 else 0,
    }


@router.delete("/{waiver_id}", status_code=204)
async def delete_waiver(
    waiver_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    waiver_data = await db.waivers.find_one({"_id": waiver_id})
    if not waiver_data:
        raise HTTPException(status_code=404, detail="Waiver not found")

    waiver = Waiver(**waiver_data)

    if waiver.project_id:
        if (
            "*" not in current_user.permissions
            and "waiver:delete" not in current_user.permissions
        ):
            await check_project_access(
                waiver.project_id, current_user, db, required_role="admin"
            )
    else:
        if (
            "*" not in current_user.permissions
            and "waiver:manage" not in current_user.permissions
            and "waiver:delete" not in current_user.permissions
        ):
            raise HTTPException(status_code=403, detail="Not enough permissions")

    await db.waivers.delete_one({"_id": waiver_id})

    # Trigger stats recalculation
    if waiver.project_id:
        background_tasks.add_task(recalculate_project_stats, waiver.project_id, db)
    else:
        background_tasks.add_task(recalculate_all_projects, db)
