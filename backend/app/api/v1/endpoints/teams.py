import logging
import re
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import Depends, HTTPException, status

from app.api.router import CustomAPIRouter
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.api.v1.helpers import (
    build_team_enrichment_pipeline,
    check_team_access,
    fetch_and_enrich_team,
    find_member_in_team,
    get_member_role,
    get_team_with_access,
)
from app.core.constants import TEAM_ROLE_OWNER
from app.core.permissions import has_permission
from app.db.mongodb import get_database
from app.models.team import Team, TeamMember
from app.models.user import User
from app.repositories import TeamRepository, UserRepository
from app.schemas.team import (
    TeamCreate,
    TeamMemberAdd,
    TeamMemberUpdate,
    TeamResponse,
    TeamUpdate,
)

logger = logging.getLogger(__name__)

router = CustomAPIRouter()


@router.post("/", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
async def create_team(
    team_in: TeamCreate,
    current_user: User = Depends(deps.PermissionChecker("team:create")),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Create a new team. The creator becomes the owner.
    """
    team_repo = TeamRepository(db)

    team = Team(
        name=team_in.name,
        description=team_in.description,
        members=[TeamMember(user_id=str(current_user.id), role=TEAM_ROLE_OWNER)],
    )

    await team_repo.create(team)

    # Enrich with username for response
    team_dict = team.model_dump()
    team_dict["members"][0]["username"] = current_user.username

    return team_dict


@router.get("/", response_model=List[TeamResponse])
async def read_teams(
    search: Optional[str] = None,
    sort_by: str = "name",
    sort_order: str = "asc",
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List teams.
    """
    team_repo = TeamRepository(db)

    query = {}
    if search:
        query["name"] = {"$regex": re.escape(search), "$options": "i"}

    if has_permission(current_user.permissions, "team:read_all"):
        final_query = query
    elif has_permission(current_user.permissions, "team:read"):
        permission_query = {"members.user_id": str(current_user.id)}

        if query:
            final_query = {"$and": [query, permission_query]}
        else:
            final_query = permission_query
    else:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    sort_direction = 1 if sort_order == "asc" else -1

    pipeline = build_team_enrichment_pipeline(final_query, sort_by, sort_direction)
    teams = await team_repo.aggregate(pipeline, limit=1000)
    return teams


@router.get("/{team_id}", response_model=TeamResponse)
async def read_team(
    team_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get team details.
    """
    team_repo = TeamRepository(db)

    await check_team_access(team_id, current_user, db)

    pipeline = build_team_enrichment_pipeline({"_id": team_id})
    result = await team_repo.aggregate(pipeline, limit=1)
    if not result:
        raise HTTPException(status_code=404, detail="Team not found")

    return result[0]


@router.put("/{team_id}", response_model=TeamResponse)
async def update_team(
    team_id: str,
    team_in: TeamUpdate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Update team details. Requires 'admin' or 'owner' role.
    """
    await get_team_with_access(team_id, current_user, db)

    team_repo = TeamRepository(db)

    update_data = team_in.model_dump(exclude_unset=True)
    update_data["updated_at"] = datetime.now(timezone.utc)

    await team_repo.update(team_id, update_data)

    return await fetch_and_enrich_team(team_id, db)


@router.delete("/{team_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_team(
    team_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Delete a team. Requires 'owner' role.

    Performs cascade cleanup:
    - Sets team_id=null on all projects assigned to this team
    - Projects remain accessible to their direct members
    """
    from app.repositories import ProjectRepository

    if not has_permission(current_user.permissions, "team:delete"):
        await check_team_access(
            team_id, current_user, db, required_role=TEAM_ROLE_OWNER
        )

    # CASCADE: Unassign team from all projects
    project_repo = ProjectRepository(db)
    updated_count = await project_repo.update_many(
        {"team_id": team_id}, {"team_id": None}
    )

    if updated_count > 0:
        logger.info(
            f"Team {team_id} deleted: unassigned from {updated_count} project(s)"
        )

    team_repo = TeamRepository(db)
    await team_repo.delete(team_id)
    return None


@router.post("/{team_id}/members", response_model=TeamResponse)
async def add_team_member(
    team_id: str,
    member_in: TeamMemberAdd,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Add a member to the team. Requires 'admin' role.
    """
    team_repo = TeamRepository(db)
    user_repo = UserRepository(db)

    team = await get_team_with_access(team_id, current_user, db)

    user_to_add = await user_repo.get_raw_by_email(member_in.email)
    if not user_to_add:
        raise HTTPException(status_code=404, detail="User with this email not found")

    user_id = str(user_to_add["_id"])

    # Check if already member
    if find_member_in_team(team, user_id) is not None:
        raise HTTPException(status_code=400, detail="User already in team")

    new_member = TeamMember(user_id=user_id, role=member_in.role)

    await team_repo.update_raw(
        team_id,
        {
            "$push": {"members": new_member.model_dump()},
            "$set": {"updated_at": datetime.now(timezone.utc)},
        },
    )

    return await fetch_and_enrich_team(team_id, db)


@router.put("/{team_id}/members/{user_id}", response_model=TeamResponse)
async def update_team_member(
    team_id: str,
    user_id: str,
    member_in: TeamMemberUpdate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Update a member's role. Requires 'admin' role.
    """
    team_repo = TeamRepository(db)

    team = await get_team_with_access(team_id, current_user, db)

    # Check if target user is in team
    member_index = find_member_in_team(team, user_id)
    if member_index is None:
        raise HTTPException(status_code=404, detail="User not in team")

    # Prevent modifying owner if you are not owner (admins can't demote owners)
    # If target is owner, only owner can modify
    if team.members[member_index].role == TEAM_ROLE_OWNER:
        await check_team_access(
            team_id, current_user, db, required_role=TEAM_ROLE_OWNER
        )

    await team_repo.update_raw(
        team_id,
        {
            "$set": {
                f"members.{member_index}.role": member_in.role,
                "updated_at": datetime.now(timezone.utc),
            }
        },
    )

    return await fetch_and_enrich_team(team_id, db)


@router.delete("/{team_id}/members/{user_id}", response_model=TeamResponse)
async def remove_team_member(
    team_id: str,
    user_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Remove a member from the team. Requires 'admin' role.
    """
    team_repo = TeamRepository(db)
    team = await get_team_with_access(team_id, current_user, db)

    # Check if target user is in team
    target_role = get_member_role(team, user_id)
    if target_role is None:
        raise HTTPException(status_code=404, detail="User not in team")

    if target_role == TEAM_ROLE_OWNER:
        raise HTTPException(status_code=400, detail="Cannot remove team owner")

    await team_repo.update_raw(
        team_id,
        {
            "$pull": {"members": {"user_id": user_id}},
            "$set": {"updated_at": datetime.now(timezone.utc)},
        },
    )

    return await fetch_and_enrich_team(team_id, db)
