from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.db.mongodb import get_database
from app.models.team import Team, TeamMember
from app.models.user import User
from app.schemas.team import (
    TeamCreate,
    TeamMemberAdd,
    TeamMemberUpdate,
    TeamResponse,
    TeamUpdate,
)

router = APIRouter()


async def enrich_team_with_usernames(team_data: dict, db: AsyncIOMotorDatabase) -> dict:
    members = team_data.get("members", [])
    user_ids = []
    for m in members:
        if "user_id" in m:
            user_ids.append(m["user_id"])

    users = await db.users.find({"_id": {"$in": user_ids}}).to_list(None)
    user_map = {u["_id"]: u["username"] for u in users}

    for member in members:
        member["username"] = user_map.get(member["user_id"])

    return team_data


async def check_team_access(
    team_id: str, user: User, db: AsyncIOMotorDatabase, required_role: str = None
) -> Team:
    team_data = await db.teams.find_one({"_id": team_id})
    if not team_data:
        raise HTTPException(status_code=404, detail="Team not found")

    team = Team(**team_data)

    if "*" in user.permissions:
        return team

    member_role = None
    is_member = False
    for member in team.members:
        if member.user_id == str(user.id):
            is_member = True
            member_role = member.role
            break

    # Check for global read permission
    if required_role is None and "team:read_all" in user.permissions:
        return team

    if not is_member:
        raise HTTPException(status_code=403, detail="Not a member of this team")

    # Check for basic read permission
    if "team:read" not in user.permissions and "team:read_all" not in user.permissions:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    if required_role:
        # Role hierarchy: owner > admin > member
        roles = ["member", "admin", "owner"]
        if roles.index(member_role) < roles.index(required_role):
            raise HTTPException(
                status_code=403, detail="Not enough permissions in this team"
            )

    return team


@router.post("/", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
async def create_team(
    team_in: TeamCreate,
    current_user: User = Depends(deps.PermissionChecker("team:create")),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Create a new team. The creator becomes the owner.
    """
    team = Team(
        name=team_in.name,
        description=team_in.description,
        members=[TeamMember(user_id=str(current_user.id), role="owner")],
    )

    await db.teams.insert_one(team.dict(by_alias=True))

    # Enrich with username for response
    team_dict = team.dict(by_alias=True)
    team_dict["members"][0]["username"] = current_user.username

    return team_dict


@router.get("/", response_model=List[TeamResponse])
async def read_teams(
    search: str = None,
    sort_by: str = "name",
    sort_order: str = "asc",
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List teams.
    """
    query = {}
    if search:
        query["name"] = {"$regex": search, "$options": "i"}

    if "*" in current_user.permissions or "team:read_all" in current_user.permissions:
        final_query = query
    elif "team:read" in current_user.permissions:
        permission_query = {"members.user_id": str(current_user.id)}

        if query:
            final_query = {"$and": [query, permission_query]}
        else:
            final_query = permission_query
    else:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    sort_direction = 1 if sort_order == "asc" else -1

    pipeline = [
        {"$match": final_query},
        {"$sort": {sort_by: sort_direction}},
        {
            "$lookup": {
                "from": "users",
                "let": {"member_ids": "$members.user_id"},
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {"$in": [{"$toString": "$_id"}, "$$member_ids"]}
                        }
                    },
                    {"$project": {"_id": 1, "username": 1}},
                ],
                "as": "users_info",
            }
        },
        {
            "$addFields": {
                "members": {
                    "$map": {
                        "input": "$members",
                        "as": "m",
                        "in": {
                            "$mergeObjects": [
                                "$$m",
                                {
                                    "username": {
                                        "$let": {
                                            "vars": {
                                                "u": {
                                                    "$arrayElemAt": [
                                                        {
                                                            "$filter": {
                                                                "input": "$users_info",
                                                                "cond": {
                                                                    "$eq": [
                                                                        {
                                                                            "$toString": "$$this._id"
                                                                        },
                                                                        "$$m.user_id",
                                                                    ]
                                                                },
                                                            }
                                                        },
                                                        0,
                                                    ]
                                                }
                                            },
                                            "in": "$$u.username",
                                        }
                                    }
                                },
                            ]
                        },
                    }
                }
            }
        },
        {"$project": {"users_info": 0}},
    ]

    teams = await db.teams.aggregate(pipeline).to_list(1000)
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
    await check_team_access(team_id, current_user, db)

    pipeline = [
        {"$match": {"_id": team_id}},
        {
            "$lookup": {
                "from": "users",
                "let": {"member_ids": "$members.user_id"},
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {"$in": [{"$toString": "$_id"}, "$$member_ids"]}
                        }
                    },
                    {"$project": {"_id": 1, "username": 1}},
                ],
                "as": "users_info",
            }
        },
        {
            "$addFields": {
                "members": {
                    "$map": {
                        "input": "$members",
                        "as": "m",
                        "in": {
                            "$mergeObjects": [
                                "$$m",
                                {
                                    "username": {
                                        "$let": {
                                            "vars": {
                                                "u": {
                                                    "$arrayElemAt": [
                                                        {
                                                            "$filter": {
                                                                "input": "$users_info",
                                                                "cond": {
                                                                    "$eq": [
                                                                        {
                                                                            "$toString": "$$this._id"
                                                                        },
                                                                        "$$m.user_id",
                                                                    ]
                                                                },
                                                            }
                                                        },
                                                        0,
                                                    ]
                                                }
                                            },
                                            "in": "$$u.username",
                                        }
                                    }
                                },
                            ]
                        },
                    }
                }
            }
        },
        {"$project": {"users_info": 0}},
    ]

    result = await db.teams.aggregate(pipeline).to_list(1)
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
    if (
        "*" not in current_user.permissions
        and "team:update" not in current_user.permissions
    ):
        await check_team_access(team_id, current_user, db, required_role="admin")

    update_data = team_in.dict(exclude_unset=True)
    update_data["updated_at"] = datetime.now(timezone.utc)

    await db.teams.update_one({"_id": team_id}, {"$set": update_data})

    updated_team = await db.teams.find_one({"_id": team_id})
    await enrich_team_with_usernames(updated_team, db)
    return updated_team


@router.delete("/{team_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_team(
    team_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Delete a team. Requires 'owner' role.
    """
    if (
        "*" not in current_user.permissions
        and "team:delete" not in current_user.permissions
    ):
        await check_team_access(team_id, current_user, db, required_role="owner")
    await db.teams.delete_one({"_id": team_id})
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
    if "*" in current_user.permissions or "team:update" in current_user.permissions:
        team_data = await db.teams.find_one({"_id": team_id})
        if not team_data:
            raise HTTPException(status_code=404, detail="Team not found")
        team = Team(**team_data)
    else:
        team = await check_team_access(team_id, current_user, db, required_role="admin")

    user_to_add = await db.users.find_one({"email": member_in.email})
    if not user_to_add:
        raise HTTPException(status_code=404, detail="User with this email not found")

    user_id = str(user_to_add["_id"])

    # Check if already member
    for member in team.members:
        if member.user_id == user_id:
            raise HTTPException(status_code=400, detail="User already in team")

    new_member = TeamMember(user_id=user_id, role=member_in.role)

    await db.teams.update_one(
        {"_id": team_id},
        {
            "$push": {"members": new_member.model_dump()},
            "$set": {"updated_at": datetime.now(timezone.utc)},
        },
    )

    updated_team = await db.teams.find_one({"_id": team_id})
    await enrich_team_with_usernames(updated_team, db)
    return TeamResponse(**updated_team)


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
    if "*" in current_user.permissions or "team:update" in current_user.permissions:
        team_data = await db.teams.find_one({"_id": team_id})
        if not team_data:
            raise HTTPException(status_code=404, detail="Team not found")
        team = Team(**team_data)
    else:
        team = await check_team_access(team_id, current_user, db, required_role="admin")

    # Check if target user is in team
    member_index = -1
    for i, member in enumerate(team.members):
        if member.user_id == user_id:
            member_index = i
            break

    if member_index == -1:
        raise HTTPException(status_code=404, detail="User not in team")

    # Prevent modifying owner if you are not owner (admins can't demote owners)
    # Admins can manage members. Owners can manage everyone.

    # If target is owner, only owner can modify
    if team.members[member_index].role == "owner":
        await check_team_access(team_id, current_user, db, required_role="owner")

    await db.teams.update_one(
        {"_id": team_id, "members.user_id": user_id},
        {
            "$set": {
                f"members.{member_index}.role": member_in.role,
                "updated_at": datetime.now(timezone.utc),
            }
        },
    )

    updated_team = await db.teams.find_one({"_id": team_id})
    await enrich_team_with_usernames(updated_team, db)
    return TeamResponse(**updated_team)


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
    if "*" in current_user.permissions or "team:update" in current_user.permissions:
        team_data = await db.teams.find_one({"_id": team_id})
        if not team_data:
            raise HTTPException(status_code=404, detail="Team not found")
        team = Team(**team_data)
    else:
        team = await check_team_access(team_id, current_user, db, required_role="admin")

    # Check if target user is in team
    member_exists = False
    target_role = None
    for member in team.members:
        if member.user_id == user_id:
            member_exists = True
            target_role = member.role
            break

    if not member_exists:
        raise HTTPException(status_code=404, detail="User not in team")

    if target_role == "owner":
        raise HTTPException(status_code=400, detail="Cannot remove team owner")

    await db.teams.update_one(
        {"_id": team_id},
        {
            "$pull": {"members": {"user_id": user_id}},
            "$set": {"updated_at": datetime.now(timezone.utc)},
        },
    )

    updated_team = await db.teams.find_one({"_id": team_id})
    await enrich_team_with_usernames(updated_team, db)
    return TeamResponse(**updated_team)
