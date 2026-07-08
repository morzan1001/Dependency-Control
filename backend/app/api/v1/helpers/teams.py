"""Shared helper functions for team-related operations."""

from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import (
    TEAM_ROLE_ADMIN,
    TEAM_ROLES,
)
from app.core.permissions import Permissions, has_permission
from app.models.team import Team
from app.models.user import User
from app.repositories import TeamRepository, UserRepository
from app.schemas.team import TeamResponse

_MSG_TEAM_NOT_FOUND = "Team not found"


def build_team_enrichment_pipeline(
    match_query: Dict[str, Any],
    sort_by: str = "name",
    sort_direction: int = 1,
) -> List[Dict[str, Any]]:
    """Build a MongoDB aggregation pipeline that enriches teams with member usernames."""
    return [
        {"$match": match_query},
        {"$sort": {sort_by: sort_direction}},
        {
            "$lookup": {
                "from": "users",
                "let": {"member_ids": "$members.user_id"},
                "pipeline": [
                    {"$match": {"$expr": {"$in": [{"$toString": "$_id"}, "$$member_ids"]}}},
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
                                                                        {"$toString": "$$this._id"},
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


async def check_team_access(
    team_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    required_role: Optional[str] = None,
) -> Team:
    """Check a user's access to a team and return it, raising 404/403 on failure."""
    team_repo = TeamRepository(db)
    team = await team_repo.get_by_id(team_id)
    if not team:
        raise HTTPException(status_code=404, detail=_MSG_TEAM_NOT_FOUND)

    # team:read_all is a superuser grant over all teams; team:update does not bypass membership.
    if not has_permission(user.permissions, Permissions.TEAM_READ_ALL):
        member_role = None
        is_member = False
        for member in team.members:
            if member.user_id == str(user.id):
                is_member = True
                member_role = member.role
                break

        if not is_member:
            raise HTTPException(status_code=403, detail="Not a member of this team")

        if Permissions.TEAM_READ not in user.permissions and Permissions.TEAM_READ_ALL not in user.permissions:
            raise HTTPException(status_code=403, detail="Not enough permissions")

        if required_role:
            if member_role is None:
                raise HTTPException(status_code=403, detail="Not enough permissions in this team")
            if TEAM_ROLES.index(member_role) < TEAM_ROLES.index(required_role):
                raise HTTPException(status_code=403, detail="Not enough permissions in this team")

    return team


async def enrich_team_with_usernames(team_data: Dict[str, Any], db: AsyncIOMotorDatabase) -> None:
    """Enrich a raw team document with member usernames, mutating it in place."""
    user_repo = UserRepository(db)
    members = team_data.get("members", [])
    user_ids = [m["user_id"] for m in members if "user_id" in m]

    if not user_ids:
        return

    users = await user_repo.find_by_ids(user_ids)
    user_map = {u["_id"]: u["username"] for u in users}

    for member in members:
        member["username"] = user_map.get(member["user_id"])


async def fetch_and_enrich_team(team_id: str, db: AsyncIOMotorDatabase) -> TeamResponse:
    """Fetch a team by ID, enrich with usernames, and return it, raising 404 if missing."""
    team_repo = TeamRepository(db)
    team_data = await team_repo.get_raw_by_id(team_id)

    if not team_data:
        raise HTTPException(status_code=404, detail=_MSG_TEAM_NOT_FOUND)

    await enrich_team_with_usernames(team_data, db)
    return TeamResponse(**team_data)


def find_member_in_team(team: Team, user_id: str) -> Optional[int]:
    """Return a member's index in the team's member list, or None if not found."""
    for i, member in enumerate(team.members):
        if member.user_id == user_id:
            return i
    return None


def get_member_role(team: Team, user_id: str) -> Optional[str]:
    """Return a member's role in the team, or None if not a member."""
    for member in team.members:
        if member.user_id == user_id:
            return member.role
    return None


async def get_team_with_access(
    team_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    required_role: str = TEAM_ROLE_ADMIN,
) -> Team:
    """Get a team via global 'team:update' permission or, failing that, role-based access."""
    team_repo = TeamRepository(db)

    if has_permission(user.permissions, "team:update"):
        team = await team_repo.get_by_id(team_id)
        if not team:
            raise HTTPException(status_code=404, detail=_MSG_TEAM_NOT_FOUND)
        return team

    return await check_team_access(team_id, user, db, required_role=required_role)
