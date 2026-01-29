"""
Team Helper Functions

Shared helper functions for team-related operations.
"""

from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import (
    TEAM_ROLE_ADMIN,
    TEAM_ROLES,
)
from app.core.permissions import has_permission
from app.models.team import Team
from app.models.user import User
from app.repositories import TeamRepository, UserRepository
from app.schemas.team import TeamResponse


def build_team_enrichment_pipeline(
    match_query: Dict[str, Any],
    sort_by: str = "name",
    sort_direction: int = 1,
) -> List[Dict[str, Any]]:
    """
    Build MongoDB aggregation pipeline to enrich teams with member usernames.

    Args:
        match_query: MongoDB query to filter teams
        sort_by: Field to sort by
        sort_direction: 1 for ascending, -1 for descending

    Returns:
        Aggregation pipeline list
    """
    return [
        {"$match": match_query},
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


async def check_team_access(
    team_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    required_role: Optional[str] = None,
) -> Team:
    """
    Check if a user has access to a team and return the team.

    Args:
        team_id: The team ID to check access for
        user: The current user
        db: Database instance
        required_role: Optional minimum role required (member, admin, owner)

    Returns:
        The Team object if access is granted

    Raises:
        HTTPException: 404 if team not found, 403 if access denied
    """
    team_repo = TeamRepository(db)
    team = await team_repo.get_by_id(team_id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")

    # SECURITY: team:read_all grants access to ALL teams (superuser)
    # Note: team:update does NOT bypass membership - only grants write permission
    if has_permission(user.permissions, "team:read_all"):
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
        if member_role is None:
            raise HTTPException(
                status_code=403, detail="Not enough permissions in this team"
            )
        # Role hierarchy: owner > admin > member (TEAM_ROLES is ordered this way)
        if TEAM_ROLES.index(member_role) < TEAM_ROLES.index(required_role):
            raise HTTPException(
                status_code=403, detail="Not enough permissions in this team"
            )

    return team


async def enrich_team_with_usernames(
    team_data: Dict[str, Any], db: AsyncIOMotorDatabase
) -> Dict[str, Any]:
    """
    Enrich team data with member usernames.

    Args:
        team_data: Raw team document from database
        db: Database instance

    Returns:
        Team data with usernames added to each member
    """
    user_repo = UserRepository(db)
    members = team_data.get("members", [])
    user_ids = [m["user_id"] for m in members if "user_id" in m]

    if not user_ids:
        return team_data

    users = await user_repo.find_by_ids(user_ids)
    user_map = {u["_id"]: u["username"] for u in users}

    for member in members:
        member["username"] = user_map.get(member["user_id"])

    return team_data


async def fetch_and_enrich_team(team_id: str, db: AsyncIOMotorDatabase) -> TeamResponse:
    """
    Fetch a team by ID, enrich with usernames, and return as TeamResponse.

    Args:
        team_id: The team ID to fetch
        db: Database instance

    Returns:
        Enriched TeamResponse

    Raises:
        HTTPException: 404 if team not found
    """
    team_repo = TeamRepository(db)
    team_data = await team_repo.get_raw_by_id(team_id)

    if not team_data:
        raise HTTPException(status_code=404, detail="Team not found")

    await enrich_team_with_usernames(team_data, db)
    return TeamResponse(**team_data)


def find_member_in_team(team: Team, user_id: str) -> Optional[int]:
    """
    Find a member's index in a team's member list.

    Args:
        team: The team to search in
        user_id: The user ID to find

    Returns:
        Index of the member, or None if not found
    """
    for i, member in enumerate(team.members):
        if member.user_id == user_id:
            return i
    return None


def get_member_role(team: Team, user_id: str) -> Optional[str]:
    """
    Get a member's role in a team.

    Args:
        team: The team to search in
        user_id: The user ID to find

    Returns:
        Role string, or None if not a member
    """
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
    """
    Get a team, checking global permission or role-based access.

    If the user has global 'team:update' permission, fetches the team directly.
    Otherwise, verifies the user has the required role in the team.

    Args:
        team_id: The team ID to fetch
        user: The current user
        db: Database instance
        required_role: Minimum role required if no global permission

    Returns:
        The Team object

    Raises:
        HTTPException: 404 if team not found, 403 if access denied
    """
    team_repo = TeamRepository(db)

    if has_permission(user.permissions, "team:update"):
        team = await team_repo.get_by_id(team_id)
        if not team:
            raise HTTPException(status_code=404, detail="Team not found")
        return team

    return await check_team_access(team_id, user, db, required_role=required_role)
