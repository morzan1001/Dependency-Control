from collections.abc import Iterable, Mapping
from typing import Any

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.sorting import case_insensitive_key
from app.core.constants import (
    TEAM_ROLE_ADMIN,
    TEAM_ROLES,
)
from app.core.permissions import Permissions, has_permission
from app.models.team import Team
from app.models.user import User
from app.repositories.teams import TeamRepository
from app.repositories.users import UserRepository
from app.schemas.team import TeamRef, TeamResponse

_MSG_TEAM_NOT_FOUND = "Team not found"


async def resolve_team_names(db: AsyncIOMotorDatabase, team_ids: Iterable[str]) -> dict[str, str]:
    """Name every team in ``team_ids`` in one read, so a page of co-owned projects is still one query."""
    wanted = sorted(set(team_ids))
    if not wanted:
        return {}
    cursor = db.teams.find({"_id": {"$in": wanted}}, {"_id": 1, "name": 1})
    return {str(team["_id"]): team.get("name", "") async for team in cursor}


def team_refs(team_ids: Iterable[str], names: Mapping[str, str]) -> list[TeamRef]:
    """Name order, since the stored order shifts with every $setUnion; an unnamed id lost its team and is dropped."""
    refs = [TeamRef(id=team_id, name=name) for team_id in team_ids if (name := names.get(team_id)) is not None]
    return sorted(refs, key=lambda ref: (case_insensitive_key(ref.name), ref.id))


def visible_teams_filter(user: User) -> dict[str, Any] | None:
    if has_permission(user.permissions, Permissions.TEAM_READ_ALL):
        return {}
    if has_permission(user.permissions, Permissions.TEAM_READ):
        return {"members.user_id": str(user.id)}
    return None


async def check_team_access(
    team_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    required_role: str | None = None,
) -> Team:
    team_repo = TeamRepository(db)
    team = await team_repo.get_by_id(team_id)
    if not team:
        raise HTTPException(status_code=404, detail=_MSG_TEAM_NOT_FOUND)

    if required_role is None and has_permission(user.permissions, Permissions.TEAM_READ_ALL):
        return team

    member_role = get_member_role(team, str(user.id))
    if member_role is None:
        raise HTTPException(status_code=403, detail="Not a member of this team")

    if not has_permission(user.permissions, [Permissions.TEAM_READ, Permissions.TEAM_READ_ALL]):
        raise HTTPException(status_code=403, detail="Not enough permissions")

    if required_role and TEAM_ROLES.index(member_role) < TEAM_ROLES.index(required_role):
        raise HTTPException(status_code=403, detail="Not enough permissions in this team")

    return team


async def enrich_teams_with_usernames(teams: list[dict[str, Any]], db: AsyncIOMotorDatabase) -> None:
    usernames = await UserRepository(db).usernames_by_id(
        m["user_id"] for team in teams for m in team.get("members", [])
    )
    for team in teams:
        for member in team.get("members", []):
            member["username"] = usernames.get(member["user_id"])


async def fetch_and_enrich_team(team_id: str, db: AsyncIOMotorDatabase) -> TeamResponse:
    team_repo = TeamRepository(db)
    team_data = await team_repo.get_raw_by_id(team_id)

    if not team_data:
        raise HTTPException(status_code=404, detail=_MSG_TEAM_NOT_FOUND)

    await enrich_teams_with_usernames([team_data], db)
    return TeamResponse(**team_data)


def get_member_role(team: Team, user_id: str) -> str | None:
    for member in team.members:
        if member.user_id == user_id:
            return member.role
    return None


async def get_team_with_access(
    team_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    required_role: str = TEAM_ROLE_ADMIN,
    *,
    global_permission: str = Permissions.TEAM_UPDATE,
) -> Team:
    team_repo = TeamRepository(db)

    if has_permission(user.permissions, global_permission):
        team = await team_repo.get_by_id(team_id)
        if not team:
            raise HTTPException(status_code=404, detail=_MSG_TEAM_NOT_FOUND)
        return team

    return await check_team_access(team_id, user, db, required_role=required_role)
