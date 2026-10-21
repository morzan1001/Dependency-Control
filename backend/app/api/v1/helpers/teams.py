from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.sorting import case_insensitive_key
from app.core.constants import (
    TEAM_ROLE_ADMIN,
    TEAM_ROLES,
    TEAM_SOURCE_GITHUB,
    TEAM_SOURCE_GITLAB,
    team_source,
)
from app.core.permissions import Permissions, has_permission
from app.models.team import Team
from app.models.user import User
from app.repositories.github_instances import GitHubInstanceRepository
from app.repositories.gitlab_instances import GitLabInstanceRepository
from app.repositories.teams import TeamRepository
from app.repositories.users import UserRepository
from app.repositories.vcs_instances import VcsInstanceRepository
from app.schemas.team import TeamRef, TeamResponse

_MSG_TEAM_NOT_FOUND = "Team not found"


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


async def syncing_sources(bound: Iterable[tuple[str, str]], db: AsyncIOMotorDatabase) -> set[str]:
    """Sources of these (provider, instance) bindings whose instance syncs teams; a sync restores their members."""
    instance_ids: defaultdict[str, set[str]] = defaultdict(set)
    for provider, instance_id in bound:
        instance_ids[provider].add(instance_id)
    repositories: dict[str, VcsInstanceRepository[Any]] = {
        TEAM_SOURCE_GITHUB: GitHubInstanceRepository(db),
        TEAM_SOURCE_GITLAB: GitLabInstanceRepository(db),
    }
    return {
        team_source(provider, instance_id)
        for provider, ids in instance_ids.items()
        for instance_id in await repositories[provider].team_syncing_ids(ids)
    }


async def mark_sync_owned_members(teams: list[dict[str, Any]], db: AsyncIOMotorDatabase) -> None:
    bound = {team["_id"]: {(b["provider"], b["instance_id"]) for b in team.get("bindings") or []} for team in teams}
    syncing = await syncing_sources(set().union(*bound.values()), db)
    for team in teams:
        owned = syncing & {team_source(provider, instance_id) for provider, instance_id in bound[team["_id"]]}
        for member in team.get("members", []):
            member["sync_owned"] = member.get("source") in owned


async def fetch_and_enrich_team(team_id: str, db: AsyncIOMotorDatabase) -> TeamResponse:
    team_repo = TeamRepository(db)
    team_data = await team_repo.get_raw_by_id(team_id)

    if not team_data:
        raise HTTPException(status_code=404, detail=_MSG_TEAM_NOT_FOUND)

    await enrich_teams_with_usernames([team_data], db)
    await mark_sync_owned_members([team_data], db)
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
