"""Shared helper functions for project-related operations."""

import secrets
from typing import Any

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core import security
from app.core.constants import (
    PROJECT_ROLE_ADMIN,
    PROJECT_ROLE_EDITOR,
    PROJECT_ROLE_VIEWER,
    PROJECT_ROLES,
    SETTINGS_MODE_GLOBAL,
    TEAM_ROLE_ADMIN,
    ProjectRole,
)
from app.core.permissions import Permissions, has_permission
from app.models.project import Project
from app.models.user import User
from app.repositories.projects import ProjectRepository, surviving_admin_filter
from app.repositories.system_settings import SystemSettingsRepository
from app.repositories.teams import TeamRepository
from app.repositories.users import UserRepository
from app.services.analysis.registry import SELECTABLE_ANALYZERS
from app.services.crypto_policy.resolver import project_overrides_locked

_MSG_NOT_ENOUGH_PERMISSIONS = "Not enough permissions"

# An empty dict means the whole collection here, so "no project" has to be a filter nothing matches.
NO_PROJECTS: dict[str, Any] = {"_id": {"$in": []}}


async def build_user_project_query(
    user: User,
    team_repo: TeamRepository,
) -> dict[str, Any]:
    """The projects ``check_project_access`` admits the user to, as a query; empty for read_all or a write superuser."""
    if is_write_superuser(user):
        return {}

    if not may_read_projects(user):
        return NO_PROJECTS

    if has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        return {}

    return {
        "$or": [
            {"members.user_id": str(user.id)},
            {"team_ids": {"$in": await team_repo.find_ids({"members.user_id": str(user.id)})}},
        ]
    }


_WRITE_ROLES = frozenset({PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN})


def is_write_superuser(user: User) -> bool:
    """True if the user may change any project; deleting one takes project:delete instead."""
    return has_permission(user.permissions, Permissions.PROJECT_UPDATE)


def may_read_projects(user: User) -> bool:
    """Whether the user holds a project-read permission at all, which every resource gate needs beside the role."""
    return has_permission(user.permissions, [Permissions.PROJECT_READ, Permissions.PROJECT_READ_ALL])


def max_project_role(role_a: ProjectRole | None, role_b: ProjectRole | None) -> ProjectRole | None:
    """Return the higher of two project roles (by PROJECT_ROLES order); either may be None."""
    if role_a is None:
        return role_b
    if role_b is None:
        return role_a
    return role_a if PROJECT_ROLES.index(role_a) >= PROJECT_ROLES.index(role_b) else role_b


def team_grant_role(team_role: str | None) -> ProjectRole:
    """The project role membership of an owning team grants: team admin -> admin, member -> viewer."""
    return PROJECT_ROLE_ADMIN if team_role == TEAM_ROLE_ADMIN else PROJECT_ROLE_VIEWER


def direct_member_role(project: Project, user_id: str) -> ProjectRole | None:
    """Return the user's direct project-member role, or ``None`` if not a member."""
    return next((member.role for member in project.members if member.user_id == user_id), None)


async def team_derived_role(
    team_ids: list[str],
    user_id: str,
    team_repo: TeamRepository,
) -> ProjectRole | None:
    """The strongest project role any of these teams grants; array order only says which writer came last."""
    if not team_ids:
        return None
    role: ProjectRole | None = None
    for members in (await team_repo.members_by_team(team_ids)).values():
        for member in members:
            if member.get("user_id") == user_id:
                role = max_project_role(role, team_grant_role(member.get("role")))
    return role


async def effective_project_role(project: Project, user: User, team_repo: TeamRepository) -> ProjectRole | None:
    """MAX(direct, team-derived); None when the user is neither a member nor on an owning team."""
    user_id = str(user.id)
    return max_project_role(
        direct_member_role(project, user_id), await team_derived_role(project.team_ids, user_id, team_repo)
    )


async def admin_supplying_owners(team_ids: list[str], team_repo: TeamRepository) -> list[str]:
    """The teams among ``team_ids`` that have an admin, each of whom administers the project."""
    by_team = await team_repo.members_by_team(team_ids)
    return sorted(
        team_id
        for team_id, members in by_team.items()
        if any(member.get("role") == TEAM_ROLE_ADMIN for member in members)
    )


async def project_admin_ids(projects: list[Project], team_repo: TeamRepository) -> dict[str, set[str]]:
    """Each project's admins: its direct admin members and the admins of every team that owns it."""
    by_team = await team_repo.members_by_team(sorted({team_id for p in projects for team_id in p.team_ids}))
    team_admins = {
        team_id: {m["user_id"] for m in members if m.get("role") == TEAM_ROLE_ADMIN}
        for team_id, members in by_team.items()
    }
    return {
        p.id: {m.user_id for m in p.members if m.role == PROJECT_ROLE_ADMIN}.union(
            *(team_admins.get(team_id, set()) for team_id in p.team_ids)
        )
        for p in projects
    }


async def last_admin_guard(
    project: Project,
    user: User,
    team_repo: TeamRepository,
    *,
    surviving_owners: set[str] | None = None,
    leaving_member: str | None = None,
) -> dict[str, Any]:
    """The filter the write itself checks so the project keeps an admin despite concurrent writes; {} needs none."""
    if is_write_superuser(user):
        return {}
    if surviving_owners is not None:
        admin_owners = await admin_supplying_owners(sorted(surviving_owners), team_repo)
        if not set(admin_owners) <= set(project.team_ids):
            return {}
        return surviving_admin_filter(admin_owners)
    if leaving_member is not None and direct_member_role(project, leaving_member) == PROJECT_ROLE_ADMIN:
        return surviving_admin_filter(await admin_supplying_owners(project.team_ids, team_repo), leaving_member)
    return {}


async def check_project_access(
    project_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    required_role: ProjectRole | None = None,
    *,
    write: bool = False,
    global_permission: str = Permissions.PROJECT_UPDATE,
) -> Project:
    """Return the project or raise 403/404; read_all opens reads only, and ``write`` asks WRITE without a role."""
    project = await ProjectRepository(db).get_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if has_permission(user.permissions, global_permission):
        return project

    if not (write or required_role in _WRITE_ROLES) and has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        return project

    effective_role = await effective_project_role(project, user, TeamRepository(db))
    if effective_role is None or not may_read_projects(user):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    if required_role and PROJECT_ROLES.index(effective_role) < PROJECT_ROLES.index(required_role):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    return project


async def authorize_waiver_read(project_id: str | None, user: User, db: AsyncIOMotorDatabase) -> None:
    """waiver:read or read_all opens global waivers, read_all every project's, read the viewable projects'."""
    if not has_permission(user.permissions, [Permissions.WAIVER_READ, Permissions.WAIVER_READ_ALL]):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)
    if project_id and not has_permission(user.permissions, Permissions.WAIVER_READ_ALL):
        await check_project_access(project_id, user, db)


def _merge_team_members(data: dict[str, Any], teams: list[dict[str, Any]], usernames: dict[str, str]) -> None:
    """Add the owning teams' members, named with each owner, and set every row's ``effective_role``; direct rows win."""
    team_roles: dict[str, ProjectRole | None] = {}
    owners: dict[str, set[str]] = {}

    # Sorted, so the answer does not depend on the order the read returned the teams in.
    for team in sorted(teams, key=lambda team: str(team.get("_id"))):
        for tm in team.get("members", []):
            uid = tm["user_id"]
            team_roles[uid] = max_project_role(team_roles.get(uid), team_grant_role(tm.get("role")))
            owners.setdefault(uid, set()).add(str(team.get("name")))

    for member in data["members"]:
        direct_role = member.get("role", PROJECT_ROLE_VIEWER)
        member["effective_role"] = max_project_role(direct_role, team_roles.pop(member["user_id"], None))

    overrides = data.get("notification_overrides") or {}
    data["members"].extend(
        {
            "user_id": uid,
            "role": role,
            "effective_role": role,
            "username": usernames.get(uid),
            "inherited_from": "Team: " + ", ".join(sorted(owners[uid])),
            "notification_preferences": overrides.get(uid) or {},
        }
        for uid, role in team_roles.items()
    )


async def load_project_with_members(db: AsyncIOMotorDatabase, project_id: str) -> dict[str, Any] | None:
    """The raw project with every member named: its own, then each owning team's at the role it grants."""
    data = await ProjectRepository(db).get_raw_by_id(project_id)
    if data is None:
        return None
    teams = await TeamRepository(db).find_many_raw({"_id": {"$in": data.get("team_ids") or []}})
    members = data.get("members", [])
    usernames = await UserRepository(db).usernames_by_id(
        [m["user_id"] for m in members] + [tm["user_id"] for team in teams for tm in team.get("members", [])]
    )
    for member in members:
        member["username"] = usernames.get(member["user_id"])
    _merge_team_members(data, teams, usernames)
    return data


async def ensure_crypto_overrides_writable(db: AsyncIOMotorDatabase) -> None:
    if project_overrides_locked(await SystemSettingsRepository(db).get()):
        raise HTTPException(
            status_code=403, detail="System enforces a global crypto policy; project overrides are disabled."
        )


def generate_project_api_key(project_id: str) -> tuple[str, str]:
    """Generate a project API key, returning (api_key "project_id.secret", api_key_hash)."""
    secret = secrets.token_urlsafe(32)
    api_key = f"{project_id}.{secret}"
    api_key_hash = security.get_password_hash(secret)
    return api_key, api_key_hash


def apply_system_settings_enforcement(
    update_data: dict[str, Any],
    retention_mode: str,
    rescan_mode: str,
) -> dict[str, Any]:
    """Strip globally-enforced fields from project update data when their mode is "global"."""
    result = update_data.copy()

    if retention_mode == SETTINGS_MODE_GLOBAL:
        result.pop("retention_days", None)
        result.pop("retention_action", None)

    if rescan_mode == SETTINGS_MODE_GLOBAL:
        result.pop("rescan_enabled", None)
        result.pop("rescan_interval", None)

    return result


def reject_unknown_analyzers(names: list[str] | None) -> None:
    """The engine skips a name it does not know without a trace, so a typo would silently stop a scanner."""
    unknown = sorted(set(names or ()) - SELECTABLE_ANALYZERS)
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown analyzers: {', '.join(unknown)}")
