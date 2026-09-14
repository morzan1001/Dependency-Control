import logging
import re
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo.errors import DuplicateKeyError

from app.api import deps
from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers import (
    build_team_enrichment_pipeline,
    check_team_access,
    fetch_and_enrich_team,
    get_member_role,
    get_team_with_access,
)
from app.api.v1.helpers.responses import (
    RESP_AUTH,
    RESP_AUTH_400_404,
    RESP_AUTH_400_404_409_502,
    RESP_AUTH_404,
)
from app.core.constants import TEAM_ROLE_ADMIN
from app.core.permissions import Permissions, has_permission
from app.models.team import GitHubTeamBinding, GitLabGroupBinding, Team, TeamMember
from app.models.user import User
from app.repositories import TeamRepository, UserRepository
from app.repositories.github_instances import GitHubInstanceRepository
from app.repositories.gitlab_instances import GitLabInstanceRepository
from app.repositories.projects import remove_team_pipeline
from app.schemas.team import (
    TeamBindingRequest,
    TeamCreate,
    TeamGitHubBindingRequest,
    TeamGitLabBindingRequest,
    TeamMemberAdd,
    TeamMemberUpdate,
    TeamResponse,
    TeamUpdate,
)
from app.services.github import GitHubService, build_team_slug_map
from app.services.gitlab import GitLabService

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

_MSG_ALREADY_IN_TEAM = "User already in team"
_MSG_LAST_ADMIN = "Cannot remove the last admin. Add another admin first."
_MSG_TEAM_NOT_FOUND = "Team not found"


@router.post("/", response_model=TeamResponse, status_code=status.HTTP_201_CREATED, responses=RESP_AUTH)
async def create_team(
    team_in: TeamCreate,
    current_user: Annotated[User, Depends(deps.PermissionChecker("team:create"))],
    db: DatabaseDep,
) -> dict[str, Any]:
    """Create a new team. The creator becomes an admin."""
    team_repo = TeamRepository(db)

    team = Team(
        name=team_in.name,
        description=team_in.description,
        members=[TeamMember(user_id=str(current_user.id), role=TEAM_ROLE_ADMIN)],
    )

    await team_repo.create(team)

    team_dict = team.model_dump()
    team_dict["members"][0]["username"] = current_user.username

    return team_dict


@router.get("/", response_model=list[TeamResponse], responses=RESP_AUTH)
async def read_teams(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    search: str | None = None,
    sort_by: str = "name",
    sort_order: str = "asc",
) -> list[dict[str, Any]]:
    """List teams."""
    team_repo = TeamRepository(db)

    query: dict[str, Any] = {}
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


@router.get("/{team_id}", response_model=TeamResponse, responses=RESP_AUTH_404)
async def read_team(
    team_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Get team details."""
    team_repo = TeamRepository(db)

    await check_team_access(team_id, current_user, db)

    pipeline = build_team_enrichment_pipeline({"_id": team_id})
    result = await team_repo.aggregate(pipeline, limit=1)
    if not result:
        raise HTTPException(status_code=404, detail=_MSG_TEAM_NOT_FOUND)

    return result[0]


@router.put("/{team_id}", responses=RESP_AUTH_404)
async def update_team(
    team_id: str,
    team_in: TeamUpdate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> TeamResponse:
    """Update team details. Requires 'admin' role."""
    await get_team_with_access(team_id, current_user, db)

    team_repo = TeamRepository(db)

    update_data = team_in.model_dump(exclude_unset=True)
    update_data["updated_at"] = datetime.now(timezone.utc)

    await team_repo.update(team_id, update_data)

    return await fetch_and_enrich_team(team_id, db)


@router.delete("/{team_id}", status_code=status.HTTP_204_NO_CONTENT, responses=RESP_AUTH_404)
async def delete_team(
    team_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> None:
    """Delete a team (admin role); unassigns it from projects and removes team webhooks."""
    from app.repositories import ProjectRepository

    if not has_permission(current_user.permissions, "team:delete"):
        await check_team_access(team_id, current_user, db, required_role=TEAM_ROLE_ADMIN)

    # Sanitize for logs to prevent CRLF log injection.
    safe_team_id = team_id.replace("\n", "_").replace("\r", "_")

    project_repo = ProjectRepository(db)
    updated_count = await project_repo.update_many_raw({"team_ids": team_id}, remove_team_pipeline(team_id))

    if updated_count > 0:
        logger.info("Team %s deleted: unassigned from %d project(s)", safe_team_id, updated_count)

    webhook_result = await db.webhooks.delete_many({"team_id": team_id})
    if webhook_result.deleted_count > 0:
        logger.info("Team %s deleted: removed %d webhook(s)", safe_team_id, webhook_result.deleted_count)

    team_repo = TeamRepository(db)
    await team_repo.delete(team_id)


async def _github_binding(request: TeamGitHubBindingRequest, db: AsyncIOMotorDatabase) -> GitHubTeamBinding:
    """The binding to store, with the slug the organisation reports for the bound team number.

    Reading the slug here rather than taking it from the caller is also what proves the team
    exists: a binding to a number no organisation carries would resolve nothing, silently, forever.
    """
    instance = await GitHubInstanceRepository(db).get_by_id(request.instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail=f"GitHub instance with ID {request.instance_id} not found")

    org_teams = await GitHubService(instance).get_org_teams(request.org)
    if org_teams is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Could not list the teams of organisation '{request.org}' on instance "
                f"'{instance.name}'. The token needs read:org there."
            ),
        )

    slug = build_team_slug_map(org_teams).get(request.external_id)
    if slug is None:
        raise HTTPException(
            status_code=400,
            detail=(
                f"GitHub organisation '{request.org}' has no team with id {request.external_id} "
                f"that instance '{instance.name}' can see."
            ),
        )
    return GitHubTeamBinding(
        instance_id=request.instance_id, org=request.org, external_id=request.external_id, slug=slug
    )


async def _gitlab_binding(request: TeamGitLabBindingRequest, db: AsyncIOMotorDatabase) -> GitLabGroupBinding:
    """The binding to store, with the full path the instance reports for the bound group number.

    Reading the path here rather than taking it from the caller is also what proves the group
    exists: a binding to a number no instance carries would resolve nothing, silently, forever.
    """
    instance = await GitLabInstanceRepository(db).get_by_id(request.instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail=f"GitLab instance with ID {request.instance_id} not found")

    lookup = await GitLabService(instance).get_group(request.external_id)
    if not lookup.reachable:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Could not read group {request.external_id} from instance '{instance.name}'. "
                f"It needs an access token that can read it."
            ),
        )
    if lookup.group is None:
        raise HTTPException(
            status_code=400,
            detail=f"GitLab instance '{instance.name}' has no group with id {request.external_id} that it can see.",
        )
    path = str(lookup.group.get("full_path") or lookup.group.get("path") or request.external_id)
    return GitLabGroupBinding(instance_id=request.instance_id, external_id=request.external_id, path=path)


def _binding_conflict(binding: GitHubTeamBinding | GitLabGroupBinding) -> str:
    if isinstance(binding, GitHubTeamBinding):
        return f"GitHub team {binding.external_id} of '{binding.org}'"
    return f"GitLab group {binding.external_id}"


async def _reject_taken_binding(
    team_repo: TeamRepository, team_id: str, binding: GitHubTeamBinding | GitLabGroupBinding
) -> None:
    """Two teams bound to one group would make the project's owner ambiguous."""
    holder = await team_repo.get_raw_by_binding_key(binding.key)
    if holder is not None and str(holder["_id"]) != team_id:
        raise HTTPException(
            status_code=409,
            detail=f"Team '{holder.get('name')}' is already bound to {_binding_conflict(binding)}.",
        )


@router.put("/{team_id}/bindings", responses=RESP_AUTH_400_404_409_502)
async def set_team_binding(
    team_id: str,
    binding_in: TeamBindingRequest,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
    db: DatabaseDep,
) -> TeamResponse:
    """Bind a team to a group on one instance, which is what makes it resolvable from that
    instance's ingests. A team holds one binding per instance and any number of instances.

    Gated on system:manage rather than team administration: a binding decides which projects
    of the whole estate land in this team, and team membership grants access to them.
    """
    team_repo = TeamRepository(db)
    if not await team_repo.get_raw_by_id(team_id):
        raise HTTPException(status_code=404, detail=_MSG_TEAM_NOT_FOUND)

    binding = (
        await _github_binding(binding_in, db)
        if isinstance(binding_in, TeamGitHubBindingRequest)
        else await _gitlab_binding(binding_in, db)
    )
    await _reject_taken_binding(team_repo, team_id, binding)

    try:
        await team_repo.replace_binding_for_instance(team_id, binding.model_dump())
    except DuplicateKeyError:
        # The unique index caught a binding written between the check above and this write.
        raise HTTPException(
            status_code=409,
            detail=f"Another team was just bound to {_binding_conflict(binding)}.",
        )

    logger.info(
        "Team %s bound to %s on instance %s by %s",
        team_id.replace("\n", "_").replace("\r", "_"),
        _binding_conflict(binding),
        binding.instance_id,
        current_user.username,
    )
    return await fetch_and_enrich_team(team_id, db)


@router.delete("/{team_id}/bindings/{instance_id}", responses=RESP_AUTH_404)
async def clear_team_binding(
    team_id: str,
    instance_id: str,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
    db: DatabaseDep,
) -> TeamResponse:
    """Remove a team's binding for one instance, leaving the ones it holds on the others. Its
    projects keep the team they have; no later ingest from that instance resolves to it.

    It stays cleared because no sync ever binds an existing team: a group left without one gets a
    team of its own, and only this endpoint's system:manage grants a team a group's projects.
    """
    team_repo = TeamRepository(db)
    if not await team_repo.get_raw_by_id(team_id):
        raise HTTPException(status_code=404, detail=_MSG_TEAM_NOT_FOUND)

    if not await team_repo.remove_binding_for_instance(team_id, instance_id):
        raise HTTPException(status_code=404, detail=f"This team holds no binding for instance {instance_id}.")

    logger.info(
        "Binding for instance %s removed from team %s by %s",
        instance_id.replace("\n", "_").replace("\r", "_"),
        team_id.replace("\n", "_").replace("\r", "_"),
        current_user.username,
    )
    return await fetch_and_enrich_team(team_id, db)


@router.post("/{team_id}/members", responses=RESP_AUTH_400_404)
async def add_team_member(
    team_id: str,
    member_in: TeamMemberAdd,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> TeamResponse:
    """Add a member to the team. Requires 'admin' role."""
    team_repo = TeamRepository(db)
    user_repo = UserRepository(db)

    await get_team_with_access(team_id, current_user, db)

    user_to_add = await user_repo.get_raw_by_email(member_in.email)
    if not user_to_add:
        raise HTTPException(status_code=404, detail="User with this email not found")

    new_member = TeamMember(user_id=str(user_to_add["_id"]), role=member_in.role)

    if not await team_repo.add_member(team_id, new_member.model_dump(), datetime.now(timezone.utc)):
        raise HTTPException(status_code=400, detail=_MSG_ALREADY_IN_TEAM)

    return await fetch_and_enrich_team(team_id, db)


@router.put("/{team_id}/members/{user_id}", responses=RESP_AUTH_404)
async def update_team_member(
    team_id: str,
    user_id: str,
    member_in: TeamMemberUpdate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> TeamResponse:
    """Update a member's role. Requires 'admin' role."""
    team_repo = TeamRepository(db)

    team = await get_team_with_access(team_id, current_user, db)

    target_role = get_member_role(team, user_id)
    if target_role is None:
        raise HTTPException(status_code=404, detail="User not in team")

    # Modifying an admin member requires admin access.
    if target_role == TEAM_ROLE_ADMIN:
        await check_team_access(team_id, current_user, db, required_role=TEAM_ROLE_ADMIN)

    await team_repo.update_member_role(team_id, user_id, member_in.role, datetime.now(timezone.utc))

    return await fetch_and_enrich_team(team_id, db)


@router.delete("/{team_id}/members/{user_id}", responses=RESP_AUTH_400_404)
async def remove_team_member(
    team_id: str,
    user_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> TeamResponse:
    """Remove a member from the team. Requires 'admin' role."""
    team_repo = TeamRepository(db)
    team = await get_team_with_access(team_id, current_user, db)

    target_role = get_member_role(team, user_id)
    if target_role is None:
        raise HTTPException(status_code=404, detail="User not in team")

    if target_role == TEAM_ROLE_ADMIN:
        await check_team_access(team_id, current_user, db, required_role=TEAM_ROLE_ADMIN)

    if not await team_repo.remove_member(team_id, user_id, datetime.now(timezone.utc)):
        raise HTTPException(status_code=400, detail=_MSG_LAST_ADMIN)

    return await fetch_and_enrich_team(team_id, db)
