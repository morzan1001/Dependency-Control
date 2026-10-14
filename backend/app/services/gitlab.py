import asyncio
import logging
import urllib.parse
from typing import Any, NamedTuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import (
    GITLAB_ADMIN_MIN_ACCESS,
    GITLAB_TEAM_MEMBER_MIN_ACCESS,
    GITLAB_USER_EMAIL_CACHE_TTL,
    MAX_PROJECT_TEAMS,
    TEAM_ROLE_ADMIN,
    TEAM_ROLE_MEMBER,
    TEAM_SOURCE_GITLAB,
)
from app.models.gitlab_api import (
    GitLabMember,
    GitLabMergeRequest,
    GitLabNote,
    GitLabProjectDetails,
    OIDCPayload,
)
from app.models.gitlab_instance import GitLabInstance
from app.models.team import GitLabGroupBinding, Team, TeamMember, TeamSyncResult, binding_of
from app.repositories.teams import TeamRepository
from app.repositories.users import UserRepository
from app.schemas.gitlab_instance import GitLabGroupOption
from app.services.git_provider import GitProviderService
from app.services.oidc_utils import discover_jwks_uri

logger = logging.getLogger(__name__)

# Bounds the in-request project, group and uncapped member reads together; a large group is many 10s pages.
_GITLAB_RESOLUTION_TIMEOUT = 30.0


def _auto_team_name(group_path: str) -> str:
    """The name a team gets while nobody has renamed it."""
    return f"GitLab Group: {group_path}"


def _auto_team_description(group_path: str) -> str:
    return f"Imported from GitLab Group {group_path}"


class GitLabGroupLookup(NamedTuple):
    """One group read back from an instance.

    ``reachable`` separates "this instance carries no such group" from "the instance did not
    answer": the first is the caller's mistake, the second is not.
    """

    reachable: bool
    group: dict[str, Any] | None


def group_full_path(group: dict[str, Any], fallback: str = "") -> str:
    """The path that tells two same-named subgroups apart."""
    return str(group.get("full_path") or group.get("path") or fallback)


def build_group_options(groups: list[dict[str, Any]]) -> list[GitLabGroupOption]:
    """The groups a human can bind to; an entry that cannot address a group is left out."""
    options = []
    for group in groups:
        group_id = group.get("id")
        full_path = group_full_path(group)
        if not isinstance(group_id, int) or not full_path:
            continue
        options.append(GitLabGroupOption(id=group_id, full_path=full_path, name=str(group.get("name") or full_path)))
    return options


class _OwningGroup(NamedTuple):
    id: int
    path: str


class GitLabSyncTarget(NamedTuple):
    """The GitLab group that should back the team for one project.

    ``determined`` is False for a question GitLab did not answer. ``group`` is None while
    ``determined`` holds for a project no group owns at all, which retires the group owner it had.
    """

    group: _OwningGroup | None
    determined: bool = True


_UNDETERMINED_TARGET = GitLabSyncTarget(None, determined=False)
_NO_OWNING_GROUP = GitLabSyncTarget(None)


class GitLabService(GitProviderService[GitLabInstance, OIDCPayload]):
    provider = "GitLab"
    _cache_prefix = "gitlab:instance"
    _team_provider = TEAM_SOURCE_GITLAB
    # GitLab accepts a public email only from the account's confirmed addresses.
    _email_field = "public_email"
    _email_cache_ttl = GITLAB_USER_EMAIL_CACHE_TTL
    _oidc_payload = OIDCPayload

    def __init__(self, gitlab_instance: GitLabInstance):
        super().__init__(gitlab_instance)
        self.api_url = f"{self.base_url}/api/v4"

    def _token_headers(self, token: str) -> dict[str, str]:
        return {"PRIVATE-TOKEN": token}

    async def _jwks_uris(self) -> list[str]:
        discovered = await discover_jwks_uri(self.base_url, self._get_cache_key(f"jwks_uri:{self.base_url}"))
        fallbacks = [f"{self.base_url}/oauth/discovery/keys", f"{self.base_url}/-/jwks"]
        return list(dict.fromkeys([discovered, *fallbacks] if discovered else fallbacks))

    async def list_branches(self, project_id: int) -> list[str] | None:
        """Every branch name of a GitLab project; None on API failure."""
        return await self._branch_names(f"/projects/{project_id}/repository/branches")

    async def get_project_details(self, project_id: int) -> GitLabProjectDetails | None:
        """Fetches project details using the system token."""
        response = await self._get_ok(f"/projects/{project_id}")
        return None if response is None else GitLabProjectDetails(**response.json())

    async def get_default_branch(self, project_id: int) -> str | None:
        """The project's default branch. Returns None on API failure."""
        details = await self.get_project_details(project_id)
        return details.default_branch if details else None

    async def get_merge_requests_for_commit(self, project_id: int, commit_sha: str) -> list[GitLabMergeRequest]:
        """Fetches merge requests associated with a specific commit."""
        response = await self._get_ok(f"/projects/{project_id}/repository/commits/{commit_sha}/merge_requests")
        return [] if response is None else [GitLabMergeRequest(**mr) for mr in response.json()]

    async def post_merge_request_comment(self, project_id: int, mr_iid: int, body: str) -> bool:
        return await self._send_comment("POST", f"/projects/{project_id}/merge_requests/{mr_iid}/notes", body)

    async def get_merge_request_notes(self, project_id: int, mr_iid: int) -> list[GitLabNote] | None:
        """Every note on a merge request, newest first; None when a page failed."""
        notes = await self._api_get_paginated(f"/projects/{project_id}/merge_requests/{mr_iid}/notes")
        return None if notes is None else [GitLabNote(**n) for n in notes]

    async def update_merge_request_comment(self, project_id: int, mr_iid: int, note_id: int, body: str) -> bool:
        return await self._send_comment("PUT", f"/projects/{project_id}/merge_requests/{mr_iid}/notes/{note_id}", body)

    async def get_group_members(self, group_id: int) -> list[GitLabMember] | None:
        """Fetch all group members via the system token."""
        members = await self._api_get_paginated(f"/groups/{group_id}/members/all")
        # An empty list is a group nobody is left in, and stays a list; only None is a failure.
        return None if members is None else [GitLabMember(**m) for m in members]

    async def _with_public_emails(self, members: list[GitLabMember]) -> list[GitLabMember] | None:
        """The members, each one listed without an email carrying its public one; None if GitLab would not say."""
        emails = await self._public_emails(
            member_id for member in members if not member.email and (member_id := member.id) is not None
        )
        if emails is None:
            # Written without them, the members GitLab would not describe would lose the team.
            return None
        return [
            member
            if member.email or member.id is None
            else member.model_copy(update={"email": emails[member.id] or None})
            for member in members
        ]

    async def get_groups(self, search: str | None = None) -> list[dict[str, Any]] | None:
        """The groups this instance's token can see, to pick from when binding a team.

        GitLab scopes /groups to the token's own memberships, or to everything for an
        administrator; ``search`` is what reaches a group beyond the pagination cap.
        """
        params: dict[str, Any] = {"order_by": "path", "sort": "asc"}
        if search:
            params["search"] = search
        return await self._api_get_paginated("/groups", params=params, max_pages=10)

    async def get_group(self, ref: int | str) -> GitLabGroupLookup:
        """One group by its numeric id or its full path."""
        endpoint = f"/groups/{urllib.parse.quote(str(ref), safe='')}"
        response = await self._api_get(endpoint, params={"with_projects": "false"})
        # 404 is also what GitLab answers for a group the token may not see: this instance cannot resolve it.
        if response is not None and response.status_code == 404:
            return GitLabGroupLookup(reachable=True, group=None)
        if response is None or not self._ok(endpoint, response):
            return GitLabGroupLookup(reachable=False, group=None)
        return GitLabGroupLookup(reachable=True, group=response.json())

    async def _resolve_sync_target_group(
        self,
        gitlab_project_id: int,
        gitlab_project_path: str,
        project: GitLabProjectDetails | None,
    ) -> GitLabSyncTarget:
        """Which GitLab group (id, path) should back the team for this project."""
        if not project or not project.namespace:
            logger.warning(
                f"Skipping team sync for project_id={gitlab_project_id} ({gitlab_project_path}): "
                "no GitLab project details available."
            )
            return _UNDETERMINED_TARGET

        if project.namespace.kind != "group":
            # Determined, not unknown: GitLab answered, and its answer is that a person owns this
            # project. A group owner it carries from before the move is retired on the strength of it.
            logger.info(
                f"No GitLab group owns project_id={gitlab_project_id} ({gitlab_project_path}): "
                f"namespace is a user namespace, so any group owner it still carries is retired."
            )
            return _NO_OWNING_GROUP

        namespace = project.namespace
        group_id = namespace.id
        group_path = namespace.full_path

        # team_sync_depth sets team granularity: depth=1 "mo/edge/k8s" -> "mo",
        # depth=2 -> "mo/edge", depth=0 -> full path.
        depth = self.instance.team_sync_depth
        if depth <= 0:
            return GitLabSyncTarget(_OwningGroup(group_id, group_path))

        parts = group_path.split("/")
        truncated_path = "/".join(parts[:depth])
        if len(parts) <= depth:
            return GitLabSyncTarget(_OwningGroup(group_id, truncated_path))

        parent = await self.get_group(truncated_path)
        if parent.group:
            return GitLabSyncTarget(_OwningGroup(parent.group["id"], truncated_path))

        # An ancestor of a group this instance carries exists by construction, so a 404 here is a
        # group the token may not see rather than one that is gone. Either way, falling back to the
        # deepest namespace would bind a team of different granularity than every other run of this
        # instance, splitting one group's people across two teams.
        logger.warning(
            "Could not resolve GitLab group path '%s' (reachable=%s) while syncing project_id=%s; "
            "the owner stays undetermined rather than being bound at the deepest namespace '%s'.",
            truncated_path,
            parent.reachable,
            gitlab_project_id,
            group_path,
        )
        return _UNDETERMINED_TARGET

    async def _build_team_members(
        self,
        gitlab_members: list[GitLabMember],
        user_repo: UserRepository,
    ) -> tuple[list[TeamMember], int, bool]:
        """(owners, unresolved count, any resolved), matching only verified local users, tagged with this instance."""
        by_email = await user_repo.verified_users_by_email({member.email for member in gitlab_members if member.email})
        resolved: list[tuple[str, str]] = []
        unresolved = 0
        resolved_any = False
        for member in gitlab_members:
            user = by_email.get(member.email.lower()) if member.email else None
            if not user:
                # No verified local account yet, or a GitLab service account/bot. Sync never
                # creates users; a real member is added on their next sync after logging in via OIDC.
                unresolved += 1
                logger.debug(
                    "Skipping GitLab member with no verified local account (username=%s, access_level=%s).",
                    member.username,
                    member.access_level,
                )
                continue
            resolved_any = True
            if (
                (member.state or "active") != "active"
                or member.membership_state == "awaiting"
                or member.access_level < GITLAB_TEAM_MEMBER_MIN_ACCESS
            ):
                continue
            role = TEAM_ROLE_ADMIN if member.access_level >= GITLAB_ADMIN_MIN_ACCESS else TEAM_ROLE_MEMBER
            resolved.append((str(user["_id"]), role))
        return self._team_members(resolved), unresolved, resolved_any

    async def _resolve_group_members(
        self,
        members: list[GitLabMember],
        user_repo: UserRepository,
        group_path: str,
        group_id: int,
    ) -> list[TeamMember] | None:
        """The members to store for a group, or None to leave the stored ones alone."""
        team_members, unresolved, resolved_any = await self._build_team_members(members, user_repo)
        if unresolved and not resolved_any:
            # A token that lost profile access resolves nobody; writing that would strip the
            # whole gitlab subset and read as a group everyone left.
            logger.warning(
                "Resolved 0 of %d members of GitLab group '%s' (group_id=%d); leaving the existing members untouched.",
                unresolved,
                group_path,
                group_id,
            )
            return None
        return team_members

    @staticmethod
    def _renamed_fields(team: dict[str, Any], stored_path: str | None, group_path: str) -> dict[str, Any]:
        """Rename only a team still named by this binding; another binding's name would flip back and forth."""
        if not stored_path or stored_path == group_path or team.get("name") != _auto_team_name(stored_path):
            return {}
        return {"name": _auto_team_name(group_path), "description": _auto_team_description(group_path)}

    async def _refresh_team(
        self,
        team_repo: TeamRepository,
        team: dict[str, Any],
        group_id: int,
        group_path: str,
        team_members: list[TeamMember] | None,
    ) -> None:
        """Write what GitLab has since changed about a bound team, and nothing when nothing has.

        ``team_members`` is None to leave the stored members alone, which the rename must not hang
        on: a group whose members none resolve would otherwise never follow a rename.
        """
        stored_path = (binding_of(team, self._instance_id) or {}).get("path")
        # A group that was renamed or moved has to carry the path GitLab reports now, including on
        # a team bound by hand before any sync ran.
        await self._write_team_refresh(
            team_repo,
            team,
            group_id,
            self._renamed_fields(team, stored_path, group_path),
            {"path": group_path} if stored_path != group_path else {},
            team_members,
        )

    async def _upsert_team_with_members(
        self,
        team_repo: TeamRepository,
        existing_team: dict[str, Any] | None,
        group_id: int,
        group_path: str,
        team_members: list[TeamMember] | None,
    ) -> TeamSyncResult:
        """The team backing the group, refreshed or created; none creatable means no owner here, not a failure."""
        if existing_team:
            await self._refresh_team(team_repo, existing_team, group_id, group_path, team_members)
            return TeamSyncResult([str(existing_team["_id"])])
        if not team_members:
            return TeamSyncResult([])
        created = await team_repo.create_bound(
            Team(
                name=_auto_team_name(group_path),
                description=_auto_team_description(group_path),
                bindings=[GitLabGroupBinding(instance_id=self._instance_id, external_id=group_id, path=group_path)],
                members=team_members,
            )
        )
        return TeamSyncResult([str(created["_id"])] if created else None)

    async def _read_owning_group(
        self,
        gitlab_project_id: int,
        gitlab_project_path: str,
    ) -> tuple[GitLabSyncTarget, list[GitLabMember] | None]:
        """Everything this sync asks GitLab for: the owning group, and the members it holds."""
        project = await self.get_project_details(gitlab_project_id)
        target = await self._resolve_sync_target_group(gitlab_project_id, gitlab_project_path, project)
        if target.group is None:
            return target, None
        members = await self.get_group_members(target.group.id)
        return target, None if members is None else await self._with_public_emails(members)

    async def sync_team_from_gitlab(
        self,
        db: AsyncIOMotorDatabase,
        gitlab_project_id: int,
        gitlab_project_path: str,
        *,
        owner_budget: int = MAX_PROJECT_TEAMS,
    ) -> TeamSyncResult:
        """Sync the group's team; undetermined on failure, none created at zero ``owner_budget``; never raises."""
        team_repo = TeamRepository(db)
        user_repo = UserRepository(db)

        try:
            try:
                # Only the reads are bounded: cancelling them costs nothing, while cancelling the
                # write would leave the team half-refreshed for no gain.
                async with asyncio.timeout(_GITLAB_RESOLUTION_TIMEOUT):
                    target, members = await self._read_owning_group(gitlab_project_id, gitlab_project_path)
            except TimeoutError:
                logger.warning(
                    "Resolving the owning group of project_id=%s (%s) took longer than %.0fs; "
                    "leaving its owner untouched.",
                    gitlab_project_id,
                    gitlab_project_path,
                    _GITLAB_RESOLUTION_TIMEOUT,
                )
                return TeamSyncResult(None)

            if not target.determined:
                return TeamSyncResult(None)
            if target.group is None:
                return TeamSyncResult([])

            group_id, group_path = target.group
            # Only by the (instance, group) key: two instances can each carry a group of the same path.
            existing_team = await team_repo.get_raw_by_binding(TEAM_SOURCE_GITLAB, self._instance_id, group_id)

            if members is None:
                logger.warning(
                    "Failed to fetch members for GitLab group '%s' (group_id=%d) while syncing project_id=%s; "
                    "its team keeps its members, and without a team the owner stays undetermined.",
                    group_path,
                    group_id,
                    gitlab_project_id,
                )
                return TeamSyncResult([str(existing_team["_id"])] if existing_team else None)

            if existing_team is None and owner_budget < 1:
                logger.warning(
                    "Project_id=%s has no room for another owner; no team is created for GitLab group '%s'.",
                    gitlab_project_id,
                    group_path,
                )
                return TeamSyncResult(None)

            team_members = await self._resolve_group_members(members, user_repo, group_path, group_id)
            return await self._upsert_team_with_members(team_repo, existing_team, group_id, group_path, team_members)

        except Exception as e:
            logger.exception(
                "Error syncing GitLab teams for project_id=%s (%s): %s: %s",
                gitlab_project_id,
                gitlab_project_path,
                type(e).__name__,
                e,
            )
            return TeamSyncResult(None)
