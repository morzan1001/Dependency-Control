"""Who the project fan-out reaches (a deactivated account keeps its memberships) and whose preferences it enforces."""

import pytest

from app.models.project import Project, ProjectMember
from app.services.notifications.service import NotificationService

_EVENT = "vulnerability_found"
_ALL_CHANNELS = ["email", "slack", "mattermost"]


async def _seed_user(db, uid: str, *, active: bool = True) -> None:
    await db.users.insert_one(
        {
            "_id": uid,
            "username": uid,
            "email": f"{uid}@test.com",
            "slack_username": uid,
            "mattermost_username": uid,
            "is_active": active,
            "permissions": [],
            "notification_preferences": {},
        }
    )


def _recording_service(sent: set[tuple[str, str]]) -> NotificationService:
    service = NotificationService()

    def recorder(channel: str):
        async def send(destination, *_args, **_kwargs):
            sent.add((channel, destination))

        return send

    service.email_provider.send = recorder("email")  # type: ignore[method-assign]
    service.slack_provider.send = recorder("slack")  # type: ignore[method-assign]
    service.mattermost_provider.send = recorder("mattermost")  # type: ignore[method-assign]
    return service


async def _notify(db, project: Project, forced_channels: list[str] | None = None) -> set[tuple[str, str]]:
    sent: set[tuple[str, str]] = set()
    await _recording_service(sent).notify_project_members(
        project=project,
        event_type=_EVENT,
        subject="s",
        message="m",
        db=db,
        forced_channels=forced_channels,
    )
    return sent


def _on_every_channel(uid: str) -> set[tuple[str, str]]:
    return {("email", f"{uid}@test.com"), ("slack", uid), ("mattermost", f"@{uid}")}


@pytest.mark.asyncio
async def test_deactivated_direct_and_team_members_are_sent_nothing_on_any_channel(db):
    await _seed_user(db, "u-direct")
    await _seed_user(db, "u-direct-gone", active=False)
    await _seed_user(db, "u-team")
    await _seed_user(db, "u-team-gone", active=False)
    await db.teams.insert_one(
        {"_id": "alpha", "name": "Alpha", "members": [{"user_id": "u-team"}, {"user_id": "u-team-gone"}]}
    )
    project = Project(
        id="p",
        name="p",
        team_ids=["alpha"],
        team_id="alpha",
        members=[ProjectMember(user_id="u-direct"), ProjectMember(user_id="u-direct-gone")],
    )

    sent = await _notify(db, project, forced_channels=_ALL_CHANNELS)

    assert sent == _on_every_channel("u-direct") | _on_every_channel("u-team")


@pytest.mark.asyncio
async def test_a_deactivated_admins_enforced_prefs_no_longer_apply(db):
    await _seed_user(db, "u-admin-gone", active=False)
    await _seed_user(db, "u-member")
    project = Project(
        id="p",
        name="p",
        enforce_notification_settings=True,
        members=[
            ProjectMember(user_id="u-admin-gone", role="admin", notification_preferences={_EVENT: ["slack"]}),
            ProjectMember(user_id="u-member", notification_preferences={_EVENT: ["email"]}),
        ],
    )

    assert await _notify(db, project) == {("email", "u-member@test.com")}


@pytest.mark.asyncio
async def test_an_active_admins_enforced_prefs_still_apply_past_a_deactivated_one(db):
    await _seed_user(db, "u-admin-gone", active=False)
    await _seed_user(db, "u-admin")
    await _seed_user(db, "u-member")
    project = Project(
        id="p",
        name="p",
        enforce_notification_settings=True,
        members=[
            ProjectMember(user_id="u-admin-gone", role="admin", notification_preferences={_EVENT: ["slack"]}),
            ProjectMember(user_id="u-admin", role="admin", notification_preferences={_EVENT: ["mattermost"]}),
            ProjectMember(user_id="u-member", notification_preferences={_EVENT: ["email"]}),
        ],
    )

    assert await _notify(db, project) == {("mattermost", "@u-admin"), ("mattermost", "@u-member")}


async def _seed_team(db, *members: tuple[str, str]) -> None:
    await db.teams.insert_one(
        {"_id": "alpha", "name": "Alpha", "members": [{"user_id": uid, "role": role} for uid, role in members]}
    )


@pytest.mark.asyncio
async def test_a_team_admins_project_overrides_are_enforced_on_every_member(db):
    await _seed_user(db, "u-team-admin")
    await _seed_user(db, "u-member")
    await _seed_team(db, ("u-team-admin", "admin"))
    project = Project(
        id="p",
        name="p",
        team_ids=["alpha"],
        enforce_notification_settings=True,
        notification_overrides={"u-team-admin": {_EVENT: ["slack"]}},
        members=[ProjectMember(user_id="u-member", notification_preferences={_EVENT: ["email"]})],
    )

    assert await _notify(db, project) == {("slack", "u-team-admin"), ("slack", "u-member")}


@pytest.mark.asyncio
async def test_a_direct_viewer_who_admins_an_owning_team_enforces_their_member_prefs(db):
    await _seed_user(db, "u-team-admin")
    await _seed_user(db, "u-member")
    await _seed_team(db, ("u-team-admin", "admin"))
    project = Project(
        id="p",
        name="p",
        team_ids=["alpha"],
        enforce_notification_settings=True,
        members=[
            ProjectMember(user_id="u-member", notification_preferences={_EVENT: ["email"]}),
            ProjectMember(user_id="u-team-admin", role="viewer", notification_preferences={_EVENT: ["mattermost"]}),
        ],
    )

    assert await _notify(db, project) == {("mattermost", "@u-team-admin"), ("mattermost", "@u-member")}


@pytest.mark.asyncio
async def test_a_direct_admins_prefs_win_over_a_team_admins_overrides(db):
    await _seed_user(db, "u-team-admin")
    await _seed_user(db, "u-admin")
    await _seed_team(db, ("u-team-admin", "admin"))
    project = Project(
        id="p",
        name="p",
        team_ids=["alpha"],
        enforce_notification_settings=True,
        notification_overrides={"u-team-admin": {_EVENT: ["slack"]}},
        members=[ProjectMember(user_id="u-admin", role="admin", notification_preferences={_EVENT: ["email"]})],
    )

    assert await _notify(db, project) == {("email", "u-admin@test.com"), ("email", "u-team-admin@test.com")}


@pytest.mark.asyncio
async def test_a_plain_team_members_overrides_enforce_nothing(db):
    await _seed_user(db, "u-team-member")
    await _seed_user(db, "u-member")
    await _seed_team(db, ("u-team-member", "member"))
    project = Project(
        id="p",
        name="p",
        team_ids=["alpha"],
        enforce_notification_settings=True,
        notification_overrides={"u-team-member": {_EVENT: ["slack"]}},
        members=[ProjectMember(user_id="u-member", notification_preferences={_EVENT: ["email"]})],
    )

    assert await _notify(db, project) == {("slack", "u-team-member"), ("email", "u-member@test.com")}
