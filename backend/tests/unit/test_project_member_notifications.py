"""Who the project fan-out reaches (a deactivated account keeps its memberships) and on which channels."""

import pytest

from app.models.project import Project, ProjectMember
from app.services.notifications.service import NotificationService

_EVENT = "vulnerability_found"
_ALL_CHANNELS = ["email", "slack", "mattermost"]
_MUTED = {"analysis_completed": [], _EVENT: []}


async def _seed_user(db, uid: str, *, active: bool = True, prefs: dict | None = None, slack: str | None = None) -> None:
    await db.users.insert_one(
        {
            "_id": uid,
            "username": uid,
            "email": f"{uid}@test.com",
            "slack_username": slack or uid,
            "mattermost_username": uid,
            "is_active": active,
            "permissions": [],
            "notification_preferences": prefs or {},
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


async def _notify(db, project: Project) -> set[tuple[str, str]]:
    sent: set[tuple[str, str]] = set()
    await _recording_service(sent).notify_project_members(project, _EVENT, "s", "m", db)
    return sent


def _on_every_channel(uid: str) -> set[tuple[str, str]]:
    return {("email", f"{uid}@test.com"), ("slack", uid), ("mattermost", f"@{uid}")}


@pytest.mark.asyncio
async def test_deactivated_direct_and_team_members_are_sent_nothing_on_any_channel(db):
    for uid in ("u-direct", "u-team"):
        await _seed_user(db, uid, prefs={_EVENT: _ALL_CHANNELS})
    for uid in ("u-direct-gone", "u-team-gone"):
        await _seed_user(db, uid, active=False, prefs={_EVENT: _ALL_CHANNELS})
    await db.teams.insert_one(
        {"_id": "alpha", "name": "Alpha", "members": [{"user_id": "u-team"}, {"user_id": "u-team-gone"}]}
    )
    project = Project(
        id="p",
        name="p",
        team_ids=["alpha"],
        members=[ProjectMember(user_id="u-direct"), ProjectMember(user_id="u-direct-gone")],
    )

    assert await _notify(db, project) == _on_every_channel("u-direct") | _on_every_channel("u-team")


@pytest.mark.asyncio
async def test_a_member_who_muted_the_project_is_sent_nothing_despite_their_account_preferences(db):
    await _seed_user(db, "u-muted", prefs={_EVENT: ["email"]})
    await _seed_user(db, "u-default", prefs={_EVENT: ["email"]})
    project = Project(
        id="p",
        name="p",
        members=[
            ProjectMember(user_id="u-muted", notification_preferences=_MUTED),
            ProjectMember(user_id="u-default"),
        ],
    )

    assert await _notify(db, project) == {("email", "u-default@test.com")}


@pytest.mark.asyncio
async def test_a_team_member_who_muted_the_project_is_sent_nothing(db):
    await _seed_user(db, "u-team", prefs={_EVENT: ["email"]})
    await db.teams.insert_one({"_id": "alpha", "name": "Alpha", "members": [{"user_id": "u-team"}]})
    project = Project(id="p", name="p", team_ids=["alpha"], notification_overrides={"u-team": _MUTED})

    assert await _notify(db, project) == set()


@pytest.mark.asyncio
async def test_the_projects_enforced_preferences_reach_every_member_whatever_the_admins_own_are(db):
    await _seed_user(db, "u-admin")
    await _seed_user(db, "u-member", prefs={_EVENT: ["email"]})
    await _seed_user(db, "u-team")
    await db.teams.insert_one({"_id": "alpha", "name": "Alpha", "members": [{"user_id": "u-team", "role": "admin"}]})
    project = Project(
        id="p",
        name="p",
        team_ids=["alpha"],
        enforce_notification_settings=True,
        enforced_notification_preferences={_EVENT: ["mattermost"]},
        notification_overrides={"u-team": {_EVENT: ["slack"]}},
        members=[
            ProjectMember(user_id="u-admin", role="admin", notification_preferences={_EVENT: ["email"]}),
            ProjectMember(user_id="u-member", notification_preferences={_EVENT: ["slack"]}),
        ],
    )

    assert await _notify(db, project) == {("mattermost", f"@{uid}") for uid in ("u-admin", "u-member", "u-team")}


@pytest.mark.parametrize("enforced", [{}, _MUTED, {"analysis_completed": ["email"]}], ids=["unset", "muted", "other"])
@pytest.mark.asyncio
async def test_enforcement_without_a_channel_for_the_event_sends_nothing_and_reads_nothing(db, enforced):
    project = Project(
        id="p",
        name="p",
        enforce_notification_settings=True,
        enforced_notification_preferences=enforced,
        members=[ProjectMember(user_id="u-admin", role="admin", notification_preferences={_EVENT: ["email"]})],
    )
    db.users.find = db.system_settings.find_one = None

    assert await _notify(db, project) == set()


@pytest.mark.asyncio
async def test_nobody_subscribed_reads_no_settings(db):
    await _seed_user(db, "u-member")
    db.system_settings.find_one = None

    assert await _notify(db, Project(id="p", name="p", members=[ProjectMember(user_id="u-member")])) == set()


@pytest.mark.asyncio
async def test_a_slack_member_id_written_with_an_at_sign_still_reaches_the_member(db):
    await _seed_user(db, "u-member", prefs={_EVENT: ["slack"]}, slack="@U0123ABCD")

    assert await _notify(db, Project(id="p", name="p", members=[ProjectMember(user_id="u-member")])) == {
        ("slack", "U0123ABCD")
    }
