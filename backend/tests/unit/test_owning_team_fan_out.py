"""Who hears about a project's events, once several teams own it.

An owning team's members can read the project, so leaving one of them out of a notification or
skipping its webhook is the same under-reach the visibility filter had: the mirrored scalar names
one owner and the reach was built from it. Both are asserted from the other side too — a team that
owns nothing must reach nobody.
"""

import pytest

from app.models.project import Project, ProjectMember
from app.services.notifications.service import NotificationService
from app.services.webhooks.webhook_service import WebhookService

_PROJECT = "p-fanout"
_EVENT = "scan.completed"
_PREFS_EVENT = "analysis_completed"


async def _seed_teams(db) -> None:
    await db.teams.insert_one({"_id": "alpha", "name": "Alpha", "members": [{"user_id": "u-alpha"}]})
    await db.teams.insert_one({"_id": "bravo", "name": "Bravo", "members": [{"user_id": "u-bravo"}]})
    await db.teams.insert_one({"_id": "zulu", "name": "Zulu", "members": [{"user_id": "u-zulu"}]})


async def _seed_users(db) -> None:
    for uid in ("u-direct", "u-alpha", "u-bravo", "u-zulu"):
        await db.users.insert_one(
            {
                "_id": uid,
                "username": uid,
                "email": f"{uid}@test.com",
                "is_active": True,
                "permissions": [],
                "notification_preferences": {_PREFS_EVENT: ["email"]},
            }
        )


def _project(owners: list[str]) -> Project:
    return Project(
        id=_PROJECT,
        name="fanout",
        team_ids=owners,
        members=[ProjectMember(user_id="u-direct", role="admin")],
    )


def _recording_service(reached: dict[str, str]) -> NotificationService:
    service = NotificationService()

    def recorder(channel: str):
        async def send(destination, *_args, **_kwargs):
            reached[destination.removesuffix("@test.com")] = channel

        return send

    service.email_provider.send = recorder("email")  # type: ignore[method-assign]
    service.slack_provider.send = recorder("slack")  # type: ignore[method-assign]
    return service


async def _notified(db, owners: list[str]) -> set[str]:
    reached: dict[str, str] = {}
    await _recording_service(reached).notify_project_members(_project(owners), _PREFS_EVENT, "s", "m", db)
    return set(reached)


@pytest.mark.asyncio
async def test_every_owning_team_is_notified(db):
    await _seed_teams(db)
    await _seed_users(db)

    assert await _notified(db, ["alpha", "bravo"]) == {"u-direct", "u-alpha", "u-bravo"}


@pytest.mark.asyncio
async def test_a_team_owning_nothing_is_not_notified(db):
    await _seed_teams(db)
    await _seed_users(db)

    assert await _notified(db, ["alpha"]) == {"u-direct", "u-alpha"}


@pytest.mark.asyncio
async def test_an_unowned_project_notifies_only_its_own_members(db):
    await _seed_teams(db)
    await _seed_users(db)

    assert await _notified(db, []) == {"u-direct"}


_PROJECT_OVERRIDE = {_PREFS_EVENT: ["slack"]}
_ACCOUNT_DEFAULT = {_PREFS_EVENT: ["email"]}


async def _seed_member_of_alpha(db) -> None:
    await db.teams.insert_one({"_id": "alpha", "name": "Alpha", "members": [{"user_id": "u-both"}]})
    await db.users.insert_one(
        {
            "_id": "u-both",
            "username": "u-both",
            "email": "u-both@test.com",
            "slack_username": "u-both",
            "is_active": True,
            "permissions": [],
            "notification_preferences": _ACCOUNT_DEFAULT,
        }
    )


@pytest.mark.asyncio
async def test_a_project_channel_override_survives_the_same_users_team_membership(db):
    await _seed_member_of_alpha(db)
    seen: dict[str, str] = {}

    await _recording_service(seen).notify_project_members(
        project=Project(
            id=_PROJECT,
            name="fanout",
            team_ids=["alpha"],
            members=[ProjectMember(user_id="u-both", role="admin", notification_preferences=_PROJECT_OVERRIDE)],
        ),
        event_type=_PREFS_EVENT,
        subject="s",
        message="m",
        db=db,
    )

    assert seen == {"u-both": "slack"}


async def _seed_webhooks(db) -> None:
    for index, team_id in enumerate(("alpha", "bravo", "zulu", None)):
        await db.webhooks.insert_one(
            {
                "_id": f"w{index}",
                "url": f"https://example.com/{team_id}",
                "team_id": team_id,
                "project_id": None,
                "events": [_EVENT],
                "is_active": True,
            }
        )


async def _fired(db, owners: list[str]) -> set[str]:
    await db.projects.insert_one({"_id": _PROJECT, "name": "fanout", "team_ids": owners})
    hooks = await WebhookService()._get_webhooks_for_event(db, _PROJECT, _EVENT)
    return {hook.id for hook in hooks}


@pytest.mark.asyncio
async def test_every_owning_teams_webhook_fires(db):
    await _seed_webhooks(db)

    # w3 is the global hook, which fires for every project.
    assert await _fired(db, ["alpha", "bravo"]) == {"w0", "w1", "w3"}


@pytest.mark.asyncio
async def test_a_team_owning_nothing_does_not_fire(db):
    await _seed_webhooks(db)

    assert await _fired(db, ["alpha"]) == {"w0", "w3"}


@pytest.mark.asyncio
async def test_an_unowned_project_fires_only_the_global_hook(db):
    await _seed_webhooks(db)

    assert await _fired(db, []) == {"w3"}
