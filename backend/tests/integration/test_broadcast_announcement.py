"""An announcement reaches its whole audience, formatted, on the channels the broadcaster chose."""

from unittest.mock import AsyncMock

import pytest

from app.services.notifications.service import notification_service

_PAST_THE_USER_CAP = 2001
_PAST_THE_TEAM_CAP = 101


async def _seed_users(db, count: int) -> list[str]:
    ids = [f"u{index}" for index in range(count)]
    await db.users.insert_many(
        [{"_id": uid, "username": uid, "email": f"{uid}@example.com", "is_active": True} for uid in ids]
    )
    return ids


async def _announce(client, headers, **overrides):
    body = {"target_type": "global", "subject": "s", "message": "m", "channels": ["email"], **overrides}
    return await client.post("/api/v1/notifications/broadcast", json=body, headers=headers)


def _delivered(sent: AsyncMock) -> int:
    return sum(len(call.args[0]) for call in sent.await_args_list)


@pytest.fixture
def sent(monkeypatch):
    mock = AsyncMock()
    monkeypatch.setattr(notification_service, "notify_users", mock)
    return mock


@pytest.mark.asyncio
async def test_an_announcement_without_a_channel_is_refused(client, db, admin_auth_headers, sent):
    await _seed_users(db, 1)

    resp = await _announce(client, admin_auth_headers, channels=[])

    assert resp.status_code == 400
    sent.assert_not_awaited()


@pytest.mark.asyncio
async def test_the_announcement_email_carries_the_markdown_rendered_once(client, db, admin_auth_headers, sent):
    await _seed_users(db, 1)

    resp = await _announce(client, admin_auth_headers, message="Maintenance **tonight**")

    assert resp.status_code == 200, resp.text
    [call] = sent.await_args_list
    assert "<strong>tonight</strong>" in call.kwargs["html_message"]
    assert "&lt;p&gt;" not in call.kwargs["html_message"]


@pytest.mark.asyncio
async def test_a_global_announcement_reaches_and_counts_every_active_user(client, db, admin_auth_headers, sent):
    await _seed_users(db, _PAST_THE_USER_CAP)

    resp = await _announce(client, admin_auth_headers)

    assert resp.json()["recipient_count"] == _PAST_THE_USER_CAP
    assert _delivered(sent) == _PAST_THE_USER_CAP


@pytest.mark.asyncio
async def test_a_team_announcement_reaches_the_members_of_every_selected_team(client, db, admin_auth_headers, sent):
    ids = await _seed_users(db, _PAST_THE_TEAM_CAP)
    await db.teams.insert_many(
        [{"_id": f"t{uid}", "name": f"t{uid}", "members": [{"user_id": uid, "role": "member"}]} for uid in ids]
    )

    resp = await _announce(client, admin_auth_headers, target_type="teams", target_teams=[f"t{uid}" for uid in ids])

    assert resp.json()["recipient_count"] == _PAST_THE_TEAM_CAP
    assert _delivered(sent) == _PAST_THE_TEAM_CAP
