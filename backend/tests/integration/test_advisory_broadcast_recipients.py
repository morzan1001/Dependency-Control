"""An advisory broadcast reaches every project admin, including those an owning team makes admin."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.services.notifications.service import notification_service

_NOW = datetime(2026, 9, 28, tzinfo=timezone.utc)
_PAST_THE_USER_CAP = 2001


async def _seed_affected_project(db, *, members: list[dict], team_ids: list[str]) -> None:
    await db.projects.insert_one(
        {"_id": "adv-p", "name": "advised", "members": members, "team_ids": team_ids, "latest_scan_id": "adv-s"}
    )
    await db.scans.insert_one(
        {"_id": "adv-s", "project_id": "adv-p", "branch": "main", "status": "completed", "created_at": _NOW}
    )
    await db.dependencies.insert_one(
        {"_id": "adv-d", "project_id": "adv-p", "scan_id": "adv-s", "name": "left-pad", "version": "1.0.0"}
    )


async def _seed_user(db, user_id: str) -> None:
    await db.users.insert_one(
        {"_id": user_id, "username": user_id, "email": f"{user_id}@example.com", "is_active": True}
    )


async def _advise(client, headers, **overrides) -> dict:
    body = {"target_type": "advisory", "packages": [{"name": "left-pad"}], "subject": "s", "message": "m"}
    resp = await client.post("/api/v1/notifications/broadcast", json={**body, **overrides}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _recipients(client, headers) -> int:
    return (await _advise(client, headers, dry_run=True))["recipient_count"]


@pytest.mark.asyncio
async def test_the_admin_of_an_owning_team_is_a_recipient(client, db, admin_auth_headers):
    await _seed_user(db, "team-admin")
    await _seed_user(db, "team-member")
    await db.teams.insert_one(
        {
            "_id": "adv-t",
            "name": "owners",
            "members": [{"user_id": "team-admin", "role": "admin"}, {"user_id": "team-member", "role": "member"}],
        }
    )
    await _seed_affected_project(db, members=[], team_ids=["adv-t"])

    assert await _recipients(client, admin_auth_headers) == 1


@pytest.mark.asyncio
async def test_a_direct_admin_reached_through_a_team_too_is_counted_once(client, db, admin_auth_headers):
    await _seed_user(db, "both")
    await db.teams.insert_one({"_id": "adv-t", "name": "owners", "members": [{"user_id": "both", "role": "admin"}]})
    await _seed_affected_project(db, members=[{"user_id": "both", "role": "admin"}], team_ids=["adv-t"])

    assert await _recipients(client, admin_auth_headers) == 1


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_every_active_admin_is_counted_however_many_there_are(client, db, admin_auth_headers):
    ids = [f"a{index}" for index in range(_PAST_THE_USER_CAP)]
    await db.users.insert_many(
        [{"_id": uid, "username": uid, "email": f"{uid}@example.com", "is_active": True} for uid in ids]
    )
    await _seed_affected_project(db, members=[{"user_id": uid, "role": "admin"} for uid in ids], team_ids=[])

    assert await _recipients(client, admin_auth_headers) == _PAST_THE_USER_CAP


@pytest.mark.asyncio
async def test_the_advisory_email_is_the_branded_template_with_formatted_markdown(
    client, db, admin_auth_headers, monkeypatch
):
    sent = AsyncMock()
    monkeypatch.setattr(notification_service, "notify_users", sent)
    await _seed_user(db, "adv-admin")
    await _seed_affected_project(db, members=[{"user_id": "adv-admin", "role": "admin"}], team_ids=[])

    await _advise(client, admin_auth_headers, message="Upgrade **now**", channels=["email"])

    [call] = sent.await_args_list
    assert "Upgrade <strong>now</strong>" in call.kwargs["html_message"]
    assert "/projects/adv-p" in call.kwargs["html_message"]
    assert "cid:logo" in call.kwargs["html_message"]
