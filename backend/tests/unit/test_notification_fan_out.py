"""A permission fan-out reaches every holder of the permission.

Nothing in a notification tells a recipient who else was told, so a ceiling on the read is a
ceiling on who learns about the change — and the ones past it never find out they were skipped.
"""

import asyncio

import pytest

from app.models.user import User
from app.services.notifications.service import _CONCURRENT_SENDS, _FAN_OUT_BATCH_SIZE, NotificationService

_PERMISSION = "system:manage"
_EVENT = "policy_changed"
_MORE_THAN_ONE_BATCH = _FAN_OUT_BATCH_SIZE + 1
_BATCHES_FOR_ONE_OVER = 2


def _seed_admins(db, count: int) -> None:
    for index in range(count):
        db.users._docs[f"u{index}"] = {
            "_id": f"u{index}",
            "username": f"admin-{index}",
            "email": f"admin-{index}@example.com",
            "is_active": True,
            "permissions": [_PERMISSION],
        }


def _recording_service(recorded: list[list[str]]) -> NotificationService:
    service = NotificationService()

    async def record(users, **_kwargs):
        recorded.append([user.username for user in users])

    service.notify_users = record  # type: ignore[method-assign]
    return service


@pytest.mark.asyncio
async def test_every_permission_holder_past_the_batch_is_notified(db):
    _seed_admins(db, _MORE_THAN_ONE_BATCH)
    recorded: list[list[str]] = []

    await _recording_service(recorded).notify_users_with_permission(
        db, permission=[_PERMISSION], event_type=_EVENT, subject="s", message="m"
    )

    assert sum(len(batch) for batch in recorded) == _MORE_THAN_ONE_BATCH


@pytest.mark.asyncio
async def test_the_fan_out_is_split_into_bounded_batches(db):
    _seed_admins(db, _MORE_THAN_ONE_BATCH)
    recorded: list[list[str]] = []

    await _recording_service(recorded).notify_users_with_permission(
        db, permission=[_PERMISSION], event_type=_EVENT, subject="s", message="m"
    )

    assert len(recorded) == _BATCHES_FOR_ONE_OVER
    assert max(len(batch) for batch in recorded) == _FAN_OUT_BATCH_SIZE


@pytest.mark.asyncio
async def test_no_holders_means_no_batch_at_all(db):
    recorded: list[list[str]] = []

    await _recording_service(recorded).notify_users_with_permission(
        db, permission=[_PERMISSION], event_type=_EVENT, subject="s", message="m"
    )

    assert recorded == []


def _deactivate(db, username: str) -> None:
    db.users._docs[username]["is_active"] = False


@pytest.mark.asyncio
async def test_a_deactivated_holder_of_the_permission_is_not_reached(db):
    _seed_admins(db, 2)
    _deactivate(db, "u0")
    recorded: list[list[str]] = []

    await _recording_service(recorded).notify_users_with_permission(
        db, permission=[_PERMISSION], event_type=_EVENT, subject="s", message="m"
    )

    assert [user for batch in recorded for user in batch] == ["admin-1"]


@pytest.mark.asyncio
async def test_a_fan_out_to_only_deactivated_holders_sends_nothing(db):
    _seed_admins(db, 1)
    _deactivate(db, "u0")
    recorded: list[list[str]] = []

    await _recording_service(recorded).notify_users_with_permission(
        db, permission=[_PERMISSION], event_type=_EVENT, subject="s", message="m"
    )

    assert recorded == []


@pytest.mark.asyncio
async def test_a_large_audience_is_sent_to_a_bounded_number_at_a_time(db):
    audience = [User(id=f"u{i}", username=f"u{i}", email=f"u{i}@example.com") for i in range(50)]
    service = NotificationService()
    sent: list[str] = []
    in_flight = peak = 0

    async def send(destination, *_args, **_kwargs):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0)
        in_flight -= 1
        sent.append(destination)
        return True

    service.email_provider.send = send  # type: ignore[method-assign]
    await service.notify_users(audience, _EVENT, "s", "m", db=db, forced_channels=["email"])

    assert sorted(sent) == sorted(user.email for user in audience)
    assert peak <= _CONCURRENT_SENDS
