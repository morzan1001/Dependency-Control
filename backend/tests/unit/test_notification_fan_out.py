"""A permission fan-out reaches every holder of the permission.

Nothing in a notification tells a recipient who else was told, so a ceiling on the read is a
ceiling on who learns about the change — and the ones past it never find out they were skipped.
"""

import pytest

from app.services.notifications.service import _FAN_OUT_BATCH_SIZE, NotificationService

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
        db, permission=_PERMISSION, event_type=_EVENT, subject="s", message="m"
    )

    assert sum(len(batch) for batch in recorded) == _MORE_THAN_ONE_BATCH


@pytest.mark.asyncio
async def test_the_fan_out_is_split_into_bounded_batches(db):
    _seed_admins(db, _MORE_THAN_ONE_BATCH)
    recorded: list[list[str]] = []

    await _recording_service(recorded).notify_users_with_permission(
        db, permission=_PERMISSION, event_type=_EVENT, subject="s", message="m"
    )

    assert len(recorded) == _BATCHES_FOR_ONE_OVER
    assert max(len(batch) for batch in recorded) == _FAN_OUT_BATCH_SIZE


@pytest.mark.asyncio
async def test_no_holders_means_no_batch_at_all(db):
    recorded: list[list[str]] = []

    await _recording_service(recorded).notify_users_with_permission(
        db, permission=_PERMISSION, event_type=_EVENT, subject="s", message="m"
    )

    assert recorded == []
