"""Verify that policy audit changes trigger in-app notifications through the
correct NotificationService methods."""

from unittest.mock import AsyncMock

import pytest


def _rule_dict(rule_id: str) -> dict:
    return {
        "rule_id": rule_id,
        "name": rule_id,
        "description": "",
        "finding_type": "crypto_weak_algorithm",
        "default_severity": "HIGH",
        "source": "custom",
        "match_name_patterns": ["X"],
        "enabled": True,
    }


@pytest.mark.asyncio
async def test_system_policy_change_notifies_users_with_permission(
    client,
    db,
    admin_auth_headers,
    monkeypatch,
):
    """System-scope changes should call notify_users_with_permission with
    ``system:manage`` (and analytics:global) so that admins are reached."""
    from app.services.notifications import service as svc_mod

    mock_perm = AsyncMock()
    mock_members = AsyncMock()
    monkeypatch.setattr(svc_mod.notification_service, "notify_users_with_permission", mock_perm)
    monkeypatch.setattr(svc_mod.notification_service, "notify_project_members", mock_members)

    resp = await client.put(
        "/api/v1/crypto-policies/system",
        json={"rules": [_rule_dict("r1")], "comment": "Q2"},
        headers=admin_auth_headers,
    )
    assert resp.status_code == 200

    mock_perm.assert_awaited()
    call = mock_perm.await_args
    assert call.kwargs.get("permission") == ["system:manage", "analytics:global"]
    assert call.kwargs.get("event_type") == "crypto_policy_changed"
    mock_members.assert_not_awaited()


@pytest.mark.asyncio
async def test_project_policy_change_notifies_project_members(
    client,
    db,
    owner_auth_headers_proj,
    monkeypatch,
):
    """Project-scope changes should call notify_project_members with the
    resolved Project object, not the bare id."""
    from app.services.notifications import service as svc_mod

    mock_perm = AsyncMock()
    mock_members = AsyncMock()
    monkeypatch.setattr(svc_mod.notification_service, "notify_users_with_permission", mock_perm)
    monkeypatch.setattr(svc_mod.notification_service, "notify_project_members", mock_members)

    resp = await client.put(
        "/api/v1/projects/p/crypto-policy",
        json={"rules": [_rule_dict("pr1")], "comment": "override"},
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200

    mock_members.assert_awaited()
    call = mock_members.await_args
    project_arg = call.kwargs.get("project")
    assert project_arg is not None
    assert getattr(project_arg, "id", None) == "p"
    assert call.kwargs.get("event_type") == "crypto_policy_changed"
    mock_perm.assert_not_awaited()
