"""Tests for webhook API endpoints.

Tests CRUD operations for project and global webhooks, update validation,
and test-webhook functionality.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.models.webhook import Webhook

MODULE = "app.api.v1.endpoints.webhooks"


def _make_webhook(id="wh-1", project_id="proj-1", url="https://example.com/hook", events=None, **kwargs):
    """Create a Webhook with sensible defaults."""
    if events is None:
        events = ["scan_completed"]
    return Webhook(id=id, project_id=project_id, url=url, events=events, **kwargs)


class TestCreateWebhook:
    def test_success_creates_project_webhook(self, regular_user):
        from app.api.v1.endpoints.webhooks import create_webhook
        from app.schemas.webhook import WebhookCreate

        webhook = _make_webhook()
        mock_repo = MagicMock()
        mock_repo.create = AsyncMock(return_value=webhook)

        with patch(f"{MODULE}.check_webhook_create_permission", new_callable=AsyncMock):
            with patch(f"{MODULE}.WebhookRepository", return_value=mock_repo):
                result = asyncio.run(
                    create_webhook(
                        project_id="proj-1",
                        webhook_in=WebhookCreate(url="https://example.com/hook", events=["scan_completed"]),
                        current_user=regular_user,
                        db=MagicMock(),
                    )
                )

        assert result.url == "https://example.com/hook"
        mock_repo.create.assert_called_once()


class TestCreateGlobalWebhook:
    def test_success_creates_global_webhook(self, admin_user):
        from app.api.v1.endpoints.webhooks import create_global_webhook
        from app.schemas.webhook import WebhookCreate

        webhook = _make_webhook(project_id=None)
        mock_repo = MagicMock()
        mock_repo.create = AsyncMock(return_value=webhook)

        with patch(f"{MODULE}.WebhookRepository", return_value=mock_repo):
            result = asyncio.run(
                create_global_webhook(
                    webhook_in=WebhookCreate(url="https://example.com/hook", events=["scan_completed"]),
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert result.project_id is None
        mock_repo.create.assert_called_once()


class TestListWebhooks:
    def test_returns_paginated_project_webhooks(self, regular_user):
        from app.api.v1.endpoints.webhooks import list_webhooks

        webhooks = [_make_webhook(id="wh-1"), _make_webhook(id="wh-2")]
        mock_repo = MagicMock()
        mock_repo.count_by_project = AsyncMock(return_value=2)
        mock_repo.find_by_project = AsyncMock(return_value=webhooks)

        with patch(f"{MODULE}.check_webhook_list_permission", new_callable=AsyncMock):
            with patch(f"{MODULE}.WebhookRepository", return_value=mock_repo):
                result = asyncio.run(
                    list_webhooks(
                        project_id="proj-1",
                        skip=0,
                        limit=50,
                        current_user=regular_user,
                        db=MagicMock(),
                    )
                )

        assert result["total"] == 2
        assert len(result["items"]) == 2


class TestListGlobalWebhooks:
    def test_returns_paginated_global_webhooks(self, admin_user):
        from app.api.v1.endpoints.webhooks import list_global_webhooks

        webhooks = [_make_webhook(project_id=None)]
        mock_repo = MagicMock()
        mock_repo.count_global = AsyncMock(return_value=1)
        mock_repo.find_global = AsyncMock(return_value=webhooks)

        with patch(f"{MODULE}.WebhookRepository", return_value=mock_repo):
            result = asyncio.run(
                list_global_webhooks(
                    skip=0,
                    limit=50,
                    current_user=admin_user,
                    db=MagicMock(),
                )
            )

        assert result["total"] == 1


class TestGetWebhook:
    def test_returns_webhook(self, regular_user):
        from app.api.v1.endpoints.webhooks import get_webhook

        webhook = _make_webhook()
        mock_repo = MagicMock()

        with patch(f"{MODULE}.WebhookRepository", return_value=mock_repo):
            with patch(f"{MODULE}.get_webhook_or_404", new_callable=AsyncMock, return_value=webhook):
                with patch(f"{MODULE}.check_webhook_permission", new_callable=AsyncMock):
                    result = asyncio.run(
                        get_webhook(
                            webhook_id="wh-1",
                            current_user=regular_user,
                            db=MagicMock(),
                        )
                    )

        assert result.url == "https://example.com/hook"

    def test_raises_404_when_not_found(self, regular_user):
        from app.api.v1.endpoints.webhooks import get_webhook

        mock_repo = MagicMock()

        with patch(f"{MODULE}.WebhookRepository", return_value=mock_repo):
            with patch(
                f"{MODULE}.get_webhook_or_404",
                new_callable=AsyncMock,
                side_effect=HTTPException(status_code=404, detail="Webhook not found"),
            ):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        get_webhook(
                            webhook_id="missing",
                            current_user=regular_user,
                            db=MagicMock(),
                        )
                    )
        assert exc_info.value.status_code == 404


class TestUpdateWebhook:
    def test_success_updates_webhook(self, regular_user):
        from app.api.v1.endpoints.webhooks import update_webhook
        from app.schemas.webhook import WebhookUpdate

        webhook = _make_webhook()
        updated_webhook = _make_webhook(url="https://new.example.com/hook")
        mock_repo = MagicMock()
        mock_repo.update = AsyncMock(return_value=updated_webhook)

        with patch(f"{MODULE}.WebhookRepository", return_value=mock_repo):
            with patch(f"{MODULE}.get_webhook_or_404", new_callable=AsyncMock, return_value=webhook):
                with patch(f"{MODULE}.check_webhook_permission", new_callable=AsyncMock):
                    result = asyncio.run(
                        update_webhook(
                            webhook_id="wh-1",
                            webhook_update=WebhookUpdate(url="https://new.example.com/hook"),
                            current_user=regular_user,
                            db=MagicMock(),
                        )
                    )

        assert result.url == "https://new.example.com/hook"

    def test_raises_400_on_empty_update(self, regular_user):
        from app.api.v1.endpoints.webhooks import update_webhook
        from app.schemas.webhook import WebhookUpdate

        webhook = _make_webhook()
        mock_repo = MagicMock()

        with patch(f"{MODULE}.WebhookRepository", return_value=mock_repo):
            with patch(f"{MODULE}.get_webhook_or_404", new_callable=AsyncMock, return_value=webhook):
                with patch(f"{MODULE}.check_webhook_permission", new_callable=AsyncMock):
                    with pytest.raises(HTTPException) as exc_info:
                        asyncio.run(
                            update_webhook(
                                webhook_id="wh-1",
                                webhook_update=WebhookUpdate(),
                                current_user=regular_user,
                                db=MagicMock(),
                            )
                        )
        assert exc_info.value.status_code == 400
        assert "No fields" in exc_info.value.detail


class TestDeleteWebhook:
    def test_success_deletes_webhook(self, regular_user):
        from app.api.v1.endpoints.webhooks import delete_webhook

        webhook = _make_webhook()
        mock_repo = MagicMock()
        mock_repo.delete = AsyncMock()

        with patch(f"{MODULE}.WebhookRepository", return_value=mock_repo):
            with patch(f"{MODULE}.get_webhook_or_404", new_callable=AsyncMock, return_value=webhook):
                with patch(f"{MODULE}.check_webhook_permission", new_callable=AsyncMock):
                    asyncio.run(
                        delete_webhook(
                            webhook_id="wh-1",
                            current_user=regular_user,
                            db=MagicMock(),
                        )
                    )

        mock_repo.delete.assert_called_once_with("wh-1")


class TestTestWebhook:
    def test_success_returns_result(self, regular_user):
        from app.api.v1.endpoints.webhooks import test_webhook

        webhook = _make_webhook()
        mock_repo = MagicMock()
        test_result = {"success": True, "status_code": 200, "response_time_ms": 42.5}

        with patch(f"{MODULE}.WebhookRepository", return_value=mock_repo):
            with patch(f"{MODULE}.get_webhook_or_404", new_callable=AsyncMock, return_value=webhook):
                with patch(f"{MODULE}.check_webhook_permission", new_callable=AsyncMock):
                    with patch(f"{MODULE}.webhook_service") as mock_svc:
                        mock_svc.test_webhook = AsyncMock(return_value=test_result)
                        result = asyncio.run(
                            test_webhook(
                                webhook_id="wh-1",
                                current_user=regular_user,
                                db=MagicMock(),
                            )
                        )

        assert result.success is True
        assert result.status_code == 200
