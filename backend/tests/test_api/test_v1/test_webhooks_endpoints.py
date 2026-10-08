"""Tests for webhook API endpoints (CRUD for project/global webhooks, update validation, test-webhook)."""

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.models.webhook import Webhook
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.webhooks"


def _make_webhook(id="wh-1", project_id="proj-1", url="https://example.com/hook", events=None, **kwargs):
    """Create a Webhook with sensible defaults."""
    if events is None:
        events = ["scan_completed"]
    return Webhook(id=id, project_id=project_id, url=url, events=events, **kwargs)


_TEAMS_URL = "https://contoso.webhook.office.com/webhookb2/abc/IncomingWebhook/xyz"
_POWER_PLATFORM_URL = (
    "https://default123.environment.api.powerplatform.com"
    "/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke"
)
_PLAIN_URL = "https://my-server.example.com/webhook"
_SCOPE_IDS = {"project": ("proj-1", None), "team": (None, "team-1"), "global": (None, None)}
_SECRET = "hmac-signing-key"


def _create(scope, db, user, webhook_in):
    from app.api.v1.endpoints import webhooks as endpoints

    if scope == "project":
        return endpoints.create_webhook(project_id="proj-1", webhook_in=webhook_in, current_user=user, db=db)
    if scope == "team":
        return endpoints.create_team_webhook(team_id="team-1", webhook_in=webhook_in, current_user=user, db=db)
    return endpoints.create_global_webhook(webhook_in=webhook_in, current_user=user, db=db)


def _list(scope, db, user):
    from app.api.v1.endpoints import webhooks as endpoints

    if scope == "project":
        return endpoints.list_webhooks(project_id="proj-1", skip=0, limit=50, current_user=user, db=db)
    if scope == "team":
        return endpoints.list_team_webhooks(team_id="team-1", skip=0, limit=50, current_user=user, db=db)
    return endpoints.list_global_webhooks(skip=0, limit=50, current_user=user, db=db)


class TestCreateWebhook:
    @pytest.mark.parametrize("scope", list(_SCOPE_IDS))
    @pytest.mark.parametrize(
        ("url", "webhook_type", "stored"),
        [
            pytest.param(_TEAMS_URL, None, "teams", id="teams-url-detected"),
            pytest.param(_POWER_PLATFORM_URL, None, "teams", id="power-platform-detected"),
            pytest.param(_PLAIN_URL, None, "generic", id="plain-url-detected"),
            pytest.param(_TEAMS_URL, "generic", "generic", id="explicit-generic-wins"),
            pytest.param(_PLAIN_URL, "teams", "teams", id="explicit-teams-wins"),
        ],
    )
    def test_stores_the_explicit_type_or_the_one_detected_from_the_url(
        self, admin_user, scope, url, webhook_type, stored
    ):
        from app.schemas.webhook import WebhookCreate

        db = FakeDatabase()
        webhook_in = WebhookCreate(url=url, events=["scan.completed"], webhook_type=webhook_type)

        with patch(f"{MODULE}.check_webhook_permission", new_callable=AsyncMock):
            created = asyncio.run(_create(scope, db, admin_user, webhook_in))

        doc = db.webhooks._docs[created.id]
        assert (doc["webhook_type"], doc["project_id"], doc["team_id"]) == (stored, *_SCOPE_IDS[scope])


class TestListWebhooks:
    @pytest.mark.parametrize("scope", list(_SCOPE_IDS))
    def test_lists_only_its_scope_newest_first_and_withholds_the_secret(self, admin_user, scope):
        db = FakeDatabase()
        for name, (project_id, team_id) in _SCOPE_IDS.items():
            for age, created_at in (
                ("old", datetime(2026, 1, 1, tzinfo=timezone.utc)),
                ("new", datetime(2026, 2, 1, tzinfo=timezone.utc)),
            ):
                asyncio.run(
                    db.webhooks.insert_one(
                        {
                            "_id": f"{name}-{age}",
                            "url": "https://example.com/hook",
                            "events": ["scan.completed"],
                            "project_id": project_id,
                            "team_id": team_id,
                            "secret": _SECRET,
                            "created_at": created_at,
                        }
                    )
                )

        with patch(f"{MODULE}.check_webhook_permission", new_callable=AsyncMock):
            result = asyncio.run(_list(scope, db, admin_user))

        assert (result["total"], [item["id"] for item in result["items"]]) == (2, [f"{scope}-new", f"{scope}-old"])
        assert _SECRET not in json.dumps(result, default=str)


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

    def test_project_viewer_holding_only_webhook_read_may_read(self):
        """Reading is gated on webhook:read; demanding webhook:update would push every read-only holder onto the project-admin branch."""
        from app.api.v1.endpoints.webhooks import get_webhook
        from app.core.permissions import Permissions
        from app.models.project import Project, ProjectMember
        from app.models.user import User

        reader = User(
            id="reader-1",
            username="reader",
            email="reader@test.com",
            permissions=[Permissions.PROJECT_READ, Permissions.WEBHOOK_READ],
        )
        webhook = _make_webhook()

        async def _run():
            db = FakeDatabase()
            project = Project(
                id="proj-1",
                name="proj-1",
                members=[ProjectMember(user_id="reader-1", role="viewer")],
            )
            await db.projects.insert_one(project.model_dump(by_alias=True))

            with (
                patch(f"{MODULE}.WebhookRepository", return_value=MagicMock()),
                patch(f"{MODULE}.get_webhook_or_404", new_callable=AsyncMock, return_value=webhook),
            ):
                return await get_webhook(webhook_id="wh-1", current_user=reader, db=db)

        assert asyncio.run(_run()).id == "wh-1"

    def test_raises_404_when_not_found(self, regular_user):
        from app.api.v1.endpoints.webhooks import get_webhook

        mock_repo = MagicMock()

        with (
            patch(f"{MODULE}.WebhookRepository", return_value=mock_repo),
            patch(
                f"{MODULE}.get_webhook_or_404",
                new_callable=AsyncMock,
                side_effect=HTTPException(status_code=404, detail="Webhook not found"),
            ),
            pytest.raises(HTTPException) as exc_info,
        ):
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

    @pytest.mark.parametrize(
        ("stored", "update", "expected"),
        [
            pytest.param("generic", {"url": _TEAMS_URL}, "teams", id="to-teams"),
            pytest.param("generic", {"url": _POWER_PLATFORM_URL}, "teams", id="to-power-platform"),
            pytest.param("teams", {"url": _PLAIN_URL}, "generic", id="to-generic"),
            pytest.param("generic", {"url": _TEAMS_URL, "webhook_type": "generic"}, "generic", id="explicit-wins"),
            pytest.param("teams", {"events": ["vulnerability.found"]}, "teams", id="no-url-keeps-type"),
        ],
    )
    def test_a_new_url_redetects_the_type_unless_the_caller_names_it(self, admin_user, stored, update, expected):
        from app.api.v1.endpoints.webhooks import update_webhook
        from app.schemas.webhook import WebhookUpdate

        db = FakeDatabase()
        asyncio.run(
            db.webhooks.insert_one(
                {"_id": "wh-1", "url": _PLAIN_URL, "events": ["scan.completed"], "webhook_type": stored}
            )
        )

        with patch(f"{MODULE}.check_webhook_permission", new_callable=AsyncMock):
            asyncio.run(
                update_webhook(
                    webhook_id="wh-1", webhook_update=WebhookUpdate(**update), current_user=admin_user, db=db
                )
            )

        assert db.webhooks._docs["wh-1"]["webhook_type"] == expected

    @pytest.mark.parametrize(
        ("update", "cleared"),
        [
            pytest.param(
                {"url": "https://contoso.webhook.office.com/webhookb2/def/IncomingWebhook/uvw"}, True, id="url"
            ),
            pytest.param({"webhook_type": "generic"}, True, id="type"),
            pytest.param({"secret": "rotated-key"}, True, id="secret"),
            pytest.param({"secret": None}, True, id="secret-removed"),
            pytest.param({"headers": {"Authorization": "Bearer rotated"}}, True, id="headers"),
            pytest.param({"events": ["vulnerability.found"]}, False, id="events"),
            pytest.param({"is_active": False}, False, id="paused"),
            pytest.param({"url": _TEAMS_URL, "secret": _SECRET}, False, id="unchanged-values"),
        ],
    )
    def test_changing_how_deliveries_go_out_clears_the_failure_state(self, admin_user, update, cleared):
        from app.api.v1.endpoints.webhooks import update_webhook
        from app.schemas.webhook import WebhookUpdate

        failure_state = {
            "consecutive_failures": 5,
            "circuit_breaker_until": datetime(2099, 1, 1, tzinfo=timezone.utc),
            "last_failure_at": datetime(2026, 10, 8, 8, 18, tzinfo=timezone.utc),
        }
        db = FakeDatabase()
        asyncio.run(
            db.webhooks.insert_one(
                {
                    "_id": "wh-1",
                    "url": _TEAMS_URL,
                    "events": ["scan.completed"],
                    "webhook_type": "teams",
                    "secret": _SECRET,
                    **failure_state,
                }
            )
        )

        with patch(f"{MODULE}.check_webhook_permission", new_callable=AsyncMock):
            asyncio.run(
                update_webhook(
                    webhook_id="wh-1", webhook_update=WebhookUpdate(**update), current_user=admin_user, db=db
                )
            )

        stored = db.webhooks._docs["wh-1"]
        cleared_state = {"consecutive_failures": 0, "circuit_breaker_until": None, "last_failure_at": None}
        assert {field: stored[field] for field in failure_state} == (cleared_state if cleared else failure_state)


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
