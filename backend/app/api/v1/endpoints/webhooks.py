"""CRUD and test endpoints for project, team, and global webhook configurations."""

from typing import Annotated, Any

from fastapi import HTTPException, Query

from app.api import deps
from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers import (
    build_pagination_response,
    check_webhook_permission,
    get_webhook_or_404,
)
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_400_404, RESP_AUTH_404
from app.core.permissions import Permissions
from app.models.webhook import Webhook
from app.repositories.webhooks import DELIVERY_FIELDS, GLOBAL_WEBHOOK_SCOPE, WebhookRepository
from app.schemas.webhook import (
    WebhookCreate,
    WebhookResponse,
    WebhookTestRequest,
    WebhookTestResponse,
    WebhookUpdate,
    detect_webhook_type,
)
from app.services.webhooks.webhook_service import webhook_service

router = CustomAPIRouter()


async def _create_scoped(
    webhook_in: WebhookCreate, db: DatabaseDep, *, project_id: str | None = None, team_id: str | None = None
) -> Webhook:
    webhook_type = webhook_in.webhook_type or detect_webhook_type(webhook_in.url)
    webhook = Webhook(
        project_id=project_id,
        team_id=team_id,
        webhook_type=webhook_type,
        **webhook_in.model_dump(exclude={"webhook_type"}),
    )
    return await WebhookRepository(db).create(webhook)


async def _list_scoped(db: DatabaseDep, scope: dict[str, Any], skip: int, limit: int) -> dict[str, Any]:
    """The response schema withholds the HMAC signing secret."""
    repo = WebhookRepository(db)
    total = await repo.count(scope)
    webhooks = await repo.list_scope(scope, skip=skip, limit=limit)
    items = [WebhookResponse.model_validate(w).model_dump() for w in webhooks]
    return build_pagination_response(items, total, skip, limit)


@router.post("/project/{project_id}", response_model=WebhookResponse, status_code=201, responses=RESP_AUTH)
async def create_webhook(
    project_id: str,
    webhook_in: WebhookCreate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Webhook:
    """Create a webhook for a project."""
    await check_webhook_permission(current_user, db, Permissions.WEBHOOK_CREATE, project_id=project_id)
    return await _create_scoped(webhook_in, db, project_id=project_id)


@router.get("/project/{project_id}", responses=RESP_AUTH)
async def list_webhooks(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: Annotated[int, Query(ge=0, description="Number of items to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=100, description="Number of items to return")] = 50,
) -> dict[str, Any]:
    """List all webhooks for a project with pagination."""
    await check_webhook_permission(current_user, db, Permissions.WEBHOOK_READ, project_id=project_id)
    return await _list_scoped(db, {"project_id": project_id}, skip, limit)


@router.post("/global/", response_model=WebhookResponse, status_code=201, responses=RESP_AUTH)
async def create_global_webhook(
    webhook_in: WebhookCreate,
    current_user: deps.SystemManagerDep,
    db: DatabaseDep,
) -> Webhook:
    """Create a global webhook, triggered for all projects."""
    return await _create_scoped(webhook_in, db)


@router.get("/global/", responses=RESP_AUTH)
async def list_global_webhooks(
    current_user: deps.SystemManagerDep,
    db: DatabaseDep,
    skip: Annotated[int, Query(ge=0, description="Number of items to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=100, description="Number of items to return")] = 50,
) -> dict[str, Any]:
    """List global webhooks with pagination."""
    return await _list_scoped(db, GLOBAL_WEBHOOK_SCOPE, skip, limit)


@router.post("/team/{team_id}", response_model=WebhookResponse, status_code=201, responses=RESP_AUTH)
async def create_team_webhook(
    team_id: str,
    webhook_in: WebhookCreate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Webhook:
    """Create a webhook for a team, triggered for all projects belonging to the team."""
    await check_webhook_permission(current_user, db, Permissions.WEBHOOK_CREATE, team_id=team_id)
    return await _create_scoped(webhook_in, db, team_id=team_id)


@router.get("/team/{team_id}", responses=RESP_AUTH)
async def list_team_webhooks(
    team_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: Annotated[int, Query(ge=0, description="Number of items to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=100, description="Number of items to return")] = 50,
) -> dict[str, Any]:
    """List all webhooks for a team with pagination."""
    await check_webhook_permission(current_user, db, Permissions.WEBHOOK_READ, team_id=team_id)
    return await _list_scoped(db, {"team_id": team_id}, skip, limit)


@router.get("/{webhook_id}", response_model=WebhookResponse, responses=RESP_AUTH_404)
async def get_webhook(
    webhook_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Webhook:
    """Get a specific webhook by ID."""
    webhook_repo = WebhookRepository(db)
    webhook = await get_webhook_or_404(webhook_repo, webhook_id)
    await check_webhook_permission(
        current_user, db, Permissions.WEBHOOK_READ, project_id=webhook.project_id, team_id=webhook.team_id
    )
    return webhook


@router.patch("/{webhook_id}", response_model=WebhookResponse, responses=RESP_AUTH_400_404)
async def update_webhook(
    webhook_id: str,
    webhook_update: WebhookUpdate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> Webhook | None:
    """Update a webhook configuration; only provided fields are changed."""
    webhook_repo = WebhookRepository(db)
    webhook = await get_webhook_or_404(webhook_repo, webhook_id)
    await check_webhook_permission(
        current_user, db, Permissions.WEBHOOK_UPDATE, project_id=webhook.project_id, team_id=webhook.team_id
    )

    update_data = webhook_update.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    # Re-detect type when URL changes without an explicit webhook_type override.
    if "url" in update_data and "webhook_type" not in update_data:
        update_data["webhook_type"] = detect_webhook_type(update_data["url"])

    # Results under the old delivery settings would misreport the new ones and keep an old circuit open.
    if any(field in update_data and update_data[field] != getattr(webhook, field) for field in DELIVERY_FIELDS):
        update_data.update(
            consecutive_failures=0, circuit_breaker_until=None, last_failure_at=None, last_triggered_at=None
        )

    return await webhook_repo.update(webhook_id, update_data)


@router.delete("/{webhook_id}", status_code=204, responses=RESP_AUTH_404)
async def delete_webhook(
    webhook_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> None:
    """Delete a webhook."""
    webhook_repo = WebhookRepository(db)
    webhook = await get_webhook_or_404(webhook_repo, webhook_id)
    await check_webhook_permission(
        current_user, db, Permissions.WEBHOOK_DELETE, project_id=webhook.project_id, team_id=webhook.team_id
    )

    await webhook_repo.delete(webhook_id)


@router.post("/{webhook_id}/test", responses=RESP_AUTH_404)
async def test_webhook(
    webhook_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    test_request: WebhookTestRequest | None = None,
) -> WebhookTestResponse:
    """Send a test payload to the webhook URL and return the result."""
    test_request = test_request or WebhookTestRequest()
    webhook_repo = WebhookRepository(db)
    webhook = await get_webhook_or_404(webhook_repo, webhook_id)
    await check_webhook_permission(
        current_user, db, Permissions.WEBHOOK_UPDATE, project_id=webhook.project_id, team_id=webhook.team_id
    )

    result = await webhook_service.test_webhook(webhook, test_request.event_type)
    await webhook_service.record_test(db, webhook, result)

    return WebhookTestResponse(**result)
