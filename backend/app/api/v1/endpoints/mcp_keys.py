"""User-facing endpoints for managing MCP API keys from the profile UI."""

import logging

from fastapi import HTTPException, status

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_404
from app.core.permissions import Permissions, has_permission
from app.repositories.mcp_api_keys import MCPApiKeyRepository
from app.schemas.mcp import (
    MCPKeyCreate,
    MCPKeyCreateResponse,
    MCPKeyListResponse,
    MCPKeyResponse,
)

logger = logging.getLogger(__name__)

router = CustomAPIRouter()


def _check_mcp_access(user) -> None:
    if not has_permission(user.permissions, Permissions.MCP_ACCESS):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MCP access permission required",
        )


def _to_response(doc: dict) -> MCPKeyResponse:
    return MCPKeyResponse(
        id=doc["_id"],
        name=doc["name"],
        prefix=doc["prefix"],
        created_at=doc["created_at"],
        expires_at=doc["expires_at"],
        last_used_at=doc.get("last_used_at"),
        revoked_at=doc.get("revoked_at"),
    )


@router.post(
    "/",
    response_model=MCPKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
    responses=RESP_AUTH,
    summary="Create an MCP API key",
)
async def create_mcp_key(
    body: MCPKeyCreate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
):
    """Issue a new MCP API token bound to the current user. The plaintext
    token is returned in this single response — store it immediately; the
    server never shows it again."""
    _check_mcp_access(current_user)
    repo = MCPApiKeyRepository(db)
    doc, plaintext = await repo.create(
        user_id=str(current_user.id),
        name=body.name,
        expires_in_days=body.expires_in_days,
    )
    return MCPKeyCreateResponse(
        id=doc["_id"],
        name=doc["name"],
        prefix=doc["prefix"],
        created_at=doc["created_at"],
        expires_at=doc["expires_at"],
        last_used_at=doc.get("last_used_at"),
        revoked_at=doc.get("revoked_at"),
        token=plaintext,
    )


@router.get(
    "/",
    response_model=MCPKeyListResponse,
    responses=RESP_AUTH,
    summary="List the current user's MCP API keys",
)
async def list_mcp_keys(
    current_user: CurrentUserDep,
    db: DatabaseDep,
):
    _check_mcp_access(current_user)
    repo = MCPApiKeyRepository(db)
    keys = await repo.list_for_user(str(current_user.id))
    return MCPKeyListResponse(keys=[_to_response(k) for k in keys])


@router.delete(
    "/{key_id}",
    responses=RESP_AUTH_404,
    summary="Revoke an MCP API key",
)
async def revoke_mcp_key(
    key_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
):
    _check_mcp_access(current_user)
    repo = MCPApiKeyRepository(db)
    revoked = await repo.revoke(key_id, user_id=str(current_user.id))
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key not found or already revoked",
        )
    return {"detail": "Key revoked"}
