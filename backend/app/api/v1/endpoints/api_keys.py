"""User-facing endpoints for minting, listing and revoking unified API keys."""

from typing import Any

from fastapi import HTTPException, status

from app.api.deps import _SURFACE_PERMISSIONS, CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_401, RESP_404, RESP_AUTH
from app.core.permissions import has_permission
from app.models.user import User
from app.repositories.api_keys import LIST_LIMIT, ApiKeyRepository
from app.schemas.api_keys import (
    ApiKeyCreate,
    ApiKeyCreateResponse,
    ApiKeyListResponse,
    ApiKeyResponse,
    key_list_truncation,
)

router = CustomAPIRouter()

_RESP_401_404 = {**RESP_401, **RESP_404}


def _authorize_surfaces(user: User, surfaces: list[str]) -> None:
    """Refuse to mint a key that outranks its holder, naming the first surface they cannot reach.

    The pairing comes from the auth dependency's own table so a key can never be issued for a
    surface the dependency would then refuse it.
    """
    for surface in surfaces:
        permission = _SURFACE_PERMISSIONS[surface]
        if not has_permission(user.permissions, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' is required for the '{surface}' surface",
            )


def _to_response(doc: dict[str, Any]) -> ApiKeyResponse:
    return ApiKeyResponse(
        id=doc["_id"],
        name=doc["name"],
        prefix=doc["prefix"],
        surfaces=doc["surfaces"],
        created_at=doc["created_at"],
        expires_at=doc["expires_at"],
        revoked_at=doc.get("revoked_at"),
        last_used_at=doc.get("last_used_at"),
    )


@router.post(
    "/",
    response_model=ApiKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
    responses=RESP_AUTH,
    summary="Create an API key",
)
async def create_api_key(
    body: ApiKeyCreate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ApiKeyCreateResponse:
    """Issue a token for the requested surfaces; the plaintext is returned once and never shown again."""
    _authorize_surfaces(current_user, body.surfaces)
    repo = ApiKeyRepository(db)
    doc, plaintext = await repo.create(
        user_id=str(current_user.id),
        name=body.name,
        surfaces=body.surfaces,
        expires_in_days=body.expires_in_days,
    )
    return ApiKeyCreateResponse(**_to_response(doc).model_dump(), token=plaintext)


@router.get(
    "/",
    response_model=ApiKeyListResponse,
    responses=RESP_401,
    summary="List the current user's API keys",
)
async def list_api_keys(
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ApiKeyListResponse:
    """List every key the caller owns, gated on ownership alone: withdrawing a surface permission
    leaves the keys it minted live, and a key its owner cannot see is a key they cannot revoke."""
    repo = ApiKeyRepository(db)
    keys, total = await repo.list_for_user(str(current_user.id))
    return ApiKeyListResponse(
        keys=[_to_response(key) for key in keys],
        truncated=key_list_truncation(returned=len(keys), total=total, limit=LIST_LIMIT),
    )


@router.delete(
    "/{key_id}",
    responses=_RESP_401_404,
    summary="Revoke an API key",
)
async def revoke_api_key(
    key_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, str]:
    """Revoke one of the caller's own keys, gated on ownership alone for the same reason the
    listing is: a credential has to stay killable by the person it belongs to."""
    repo = ApiKeyRepository(db)
    revoked = await repo.revoke(key_id, user_id=str(current_user.id))
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key not found or already revoked",
        )
    return {"detail": "Key revoked"}
