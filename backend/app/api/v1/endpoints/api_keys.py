"""User-facing endpoints for minting, listing and revoking unified API keys."""

from collections.abc import Sequence

from fastapi import HTTPException, status

from app.api.deps import SURFACE_PERMISSIONS, CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_401, RESP_401_404, RESP_AUTH
from app.core.constants import ApiKeySurface
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


def _authorize_surfaces(user: User, surfaces: Sequence[ApiKeySurface]) -> None:
    """Refuse to mint a key that outranks its holder, naming the first surface they cannot reach."""
    for surface in surfaces:
        permission = SURFACE_PERMISSIONS[surface]
        if not has_permission(user.permissions, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' is required for the '{surface}' surface",
            )


@router.post(
    "/",
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
    return ApiKeyCreateResponse.model_validate({**doc, "id": doc["_id"], "token": plaintext})


@router.get(
    "/",
    responses=RESP_401,
    summary="List the current user's API keys",
)
async def list_api_keys(
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> ApiKeyListResponse:
    """List every key the caller owns, on ownership alone, so a key stays visible after its permission is withdrawn."""
    repo = ApiKeyRepository(db)
    keys, total = await repo.list_for_user(str(current_user.id))
    return ApiKeyListResponse(
        keys=[ApiKeyResponse.model_validate({**key, "id": key["_id"]}) for key in keys],
        truncated=key_list_truncation(returned=len(keys), total=total, limit=LIST_LIMIT),
    )


@router.delete(
    "/{key_id}",
    responses=RESP_401_404,
    summary="Revoke an API key",
)
async def revoke_api_key(
    key_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, str]:
    """Revoke one of the caller's own keys, on ownership alone, so a credential stays killable by its owner."""
    repo = ApiKeyRepository(db)
    revoked = await repo.revoke(key_id, user_id=str(current_user.id))
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key not found or already revoked",
        )
    return {"detail": "Key revoked"}
