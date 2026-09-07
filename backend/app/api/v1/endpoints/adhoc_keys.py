"""User-facing endpoints for managing ad-hoc analysis API keys from the profile UI."""

from fastapi import HTTPException, status

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_404
from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories.adhoc_api_keys import LIST_LIMIT, AdhocApiKeyRepository
from app.schemas.adhoc import (
    AdhocKeyCreate,
    AdhocKeyCreateResponse,
    AdhocKeyListResponse,
    AdhocKeyResponse,
)
from app.schemas.api_keys import key_list_truncation

router = CustomAPIRouter()


def _check_adhoc_access(user: User) -> None:
    if not has_permission(user.permissions, Permissions.ANALYZE_ADHOC):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ad-hoc analysis permission required",
        )


def _to_response(doc: dict) -> AdhocKeyResponse:
    return AdhocKeyResponse(
        id=doc["_id"],
        name=doc["name"],
        prefix=doc["prefix"],
        created_at=doc["created_at"],
        expires_at=doc["expires_at"],
        revoked_at=doc.get("revoked_at"),
    )


@router.post(
    "/",
    response_model=AdhocKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
    responses=RESP_AUTH,
    summary="Create an ad-hoc analysis API key",
)
async def create_adhoc_key(
    body: AdhocKeyCreate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> AdhocKeyCreateResponse:
    """Issue a token for POST /analyze; the plaintext is returned once and never shown again."""
    _check_adhoc_access(current_user)
    repo = AdhocApiKeyRepository(db)
    doc, plaintext = await repo.create(
        user_id=str(current_user.id),
        name=body.name,
        expires_in_days=body.expires_in_days,
    )
    return AdhocKeyCreateResponse(
        id=doc["_id"],
        name=doc["name"],
        prefix=doc["prefix"],
        created_at=doc["created_at"],
        expires_at=doc["expires_at"],
        revoked_at=doc.get("revoked_at"),
        token=plaintext,
    )


@router.get(
    "/",
    response_model=AdhocKeyListResponse,
    responses=RESP_AUTH,
    summary="List the current user's ad-hoc analysis API keys",
)
async def list_adhoc_keys(
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> AdhocKeyListResponse:
    _check_adhoc_access(current_user)
    repo = AdhocApiKeyRepository(db)
    keys, total = await repo.list_for_user(str(current_user.id))
    return AdhocKeyListResponse(
        keys=[_to_response(k) for k in keys],
        truncated=key_list_truncation(returned=len(keys), total=total, limit=LIST_LIMIT),
    )


@router.delete(
    "/{key_id}",
    responses=RESP_AUTH_404,
    summary="Revoke an ad-hoc analysis API key",
)
async def revoke_adhoc_key(
    key_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, str]:
    _check_adhoc_access(current_user)
    repo = AdhocApiKeyRepository(db)
    revoked = await repo.revoke(key_id, user_id=str(current_user.id))
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key not found or already revoked",
        )
    return {"detail": "Key revoked"}
