"""Request and response models for the unified API key system."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import API_KEY_SURFACES


class KeyListTruncation(BaseModel):
    """What a saturated key listing left out. A credential the owner cannot see is one they
    cannot revoke, so the page may not end without the response saying that it did."""

    limit: int
    returned: int
    total: int


def key_list_truncation(*, returned: int, total: int, limit: int) -> KeyListTruncation | None:
    """The disclosure for a key listing, or None when the listing is the whole of it."""
    return KeyListTruncation(limit=limit, returned=returned, total=total) if total > returned else None


class ApiKeyCreate(BaseModel):
    """Request to create a new unified API key."""

    name: str = Field(..., min_length=1, max_length=80)
    surfaces: list[str] = Field(..., description="Non-empty list of surfaces the key may enter (mcp, adhoc, or both)")
    expires_in_days: int = Field(90, ge=1, le=365)

    @field_validator("surfaces", mode="before")
    @classmethod
    def validate_and_deduplicate_surfaces(cls, v: list[str]) -> list[str]:
        """Validate surfaces against allowed set and de-duplicate."""
        if not v:
            raise ValueError("surfaces must not be empty")
        deduplicated = list(dict.fromkeys(v))
        invalid = [s for s in deduplicated if s not in API_KEY_SURFACES]
        if invalid:
            raise ValueError(f"Invalid surface(s): {invalid}. Allowed: {sorted(API_KEY_SURFACES)}")
        return deduplicated


class ApiKeyResponse(BaseModel):
    """Response representing an API key (without the plaintext token)."""

    id: str
    name: str
    prefix: str
    surfaces: list[str]
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class ApiKeyCreateResponse(ApiKeyResponse):
    """Returned only at creation — contains the plaintext token."""

    token: str = Field(
        ...,
        description=(
            "The plaintext API key. Shown exactly once — the server only keeps a "
            "SHA-256 hash. If you lose it, revoke this key and create a new one."
        ),
    )


class ApiKeyListResponse(BaseModel):
    """Response to a key listing request."""

    keys: list[ApiKeyResponse]
    truncated: KeyListTruncation | None = None
