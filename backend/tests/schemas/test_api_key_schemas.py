"""Tests for unified API key schemas."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.api_keys import (
    ApiKeyCreate,
    ApiKeyCreateResponse,
    ApiKeyListResponse,
    ApiKeyResponse,
)


class TestApiKeyCreate:
    """Tests for ApiKeyCreate schema."""

    def test_valid_payload_round_trips(self):
        """Valid payload round-trips correctly."""
        payload = {"name": "my-key", "surfaces": ["mcp", "adhoc"], "expires_in_days": 90}
        model = ApiKeyCreate(**payload)
        assert model.name == "my-key"
        assert model.surfaces == ["mcp", "adhoc"]
        assert model.expires_in_days == 90

    def test_empty_surfaces_rejected(self):
        """Empty surfaces list is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyCreate(name="my-key", surfaces=[], expires_in_days=90)
        assert "surfaces" in str(exc_info.value).lower()

    def test_unknown_surface_rejected_with_name(self):
        """Unknown surface is rejected, naming the offender."""
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyCreate(name="my-key", surfaces=["mcp", "invalid"], expires_in_days=90)
        error = str(exc_info.value).lower()
        assert "invalid" in error
        assert "surfaces" in error

    def test_duplicate_surfaces_collapsed(self):
        """Duplicate surfaces are de-duplicated."""
        model = ApiKeyCreate(name="my-key", surfaces=["mcp", "adhoc", "mcp"], expires_in_days=90)
        assert model.surfaces == ["mcp", "adhoc"]

    def test_name_empty_rejected(self):
        """Name with 0 characters is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyCreate(name="", surfaces=["mcp"], expires_in_days=90)
        assert "name" in str(exc_info.value).lower()

    def test_name_81_chars_rejected(self):
        """Name with 81 characters is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyCreate(name="x" * 81, surfaces=["mcp"], expires_in_days=90)
        assert "name" in str(exc_info.value).lower()

    def test_expires_in_days_zero_rejected(self):
        """expires_in_days of 0 is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyCreate(name="my-key", surfaces=["mcp"], expires_in_days=0)
        assert "expires_in_days" in str(exc_info.value).lower()

    def test_expires_in_days_366_rejected(self):
        """expires_in_days of 366 is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyCreate(name="my-key", surfaces=["mcp"], expires_in_days=366)
        assert "expires_in_days" in str(exc_info.value).lower()

    def test_expires_in_days_default_90(self):
        """Default expires_in_days is 90."""
        model = ApiKeyCreate(name="my-key", surfaces=["mcp"])
        assert model.expires_in_days == 90


class TestApiKeyResponse:
    """Tests for ApiKeyResponse schema."""

    def test_response_excludes_token(self):
        """ApiKeyResponse does not have token field."""
        assert "token" not in ApiKeyResponse.model_fields

    def test_last_used_at_serializes_none(self):
        """last_used_at serializes explicit None, not omitted."""
        now = datetime.now(timezone.utc)
        response = ApiKeyResponse(
            id="test-id",
            name="my-key",
            prefix="test-",
            surfaces=["mcp"],
            created_at=now,
            expires_at=now,
            last_used_at=None,
        )
        data = response.model_dump()
        assert "last_used_at" in data
        assert data["last_used_at"] is None

    def test_last_used_at_with_value(self):
        """last_used_at serializes datetime when present."""
        now = datetime.now(timezone.utc)
        response = ApiKeyResponse(
            id="test-id",
            name="my-key",
            prefix="test-",
            surfaces=["mcp"],
            created_at=now,
            expires_at=now,
            last_used_at=now,
        )
        data = response.model_dump()
        assert data["last_used_at"] == now


class TestApiKeyCreateResponse:
    """Tests for ApiKeyCreateResponse schema."""

    def test_create_response_carries_token(self):
        """ApiKeyCreateResponse has token field."""
        assert "token" in ApiKeyCreateResponse.model_fields

    def test_create_response_is_response_subclass(self):
        """ApiKeyCreateResponse inherits from ApiKeyResponse."""
        now = datetime.now(timezone.utc)
        response = ApiKeyCreateResponse(
            id="test-id",
            name="my-key",
            prefix="test-",
            surfaces=["mcp"],
            created_at=now,
            expires_at=now,
            token="plaintext-token",
        )
        assert isinstance(response, ApiKeyResponse)
        assert response.token == "plaintext-token"


class TestApiKeyListResponse:
    """Tests for ApiKeyListResponse schema."""

    def test_list_response_shape(self):
        """ApiKeyListResponse accepts list of keys and optional truncation."""
        now = datetime.now(timezone.utc)
        response = ApiKeyListResponse(
            keys=[
                ApiKeyResponse(
                    id="id-1",
                    name="key-1",
                    prefix="pref-",
                    surfaces=["mcp"],
                    created_at=now,
                    expires_at=now,
                )
            ],
            truncated=None,
        )
        assert len(response.keys) == 1
        assert response.truncated is None
