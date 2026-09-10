"""Tests for unified API key schemas."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.core.constants import API_KEY_SURFACES
from app.schemas.api_keys import (
    ApiKeyCreate,
    ApiKeyCreateResponse,
    ApiKeyListResponse,
    ApiKeyResponse,
)


def _required(model):
    return {name for name, field in model.model_fields.items() if field.is_required()}


class TestApiKeyCreate:
    def test_name_and_surfaces_are_required(self):
        # A default on either would mint a nameless or surface-less key from an empty request.
        assert _required(ApiKeyCreate) == {"name", "surfaces"}

    def test_the_allowed_surfaces_reach_the_published_schema(self):
        # A bare list[str] publishes no enum, leaving a client to guess the vocabulary.
        items = ApiKeyCreate.model_json_schema()["properties"]["surfaces"]["items"]
        assert set(items["enum"]) == API_KEY_SURFACES

    def test_valid_payload_round_trips(self):
        payload = {"name": "my-key", "surfaces": ["mcp", "adhoc"], "expires_in_days": 90}
        model = ApiKeyCreate(**payload)
        assert model.name == "my-key"
        assert model.surfaces == ["mcp", "adhoc"]
        assert model.expires_in_days == 90

    def test_empty_surfaces_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyCreate(name="my-key", surfaces=[], expires_in_days=90)
        assert "surfaces" in str(exc_info.value).lower()

    def test_unknown_surface_rejected_with_name(self):
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyCreate(name="my-key", surfaces=["mcp", "sftp"], expires_in_days=90)
        error = str(exc_info.value)
        assert "sftp" in error

    def test_duplicate_surfaces_collapsed(self):
        model = ApiKeyCreate(name="my-key", surfaces=["mcp", "adhoc", "mcp"], expires_in_days=90)
        assert model.surfaces == ["mcp", "adhoc"]

    def test_name_empty_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyCreate(name="", surfaces=["mcp"], expires_in_days=90)
        assert "name" in str(exc_info.value).lower()

    def test_name_81_chars_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyCreate(name="x" * 81, surfaces=["mcp"], expires_in_days=90)
        assert "name" in str(exc_info.value).lower()

    def test_expires_in_days_zero_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyCreate(name="my-key", surfaces=["mcp"], expires_in_days=0)
        assert "expires_in_days" in str(exc_info.value).lower()

    def test_expires_in_days_366_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyCreate(name="my-key", surfaces=["mcp"], expires_in_days=366)
        assert "expires_in_days" in str(exc_info.value).lower()

    def test_expires_in_days_default_90(self):
        model = ApiKeyCreate(name="my-key", surfaces=["mcp"])
        assert model.expires_in_days == 90

    def test_malformed_surfaces_int_returns_422(self):
        """Malformed surfaces: int instead of list → 422."""
        with pytest.raises(ValidationError):
            ApiKeyCreate(name="test", surfaces=123, expires_in_days=90)

    def test_malformed_surfaces_nested_list_returns_422(self):
        """Malformed surfaces: nested list → 422."""
        with pytest.raises(ValidationError):
            ApiKeyCreate(name="test", surfaces=[["mcp"]], expires_in_days=90)

    def test_malformed_surfaces_dict_returns_422(self):
        """Malformed surfaces: dict instead of list → 422."""
        with pytest.raises(ValidationError):
            ApiKeyCreate(name="test", surfaces={"mcp": 1, "adhoc": 2}, expires_in_days=90)


class TestApiKeyResponse:
    def test_response_field_names(self):
        """ApiKeyResponse has exactly the expected fields."""
        assert set(ApiKeyResponse.model_fields) == {
            "id",
            "name",
            "prefix",
            "surfaces",
            "created_at",
            "expires_at",
            "revoked_at",
            "last_used_at",
        }

    def test_response_excludes_token(self):
        assert "token" not in ApiKeyResponse.model_fields

    def test_last_used_at_serializes_none(self):
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
    def test_create_response_carries_token(self):
        assert "token" in ApiKeyCreateResponse.model_fields

    def test_the_token_is_required(self):
        # Made optional, the one response that ever carries the plaintext could omit it.
        assert _required(ApiKeyCreateResponse) == _required(ApiKeyResponse) | {"token"}

    def test_create_response_is_response_subclass(self):
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
    def test_keys_is_required(self):
        # Defaulted, a listing that failed to build its page would answer with an empty one.
        assert _required(ApiKeyListResponse) == {"keys"}

    def test_list_response_shape(self):
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
