"""Tests for shared OIDC token validation utilities.

These tests exercise the *real* JWT decode path with a genuine RS256
keypair and JWKS (no mocking of ``jwt.decode``), so they verify actual
cryptographic / claim-verification behavior rather than mocks asserting
mocks.

Security focus (Finding 7 / W1.1): OIDC audience verification is now
hard-required and fail-closed. A token must be REJECTED when:
  - the instance has no expected audience configured (fail closed), and
  - the token's ``aud`` claim does not match the configured audience.
A token with a matching ``aud`` is accepted (regression guard).
"""

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk, jwt
from jose.constants import ALGORITHMS

from pydantic import ValidationError

from app.models.gitlab_api import OIDCPayload
from app.schemas.github_instance import (
    GitHubInstanceCreate,
    GitHubInstanceResponse,
    GitHubInstanceUpdate,
)
from app.schemas.gitlab_instance import (
    GitLabInstanceCreate,
    GitLabInstanceResponse,
    GitLabInstanceUpdate,
)
from app.services.oidc_utils import validate_oidc_token

ISSUER = "https://gitlab.example.com"
KID = "test-signing-key"


@pytest.fixture(scope="module")
def rsa_keypair():
    """A real RSA keypair shared across the module's crypto tests."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture(scope="module")
def jwks(rsa_keypair):
    """A real JWKS document derived from the public key."""
    _, public_pem = rsa_keypair
    public_jwk = jwk.construct(public_pem, algorithm=ALGORITHMS.RS256).to_dict()
    public_jwk["kid"] = KID
    return {"keys": [public_jwk]}


def _make_token(private_pem: str, aud) -> str:
    """Sign a real RS256 OIDC token with the given audience."""
    claims = {
        "iss": ISSUER,
        "project_id": "123",
        "project_path": "group/project",
    }
    if aud is not None:
        claims["aud"] = aud
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": KID})


def _validate(token: str, audience, jwks):
    """Run validate_oidc_token with the real decode path and a stubbed JWKS source."""
    get_jwks = AsyncMock(return_value=jwks)
    invalidate = AsyncMock()
    return asyncio.run(
        validate_oidc_token(
            token=token,
            get_jwks=get_jwks,
            invalidate_cache=invalidate,
            issuer=ISSUER,
            audience=audience,
            payload_model=OIDCPayload,
            provider_name="GitLab",
        )
    )


class TestOIDCAudienceFailClosed:
    """Audience is hard-required and verification fails closed."""

    def test_no_audience_configured_is_rejected(self, rsa_keypair, jwks):
        """A validly-signed token MUST be rejected when the instance has no
        configured audience (fail closed), even though the signature is valid."""
        private_pem, _ = rsa_keypair
        token = _make_token(private_pem, aud="some-audience")

        # No decode should even be attempted: the guard rejects up front.
        with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
            result = _validate(token, audience=None, jwks=jwks)

        assert result is None
        mock_decode.assert_not_called()

    def test_empty_string_audience_is_rejected(self, rsa_keypair, jwks):
        """An empty-string audience is treated as 'not configured' -> rejected."""
        private_pem, _ = rsa_keypair
        token = _make_token(private_pem, aud="some-audience")

        with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
            result = _validate(token, audience="", jwks=jwks)

        assert result is None
        mock_decode.assert_not_called()

    def test_audience_mismatch_is_rejected(self, rsa_keypair, jwks):
        """A real token whose 'aud' does not match the configured audience
        MUST be rejected by genuine claim verification."""
        private_pem, _ = rsa_keypair
        token = _make_token(private_pem, aud="attacker-audience")

        result = _validate(token, audience="dependency-control", jwks=jwks)

        assert result is None

    def test_matching_audience_is_accepted(self, rsa_keypair, jwks):
        """Regression guard: a real token with a matching 'aud' is accepted."""
        private_pem, _ = rsa_keypair
        token = _make_token(private_pem, aud="dependency-control")

        result = _validate(token, audience="dependency-control", jwks=jwks)

        assert isinstance(result, OIDCPayload)
        assert result.project_id == "123"
        assert result.project_path == "group/project"

    def test_token_without_aud_claim_is_rejected_when_audience_required(self, rsa_keypair, jwks):
        """A token missing the 'aud' claim entirely is rejected when an
        audience is configured (verify_aud=True is always enforced)."""
        private_pem, _ = rsa_keypair
        token = _make_token(private_pem, aud=None)

        result = _validate(token, audience="dependency-control", jwks=jwks)

        assert result is None


class TestGitLabInstanceSchemaRequiresAudience:
    """Creating/updating a GitLab instance requires a non-empty oidc_audience."""

    def test_create_without_audience_rejected(self):
        with pytest.raises(ValidationError):
            GitLabInstanceCreate(
                name="GitLab",
                url="https://gitlab.com",
            )

    def test_create_with_empty_audience_rejected(self):
        with pytest.raises(ValidationError):
            GitLabInstanceCreate(
                name="GitLab",
                url="https://gitlab.com",
                oidc_audience="",
            )

    def test_create_with_whitespace_audience_rejected(self):
        with pytest.raises(ValidationError):
            GitLabInstanceCreate(
                name="GitLab",
                url="https://gitlab.com",
                oidc_audience="   ",
            )

    def test_create_with_audience_accepted(self):
        instance = GitLabInstanceCreate(
            name="GitLab",
            url="https://gitlab.com",
            oidc_audience="dependency-control",
        )
        assert instance.oidc_audience == "dependency-control"

    def test_update_with_empty_audience_rejected(self):
        with pytest.raises(ValidationError):
            GitLabInstanceUpdate(oidc_audience="")

    def test_update_omitting_audience_allowed(self):
        # An update that doesn't touch oidc_audience must remain valid.
        update = GitLabInstanceUpdate(name="Renamed")
        assert update.oidc_audience is None


class TestGitHubInstanceSchemaRequiresAudience:
    """Creating/updating a GitHub instance requires a non-empty oidc_audience."""

    def test_create_without_audience_rejected(self):
        with pytest.raises(ValidationError):
            GitHubInstanceCreate(
                name="GitHub",
                url="https://token.actions.githubusercontent.com",
            )

    def test_create_with_empty_audience_rejected(self):
        with pytest.raises(ValidationError):
            GitHubInstanceCreate(
                name="GitHub",
                url="https://token.actions.githubusercontent.com",
                oidc_audience="",
            )

    def test_create_with_audience_accepted(self):
        instance = GitHubInstanceCreate(
            name="GitHub",
            url="https://token.actions.githubusercontent.com",
            oidc_audience="dependency-control",
        )
        assert instance.oidc_audience == "dependency-control"

    def test_update_with_empty_audience_rejected(self):
        with pytest.raises(ValidationError):
            GitHubInstanceUpdate(oidc_audience="")

    def test_update_omitting_audience_allowed(self):
        update = GitHubInstanceUpdate(name="Renamed")
        assert update.oidc_audience is None


class TestInstanceResponseAllowsNullAudience:
    """Response schemas MUST serialize legacy instances whose oidc_audience is
    null (created before the field became required), so admins can see and fix
    them. The blank-check belongs only on Create/Update — never on the Response.
    """

    def test_gitlab_response_allows_explicit_null_audience(self):
        response = GitLabInstanceResponse(
            id="abc123",
            name="Legacy GitLab",
            url="https://gitlab.com",
            oidc_audience=None,
            created_at=datetime.now(timezone.utc),
            created_by="user-1",
            token_configured=False,
        )
        assert response.oidc_audience is None

    def test_github_response_allows_explicit_null_audience(self):
        response = GitHubInstanceResponse(
            id="abc123",
            name="Legacy GitHub",
            url="https://token.actions.githubusercontent.com",
            oidc_audience=None,
            created_at=datetime.now(timezone.utc),
            created_by="user-1",
        )
        assert response.oidc_audience is None

    def test_gitlab_to_response_helper_serializes_legacy_null_audience(self):
        """Exercise the real GET-endpoint helper for a legacy instance with a
        null audience: it must build a Response, not raise (which would 500)."""
        from app.api.v1.endpoints.gitlab_instances import _to_response

        legacy = SimpleNamespace(
            id="abc123",
            name="Legacy GitLab",
            url="https://gitlab.com",
            description=None,
            is_active=True,
            is_default=False,
            oidc_audience=None,
            auto_create_projects=False,
            sync_teams=False,
            created_at=datetime.now(timezone.utc),
            created_by="user-1",
            last_modified_at=None,
            access_token=None,
        )

        response = _to_response(legacy)

        assert response.oidc_audience is None
