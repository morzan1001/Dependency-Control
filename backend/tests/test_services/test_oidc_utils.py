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
from app.services.oidc_utils import find_jwks_key, validate_oidc_token

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


class _FakeCooldownCache:
    """In-memory stand-in for the Redis-backed ``cache_service`` used by
    ``find_jwks_key`` to rate-limit forced JWKS refreshes. TTL is ignored
    (tests run well inside any realistic cooldown window)."""

    def __init__(self):
        self.store = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ttl_seconds=None):
        self.store[key] = value
        return True


class TestJwksForcedRefreshCooldown:
    """Finding 1 (bug/low): an unknown ``kid`` must not be able to force an
    unbounded number of JWKS cache invalidations + upstream refetches. Once a
    forced refresh has happened, further unknown-kid lookups within the cooldown
    fail fast without invalidating the cache or refetching."""

    _KNOWN_KEY = {"kid": "known", "kty": "RSA", "n": "n", "e": "AQAB"}

    def test_unknown_kid_forces_refresh_only_once_within_cooldown(self):
        """Reproduces the cache-busting DoS: repeated unknown kids should trigger
        at most ONE forced refresh per provider within the cooldown window."""
        jwks_without_target = {"keys": [self._KNOWN_KEY]}
        get_jwks = AsyncMock(return_value=jwks_without_target)
        invalidate = AsyncMock()
        fake_cache = _FakeCooldownCache()

        with patch("app.services.oidc_utils.cache_service", fake_cache):
            # First attacker request with an unknown kid: one forced refresh.
            r1 = asyncio.run(find_jwks_key("attacker-kid-1", get_jwks, invalidate, "GitLab"))
            assert r1 is None
            assert invalidate.await_count == 1
            # Initial lookup + one refetch after invalidate == 2 get_jwks calls.
            assert get_jwks.await_count == 2

            # Second attacker request (different unknown kid) inside the cooldown:
            # must fail fast — NO extra invalidate, NO forced refetch.
            r2 = asyncio.run(find_jwks_key("attacker-kid-2", get_jwks, invalidate, "GitLab"))
            assert r2 is None
            assert invalidate.await_count == 1  # unchanged: no second invalidation
            # Only the initial lookup ran (2 + 1), no post-invalidate refetch.
            assert get_jwks.await_count == 3

    def test_legitimate_rotation_still_refreshes_when_cooldown_clear(self):
        """Regression guard: with the cooldown clear, a genuine key rotation is
        still resolved by invalidating and refetching the JWKS."""
        rotated_key = {"kid": "rotated", "kty": "RSA", "n": "n2", "e": "AQAB"}
        jwks_old = {"keys": [self._KNOWN_KEY]}
        jwks_new = {"keys": [self._KNOWN_KEY, rotated_key]}
        get_jwks = AsyncMock(side_effect=[jwks_old, jwks_new])
        invalidate = AsyncMock()
        fake_cache = _FakeCooldownCache()

        with patch("app.services.oidc_utils.cache_service", fake_cache):
            result = asyncio.run(find_jwks_key("rotated", get_jwks, invalidate, "GitHub"))

        assert result == rotated_key
        invalidate.assert_awaited_once()
        assert get_jwks.await_count == 2

    def test_cooldown_is_per_provider(self):
        """A cooldown set by traffic to one provider must not throttle a
        different provider's legitimate forced refresh."""
        jwks_without_target = {"keys": [self._KNOWN_KEY]}
        get_jwks = AsyncMock(return_value=jwks_without_target)
        invalidate = AsyncMock()
        fake_cache = _FakeCooldownCache()

        with patch("app.services.oidc_utils.cache_service", fake_cache):
            # Trip the cooldown for GitLab.
            asyncio.run(find_jwks_key("x", get_jwks, invalidate, "GitLab"))
            assert invalidate.await_count == 1
            # GitHub is a different key -> still allowed to force one refresh.
            asyncio.run(find_jwks_key("y", get_jwks, invalidate, "GitHub"))
            assert invalidate.await_count == 2


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
