"""Tests for shared OIDC token validation, exercising the real RS256 decode/claim-verification path (no jwt.decode mocking)."""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from functools import partial
from types import SimpleNamespace
from typing import ClassVar
from unittest.mock import AsyncMock, patch

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from pydantic import ValidationError

from app.core.constants import JWKS_CACHE_TTL, JWKS_URI_CACHE_TTL
from app.core.http_utils import InstrumentedAsyncClient
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
from app.services import oidc_utils
from app.services.oidc_utils import discover_jwks_uri, fetch_jwks, find_jwks_key, validate_oidc_token

ISSUER = "https://gitlab.example.com"
KID = "test-signing-key"
AUDIENCE = "dependency-control"
# GitLab backdates nbf by 5 seconds against the issuing clock.
_GITLAB_NBF_BACKDATE = 5


def _rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def signing_key():
    return _rsa_key()


@pytest.fixture(scope="module")
def jwks(signing_key):
    return {"keys": [{**RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True), "kid": KID}]}


def _make_token(private_key, aud, headers=None, **claims) -> str:
    """Sign a real RS256 OIDC token shaped like a GitLab CI id_token."""
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": "project_path:group/project:ref_type:branch:ref:main",
        "iat": now,
        "nbf": now - _GITLAB_NBF_BACKDATE,
        "exp": now + 300,
        "jti": "8d3b1c1e-2f6a-4f0e-9d55-3f2a1a0b9c11",
        "project_id": "123",
        "project_path": "group/project",
        **claims,
    }
    if aud is not None:
        claims["aud"] = aud
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": KID, **(headers or {})})


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _hs256_signed_with_public_key(signing_key) -> str:
    public_pem = signing_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header, payload, _ = _make_token(signing_key, aud=AUDIENCE).split(".")
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
    signature = hmac.new(public_pem, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(signature)}"


def _retargeted(token: str) -> str:
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["project_path"] = "victim/project"
    return f"{header}.{_b64(json.dumps(claims).encode())}.{signature}"


def _validate(token: str, audience, jwks, get_jwks=None):
    """Run validate_oidc_token with the real decode path and a stubbed JWKS source."""
    return asyncio.run(
        validate_oidc_token(
            token=token,
            get_jwks=get_jwks or AsyncMock(return_value=jwks),
            refresh_jwks=AsyncMock(return_value=jwks),
            issuer=ISSUER,
            audience=audience,
            payload_model=OIDCPayload,
            provider_name="GitLab",
        )
    )


class TestOIDCAudienceFailClosed:
    """Audience is hard-required and verification fails closed."""

    def test_no_audience_configured_is_rejected(self, signing_key, jwks):
        """A validly-signed token must be rejected when the instance has no configured audience (fail closed)."""
        token = _make_token(signing_key, aud="some-audience")

        # No decode should even be attempted: the guard rejects up front.
        with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
            result = _validate(token, audience=None, jwks=jwks)

        assert result is None
        mock_decode.assert_not_called()

    def test_empty_string_audience_is_rejected(self, signing_key, jwks):
        """An empty-string audience is treated as 'not configured' -> rejected."""
        token = _make_token(signing_key, aud="some-audience")

        with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
            result = _validate(token, audience="", jwks=jwks)

        assert result is None
        mock_decode.assert_not_called()

    def test_audience_mismatch_is_rejected(self, signing_key, jwks):
        """A real token whose 'aud' does not match the configured audience must be rejected."""
        token = _make_token(signing_key, aud="attacker-audience")

        result = _validate(token, audience=AUDIENCE, jwks=jwks)

        assert result is None

    @pytest.mark.parametrize(
        "aud", [pytest.param(AUDIENCE, id="string"), pytest.param(["other-service", AUDIENCE], id="list")]
    )
    def test_matching_audience_is_accepted(self, signing_key, jwks, aud):
        """A real token whose 'aud' names the configured audience is accepted."""
        token = _make_token(signing_key, aud=aud)

        result = _validate(token, audience=AUDIENCE, jwks=jwks)

        assert isinstance(result, OIDCPayload)
        assert result.project_id == "123"
        assert result.project_path == "group/project"

    def test_token_without_aud_claim_is_rejected_when_audience_required(self, signing_key, jwks):
        """A token missing the 'aud' claim entirely is rejected when an audience is configured."""
        token = _make_token(signing_key, aud=None)

        result = _validate(token, audience=AUDIENCE, jwks=jwks)

        assert result is None


class TestOIDCSignatureAndClaims:
    def test_a_token_from_another_issuer_is_rejected(self, signing_key, jwks):
        assert _validate(_make_token(signing_key, aud=AUDIENCE, iss="https://evil.example.com"), AUDIENCE, jwks) is None

    def test_a_token_without_a_kid_is_rejected(self, signing_key, jwks):
        token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE}, signing_key, algorithm="RS256")

        assert _validate(token, AUDIENCE, jwks) is None

    def test_a_token_whose_kid_the_issuer_does_not_publish_is_rejected(self, signing_key, jwks, oidc_cache):
        token = _make_token(signing_key, aud=AUDIENCE, headers={"kid": "rotated-away"})

        assert _validate(token, AUDIENCE, jwks) is None

    def test_the_signing_key_is_chosen_by_kid(self, signing_key):
        other_key = _rsa_key()
        jwks = {
            "keys": [
                {**RSAAlgorithm.to_jwk(other_key.public_key(), as_dict=True), "kid": "other"},
                {**RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True), "kid": KID},
            ]
        }

        assert isinstance(_validate(_make_token(signing_key, aud=AUDIENCE), AUDIENCE, jwks), OIDCPayload)

    @pytest.mark.parametrize(
        "forge",
        [
            pytest.param(lambda key: _make_token(_rsa_key(), aud=AUDIENCE), id="foreign-key-same-kid"),
            pytest.param(lambda key: _retargeted(_make_token(key, aud=AUDIENCE)), id="tampered-payload"),
            pytest.param(_hs256_signed_with_public_key, id="hs256-with-public-key"),
            pytest.param(
                lambda key: jwt.encode({"iss": ISSUER, "aud": AUDIENCE}, None, algorithm="none", headers={"kid": KID}),
                id="alg-none",
            ),
            pytest.param(lambda key: "a.b.c", id="malformed"),
        ],
    )
    def test_a_token_the_published_key_did_not_sign_is_rejected(self, signing_key, jwks, forge):
        assert _validate(forge(signing_key), AUDIENCE, jwks) is None

    def test_a_token_that_is_not_yet_valid_is_rejected(self, signing_key, jwks):
        token = _make_token(signing_key, aud=AUDIENCE, nbf=int(time.time()) + 600)

        assert _validate(token, AUDIENCE, jwks) is None

    def test_a_token_from_an_issuer_clock_ahead_within_its_nbf_allowance_is_accepted(self, signing_key, jwks):
        now = int(time.time())
        token = _make_token(signing_key, aud=AUDIENCE, iat=now + 3, nbf=now + 3 - _GITLAB_NBF_BACKDATE)

        assert isinstance(_validate(token, AUDIENCE, jwks), OIDCPayload)

    @pytest.mark.parametrize(
        "published",
        [
            pytest.param(
                lambda: ECAlgorithm.to_jwk(ec.generate_private_key(ec.SECP256R1()).public_key(), as_dict=True),
                id="ec-key",
            ),
            pytest.param(lambda: {"kty": "RSA", "n": "n", "e": "AQAB"}, id="unparseable-rsa-key"),
        ],
    )
    def test_a_published_key_that_cannot_verify_rs256_rejects_the_token(self, signing_key, published):
        jwks = {"keys": [{**published(), "kid": KID}]}

        assert _validate(_make_token(signing_key, aud=AUDIENCE), AUDIENCE, jwks) is None


class TestOIDCRejectionLogging:
    """An expected rejection is one warning line; a defect is not dressed up as a bad token."""

    def test_an_expired_token_is_one_warning_without_a_traceback(self, signing_key, jwks, caplog):
        token = _make_token(signing_key, aud=AUDIENCE, exp=int(time.time()) - 60)

        with caplog.at_level(logging.WARNING, logger="app.services.oidc_utils"):
            result = _validate(token, audience=AUDIENCE, jwks=jwks)

        assert result is None
        assert [(r.levelno, r.exc_info) for r in caplog.records] == [(logging.WARNING, None)]
        assert "expired" in caplog.records[0].getMessage().lower()

    def test_claims_the_payload_model_rejects_are_one_warning_without_a_traceback(self, signing_key, jwks, caplog):
        token = jwt.encode(
            {"iss": ISSUER, "aud": AUDIENCE, "project_path": "group/project"},
            signing_key,
            algorithm="RS256",
            headers={"kid": KID},
        )

        with caplog.at_level(logging.WARNING, logger="app.services.oidc_utils"):
            result = _validate(token, audience=AUDIENCE, jwks=jwks)

        assert result is None
        assert [(r.levelno, r.exc_info) for r in caplog.records] == [(logging.WARNING, None)]

    def test_an_unexpected_error_propagates(self, signing_key, jwks):
        token = _make_token(signing_key, aud=AUDIENCE)

        with pytest.raises(RuntimeError, match="broken key source"):
            _validate(
                token,
                audience=AUDIENCE,
                jwks=jwks,
                get_jwks=AsyncMock(side_effect=RuntimeError("broken key source")),
            )


@pytest.fixture
def oidc_cache(fake_cache, monkeypatch):
    monkeypatch.setattr(oidc_utils, "cache_service", fake_cache)
    return fake_cache


async def _ttl(cache, key):
    return await cache._client.ttl(cache._make_key(key))


async def _stored_keys(cache):
    return await cache._client.keys("*")


def _serve(monkeypatch, handler):
    """Route the module's HTTP client through ``handler`` and record every requested URL."""
    requested: list[str] = []

    async def recording(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return await handler(request)

    transport = httpx.MockTransport(recording)
    monkeypatch.setattr(oidc_utils, "InstrumentedAsyncClient", partial(InstrumentedAsyncClient, transport=transport))
    return requested


def _uris(*uris):
    return AsyncMock(return_value=list(uris))


_JWKS_A = "https://gitlab.example.com/oauth/discovery/keys"
_JWKS_B = "https://gitlab.example.com/-/jwks"


@pytest.mark.asyncio
class TestFetchJwks:
    async def test_a_dead_idp_is_asked_once_per_candidate_and_then_left_alone(self, monkeypatch, oidc_cache):
        async def unreachable(request):
            raise httpx.ConnectTimeout("timed out", request=request)

        requested = _serve(monkeypatch, unreachable)

        assert await fetch_jwks("jwks-key", _uris(_JWKS_A, _JWKS_B), "GitLab") is None
        assert requested == [_JWKS_A, _JWKS_B]
        assert await oidc_cache.get("jwks-key") is None
        assert await _ttl(oidc_cache, "jwks-key:fetch_failed") == 30

        candidates = _uris(_JWKS_A, _JWKS_B)
        assert await fetch_jwks("jwks-key", candidates, "GitLab") is None
        candidates.assert_not_awaited()
        assert requested == [_JWKS_A, _JWKS_B]

    async def test_the_first_candidate_serving_a_key_set_wins_and_is_cached(self, monkeypatch, oidc_cache, jwks):
        async def handler(request):
            if str(request.url) == _JWKS_A:
                return httpx.Response(200, text="<html>sign in</html>")
            return httpx.Response(200, json=jwks)

        requested = _serve(monkeypatch, handler)

        assert await fetch_jwks("jwks-key", _uris(_JWKS_A, _JWKS_B), "GitLab") == jwks
        assert requested == [_JWKS_A, _JWKS_B]
        assert await oidc_cache.get("jwks-key") == jwks
        assert await _ttl(oidc_cache, "jwks-key") == JWKS_CACHE_TTL

    async def test_a_body_without_a_key_list_is_not_a_key_set(self, monkeypatch, oidc_cache):
        async def handler(request):
            return httpx.Response(200, json={"error": "not found"})

        _serve(monkeypatch, handler)

        assert await fetch_jwks("jwks-key", _uris(_JWKS_A), "GitLab") is None
        assert await oidc_cache.get("jwks-key") is None

    async def test_a_failed_refresh_leaves_the_cached_set_readable(self, monkeypatch, oidc_cache, jwks):
        await oidc_cache.set("jwks-key", jwks)

        async def handler(request):
            return httpx.Response(503)

        _serve(monkeypatch, handler)

        assert await fetch_jwks("jwks-key", _uris(_JWKS_A), "GitLab") is None
        assert await oidc_cache.get("jwks-key") == jwks

    async def test_a_hanging_idp_is_cut_off_by_one_deadline(self, monkeypatch, oidc_cache):
        monkeypatch.setattr(oidc_utils, "_JWKS_FETCH_TIMEOUT_SECONDS", 0.05)

        async def hanging(request):
            await asyncio.sleep(5)
            return httpx.Response(200, json={"keys": []})

        _serve(monkeypatch, hanging)

        started = time.monotonic()
        assert await fetch_jwks("jwks-key", _uris(_JWKS_A, _JWKS_B), "GitLab") is None
        assert time.monotonic() - started < 1
        assert await _ttl(oidc_cache, "jwks-key:fetch_failed") == 30


@pytest.mark.asyncio
class TestDiscoverJwksUri:
    async def test_a_discovered_uri_is_cached(self, monkeypatch, oidc_cache):
        async def handler(request):
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": _JWKS_A})

        requested = _serve(monkeypatch, handler)

        assert await discover_jwks_uri(ISSUER, "uri-key") == _JWKS_A
        assert requested == [f"{ISSUER}/.well-known/openid-configuration"]
        assert await oidc_cache.get("uri-key") == _JWKS_A
        assert await _ttl(oidc_cache, "uri-key") == JWKS_URI_CACHE_TTL

    async def test_a_failed_discovery_caches_no_guess(self, monkeypatch, oidc_cache):
        async def handler(request):
            return httpx.Response(404)

        _serve(monkeypatch, handler)

        assert await discover_jwks_uri(ISSUER, "uri-key") is None
        assert await _stored_keys(oidc_cache) == []


@pytest.mark.asyncio
class TestJwksForcedRefreshCooldown:
    """After one forced refresh, further unknown-kid lookups on the same instance within the cooldown fail fast."""

    _KNOWN_KEY: ClassVar[dict[str, str]] = {"kid": "known", "kty": "RSA", "n": "n", "e": "AQAB"}

    async def test_unknown_kid_forces_refresh_only_once_within_cooldown(self, oidc_cache):
        get_jwks = AsyncMock(return_value={"keys": [self._KNOWN_KEY]})
        refresh = AsyncMock(return_value={"keys": [self._KNOWN_KEY]})

        assert await find_jwks_key("attacker-kid-1", get_jwks, refresh, "GitLab", ISSUER) is None
        assert refresh.await_count == 1

        assert await find_jwks_key("attacker-kid-2", get_jwks, refresh, "GitLab", ISSUER) is None
        assert refresh.await_count == 1
        assert get_jwks.await_count == 2

    async def test_legitimate_rotation_is_resolved_from_the_refreshed_set(self, oidc_cache):
        rotated_key = {"kid": "rotated", "kty": "RSA", "n": "n2", "e": "AQAB"}
        get_jwks = AsyncMock(return_value={"keys": [self._KNOWN_KEY]})
        refresh = AsyncMock(return_value={"keys": [self._KNOWN_KEY, rotated_key]})

        assert await find_jwks_key("rotated", get_jwks, refresh, "GitHub", ISSUER) == rotated_key
        get_jwks.assert_awaited_once()
        refresh.assert_awaited_once()

    async def test_cooldown_is_per_instance(self, oidc_cache):
        """Two instances of one provider must not throttle each other's forced refresh."""
        get_jwks = AsyncMock(return_value={"keys": [self._KNOWN_KEY]})
        refresh = AsyncMock(return_value={"keys": [self._KNOWN_KEY]})

        await find_jwks_key("x", get_jwks, refresh, "GitLab", "https://gitlab-a.example.com")
        await find_jwks_key("y", get_jwks, refresh, "GitLab", "https://gitlab-b.example.com")
        assert refresh.await_count == 2

        await find_jwks_key("z", get_jwks, refresh, "GitLab", "https://gitlab-a.example.com")
        assert refresh.await_count == 2

    async def test_a_failed_refresh_is_a_miss(self, oidc_cache):
        refresh = AsyncMock(return_value=None)

        assert (
            await find_jwks_key("k", AsyncMock(return_value={"keys": [self._KNOWN_KEY]}), refresh, "GitLab", ISSUER)
            is None
        )
        refresh.assert_awaited_once()

    async def test_no_key_set_at_all_forces_no_refresh(self, oidc_cache):
        """An unreachable IdP is not an unknown kid: the refresh would only repeat the failed fetch."""
        refresh = AsyncMock(return_value=None)

        assert await find_jwks_key("k", AsyncMock(return_value=None), refresh, "GitLab", ISSUER) is None
        refresh.assert_not_awaited()
        assert await _stored_keys(oidc_cache) == []


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
    """Response schemas must serialize instances whose oidc_audience is null so admins can see and fix them; the blank-check belongs only on Create/Update."""

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
            token_configured=False,
        )
        assert response.oidc_audience is None

    def test_gitlab_to_response_helper_serializes_legacy_null_audience(self):
        """The GET-endpoint helper for an instance with a null audience must build a Response, not raise (which would 500)."""
        from app.api.v1.endpoints.gitlab_instances import _to_response

        legacy = SimpleNamespace(
            id="abc123",
            name="Legacy GitLab",
            url="https://gitlab.com",
            description=None,
            is_active=True,
            oidc_audience=None,
            auto_create_projects=False,
            sync_teams=False,
            allowed_namespaces=[],
            created_at=datetime.now(timezone.utc),
            created_by="user-1",
            last_modified_at=None,
            access_token=None,
        )

        response = _to_response(legacy)

        assert response.oidc_audience is None
