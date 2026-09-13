"""Tests for GitLabService multi-instance support."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.gitlab_api import OIDCPayload
from app.models.gitlab_instance import GitLabInstance
from app.services.gitlab import GitLabService


class TestGitLabServiceInitialization:
    def test_with_instance(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)
        assert service.instance == gitlab_instance_a
        assert service.base_url == "https://gitlab-a.com"
        assert service.api_url == "https://gitlab-a.com/api/v4"

    def test_strips_trailing_slash(self):
        instance = GitLabInstance(
            name="Test",
            url="https://gitlab.com/",
            access_token="token",
            created_by="test",
        )
        service = GitLabService(instance)
        assert service.base_url == "https://gitlab.com"
        assert service.api_url == "https://gitlab.com/api/v4"

    def test_strips_multiple_trailing_slashes(self):
        instance = GitLabInstance(
            name="Test",
            url="https://gitlab.com//",
            access_token="token",
            created_by="test",
        )
        service = GitLabService(instance)
        assert service.base_url == "https://gitlab.com"


class TestGitLabServiceCacheKeys:
    def test_uses_instance_id(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)
        key = service._get_cache_key("jwks")
        assert "instance-a-id" in key
        assert key.startswith("gitlab:instance:")

    def test_differ_between_instances(self, gitlab_instance_a, gitlab_instance_b):
        service_a = GitLabService(gitlab_instance_a)
        service_b = GitLabService(gitlab_instance_b)
        key_a = service_a._get_cache_key("jwks")
        key_b = service_b._get_cache_key("jwks")
        assert key_a != key_b
        assert "instance-a-id" in key_a
        assert "instance-b-id" in key_b


class TestGitLabServiceAuth:
    def test_uses_instance_token(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)
        headers = service._get_auth_headers()
        assert headers["PRIVATE-TOKEN"] == "glpat-token-a"

    def test_raises_error_if_no_token(self):
        instance = GitLabInstance(
            name="No Token",
            url="https://gitlab.com",
            access_token=None,
            created_by="test",
        )
        service = GitLabService(instance)
        with pytest.raises(ValueError, match="No access token configured"):
            service._get_auth_headers()

    def test_different_instances_different_tokens(self, gitlab_instance_a, gitlab_instance_b):
        service_a = GitLabService(gitlab_instance_a)
        service_b = GitLabService(gitlab_instance_b)
        assert service_a._get_auth_headers()["PRIVATE-TOKEN"] == "glpat-token-a"
        assert service_b._get_auth_headers()["PRIVATE-TOKEN"] == "glpat-token-b"


class TestGitLabServiceOIDC:
    def test_uses_instance_issuer(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "test-key-id", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "test-key-id"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {"project_id": "123", "project_path": "g/p"}

                    asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    call_kwargs = mock_decode.call_args.kwargs
                    assert call_kwargs["issuer"] == "https://gitlab-a.com"
                    assert call_kwargs["audience"] == "https://app.example.com"

    def test_rejected_when_no_audience_configured(self):
        """An instance without a configured oidc_audience must reject any token (fail closed), never decode it."""
        instance = GitLabInstance(
            name="No Audience",
            url="https://gitlab.com",
            access_token="token",
            oidc_audience=None,
            created_by="test",
        )
        service = GitLabService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "test-key-id", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "test-key-id"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {"project_id": "123", "project_path": "g/p"}

                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    # Token rejected, and decode is never attempted.
                    assert result is None
                    mock_decode.assert_not_called()

    def test_missing_kid_returns_none(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)
        with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
            mock_header.return_value = {}  # No kid
            result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
            assert result is None

    def test_no_matching_key_returns_none(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "other-key", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch.object(service, "_invalidate_jwks_cache", new_callable=AsyncMock):
                with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {"kid": "missing-key"}
                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert result is None

    def test_returns_payload_on_success(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {"project_id": "123", "project_path": "group/proj"}

                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert isinstance(result, OIDCPayload)
                    assert result.project_id == "123"
                    assert result.project_path == "group/proj"

    def test_issuer_uses_normalized_url(self):
        """Issuer verification must use URL without trailing slash, even if the stored instance URL has one."""
        instance = GitLabInstance(
            name="Trailing Slash",
            url="https://gitlab.com/",
            access_token="token",
            # oidc_audience must be set, otherwise validation fails closed before decode; this test is about issuer normalization.
            oidc_audience="https://app.example.com",
            created_by="test",
        )
        service = GitLabService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {"project_id": "123", "project_path": "g/p"}

                    asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    call_kwargs = mock_decode.call_args.kwargs
                    # Issuer must NOT have trailing slash
                    assert call_kwargs["issuer"] == "https://gitlab.com"

    def test_key_rotation_refreshes_jwks(self, gitlab_instance_a):
        """When key is not in cached JWKS, should invalidate and retry."""
        service = GitLabService(gitlab_instance_a)

        jwks_old = {"keys": [{"kid": "old-key", "kty": "RSA", "n": "n", "e": "AQAB"}]}
        jwks_new = {
            "keys": [
                {"kid": "old-key", "kty": "RSA", "n": "n", "e": "AQAB"},
                {"kid": "new-key", "kty": "RSA", "n": "n2", "e": "AQAB"},
            ]
        }

        call_count = 0

        async def get_jwks_side_effect():
            nonlocal call_count
            call_count += 1
            return jwks_old if call_count == 1 else jwks_new

        with patch.object(service, "get_jwks", side_effect=get_jwks_side_effect):
            with patch.object(service, "_invalidate_jwks_cache", new_callable=AsyncMock) as mock_invalidate:
                with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {"kid": "new-key"}
                    with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                        mock_decode.return_value = {"project_id": "42", "project_path": "g/p"}

                        result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                        assert isinstance(result, OIDCPayload)
                        assert result.project_id == "42"
                        mock_invalidate.assert_called_once()
                        assert call_count == 2


class TestGroupLookup:
    """A binding to a group the instance cannot resolve would silently own nothing, so the
    lookup has to separate "no such group" from "the instance did not answer"."""

    @staticmethod
    def _lookup(service, response):
        with patch.object(service, "_api_get", new=AsyncMock(return_value=response)):
            return asyncio.run(service.get_group(77))

    def test_a_group_the_instance_carries_is_returned(self, gitlab_instance_a):
        response = MagicMock(status_code=200)
        response.json.return_value = {"id": 77, "full_path": "mo/edge"}

        lookup = self._lookup(GitLabService(gitlab_instance_a), response)

        assert (lookup.reachable, lookup.group["full_path"]) == (True, "mo/edge")

    def test_a_group_the_instance_does_not_carry_is_reachable_and_absent(self, gitlab_instance_a):
        lookup = self._lookup(GitLabService(gitlab_instance_a), MagicMock(status_code=404))

        assert (lookup.reachable, lookup.group) == (True, None)

    def test_an_unanswered_request_is_not_an_absent_group(self, gitlab_instance_a):
        lookup = self._lookup(GitLabService(gitlab_instance_a), None)

        assert (lookup.reachable, lookup.group) == (False, None)

    def test_a_refused_request_is_not_an_absent_group(self, gitlab_instance_a):
        lookup = self._lookup(GitLabService(gitlab_instance_a), MagicMock(status_code=403))

        assert (lookup.reachable, lookup.group) == (False, None)


class TestGroupListing:
    def test_the_search_term_is_passed_to_gitlab(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)

        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=[])) as paginated:
            asyncio.run(service.get_groups("edge"))

        endpoint, kwargs = paginated.await_args[0][0], paginated.await_args[1]
        assert endpoint == "/groups"
        assert kwargs["params"]["search"] == "edge"

    def test_no_search_term_asks_for_no_filter(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)

        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=[])) as paginated:
            asyncio.run(service.get_groups())

        assert "search" not in paginated.await_args[1]["params"]
