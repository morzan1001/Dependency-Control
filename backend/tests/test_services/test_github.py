"""Tests for GitHubService OIDC validation.

Tests instance-aware initialization, cache key generation, and OIDC token validation.
Mirrors the pattern in test_gitlab.py.
"""

import asyncio
from unittest.mock import AsyncMock, patch


from app.models.github_api import GitHubOIDCPayload
from app.services.github import GitHubService
from tests.mocks.github import make_github_instance, github_instance_a, github_instance_b


class TestGitHubServiceInitialization:
    def test_with_instance(self):
        instance = github_instance_a()
        service = GitHubService(instance)
        assert service.instance == instance
        assert service.base_url == "https://token.actions.githubusercontent.com"

    def test_strips_trailing_slash(self):
        instance = make_github_instance(url="https://token.actions.githubusercontent.com/")
        service = GitHubService(instance)
        assert service.base_url == "https://token.actions.githubusercontent.com"

    def test_strips_multiple_trailing_slashes(self):
        instance = make_github_instance(url="https://github.corp.example.com//")
        service = GitHubService(instance)
        assert service.base_url == "https://github.corp.example.com"


class TestGitHubServiceCacheKeys:
    def test_uses_instance_id(self):
        instance = github_instance_a()
        service = GitHubService(instance)
        key = service._get_cache_key("jwks")
        assert "gh-instance-a-id" in key
        assert key.startswith("github:")

    def test_differ_between_instances(self):
        service_a = GitHubService(github_instance_a())
        service_b = GitHubService(github_instance_b())
        key_a = service_a._get_cache_key("jwks")
        key_b = service_b._get_cache_key("jwks")
        assert key_a != key_b
        assert "gh-instance-a-id" in key_a
        assert "gh-instance-b-id" in key_b


class TestGitHubServiceOIDC:
    def test_uses_instance_issuer(self):
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "test-key-id", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch("app.services.github.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "test-key-id"}
                with patch("app.services.github.jwt.decode") as mock_decode:
                    mock_decode.return_value = {
                        "repository_id": "123",
                        "repository": "owner/repo",
                        "repository_owner": "owner",
                        "actor": "user",
                    }

                    asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    call_kwargs = mock_decode.call_args.kwargs
                    assert call_kwargs["issuer"] == "https://token.actions.githubusercontent.com"
                    assert call_kwargs["audience"] == "dependency-control"

    def test_audience_none_when_not_configured(self):
        instance = make_github_instance(oidc_audience=None)
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "test-key-id", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch("app.services.github.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "test-key-id"}
                with patch("app.services.github.jwt.decode") as mock_decode:
                    mock_decode.return_value = {
                        "repository_id": "123",
                        "repository": "owner/repo",
                        "repository_owner": "owner",
                        "actor": "user",
                    }

                    asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    call_kwargs = mock_decode.call_args.kwargs
                    assert call_kwargs["audience"] is None

    def test_missing_kid_returns_none(self):
        instance = github_instance_a()
        service = GitHubService(instance)
        with patch("app.services.github.jwt.get_unverified_header") as mock_header:
            mock_header.return_value = {}  # No kid
            result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
            assert result is None

    def test_no_matching_key_returns_none(self):
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "other-key", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch.object(service, "_invalidate_jwks_cache", new_callable=AsyncMock):
                with patch("app.services.github.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {"kid": "missing-key"}
                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert result is None

    def test_returns_payload_on_success(self):
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch("app.services.github.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.github.jwt.decode") as mock_decode:
                    mock_decode.return_value = {
                        "repository_id": "123456",
                        "repository": "owner/my-repo",
                        "repository_owner": "owner",
                        "actor": "developer",
                    }

                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert isinstance(result, GitHubOIDCPayload)
                    assert result.repository_id == "123456"
                    assert result.repository == "owner/my-repo"
                    assert result.actor == "developer"

    def test_issuer_uses_normalized_url(self):
        """Issuer verification must use URL without trailing slash."""
        instance = make_github_instance(url="https://token.actions.githubusercontent.com/")
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch("app.services.github.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.github.jwt.decode") as mock_decode:
                    mock_decode.return_value = {
                        "repository_id": "123",
                        "repository": "o/r",
                        "repository_owner": "o",
                        "actor": "u",
                    }

                    asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    call_kwargs = mock_decode.call_args.kwargs
                    assert call_kwargs["issuer"] == "https://token.actions.githubusercontent.com"

    def test_key_rotation_refreshes_jwks(self):
        """When key is not in cached JWKS, should invalidate and retry."""
        instance = github_instance_a()
        service = GitHubService(instance)

        jwks_old = {"keys": [{"kid": "old-key", "kty": "RSA", "n": "n", "e": "AQAB"}]}
        jwks_new = {
            "keys": [
                {"kid": "old-key", "kty": "RSA", "n": "n", "e": "AQAB"},
                {"kid": "new-key", "kty": "RSA", "n": "n2", "e": "AQAB"},
            ]
        }

        call_count = 0

        def get_jwks_side_effect():
            nonlocal call_count
            call_count += 1
            return jwks_old if call_count == 1 else jwks_new

        with patch.object(service, "get_jwks", new_callable=AsyncMock, side_effect=get_jwks_side_effect):
            with patch.object(service, "_invalidate_jwks_cache", new_callable=AsyncMock) as mock_invalidate:
                with patch("app.services.github.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {"kid": "new-key"}
                    with patch("app.services.github.jwt.decode") as mock_decode:
                        mock_decode.return_value = {
                            "repository_id": "42",
                            "repository": "o/p",
                            "repository_owner": "o",
                            "actor": "u",
                        }

                        result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                        assert isinstance(result, GitHubOIDCPayload)
                        assert result.repository_id == "42"
                        mock_invalidate.assert_called_once()
                        assert call_count == 2

    def test_uses_rs256_algorithm(self):
        """GitHub OIDC tokens use RS256, verify the service enforces this."""
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch("app.services.github.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.github.jwt.decode") as mock_decode:
                    mock_decode.return_value = {
                        "repository_id": "1",
                        "repository": "o/r",
                        "repository_owner": "o",
                        "actor": "u",
                    }

                    asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    call_kwargs = mock_decode.call_args.kwargs
                    assert call_kwargs["algorithms"] == ["RS256"]

    def test_extra_claims_ignored(self):
        """GitHubOIDCPayload uses extra='ignore', non-standard claims should not cause errors."""
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch("app.services.github.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.github.jwt.decode") as mock_decode:
                    mock_decode.return_value = {
                        "repository_id": "1",
                        "repository": "o/r",
                        "repository_owner": "o",
                        "actor": "u",
                        "iss": "https://token.actions.githubusercontent.com",
                        "sub": "repo:o/r:ref:refs/heads/main",
                        "aud": "dependency-control",
                        "custom_claim": "should-be-ignored",
                    }

                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert isinstance(result, GitHubOIDCPayload)
                    assert result.repository_id == "1"

    def test_decode_exception_returns_none(self):
        """If jwt.decode raises, should return None (not crash)."""
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch("app.services.github.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.github.jwt.decode") as mock_decode:
                    mock_decode.side_effect = Exception("Signature verification failed")

                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert result is None
