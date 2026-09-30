"""Tests for GitLabService multi-instance support."""

import asyncio
from typing import ClassVar
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.models.gitlab_api import OIDCPayload
from app.models.gitlab_instance import GitLabInstance
from app.services.gitlab import GitLabGroupLookup, GitLabService


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


_GROUP = {
    "id": 77,
    "web_url": "https://gitlab-a.com/groups/mo/edge",
    "name": "edge",
    "path": "edge",
    "full_path": "mo/edge",
    "full_name": "mo / edge",
    "visibility": "private",
    "parent_id": 5,
}


class TestGroupLookup:
    """A binding or an owning group the instance cannot resolve would silently own nothing, so the
    lookup has to separate "no such group" from "the instance did not answer"."""

    _REFS: ClassVar = {
        "by id": (lambda service: service.get_group(77), "/groups/77"),
        "by path": (lambda service: service._lookup_group("mo/edge"), "/groups/mo%2Fedge"),
    }

    @pytest.mark.parametrize("ref", ["by id", "by path"])
    @pytest.mark.parametrize(
        ("response", "expected"),
        [
            (httpx.Response(200, json=_GROUP), GitLabGroupLookup(reachable=True, group=_GROUP)),
            (
                httpx.Response(404, json={"message": "404 Group Not Found"}),
                GitLabGroupLookup(reachable=True, group=None),
            ),
            (httpx.Response(403, json={"message": "403 Forbidden"}), GitLabGroupLookup(reachable=False, group=None)),
            (None, GitLabGroupLookup(reachable=False, group=None)),
        ],
        ids=["carried", "absent", "refused", "unanswered"],
    )
    def test_absent_and_unreachable_stay_apart(self, gitlab_instance_a, ref, response, expected):
        lookup, endpoint = self._REFS[ref]
        service = GitLabService(gitlab_instance_a)

        with patch.object(service, "_api_get", new=AsyncMock(return_value=response)) as api_get:
            assert asyncio.run(lookup(service)) == expected

        # Without the flag GitLab embeds up to 200 of the group's projects in the answer.
        api_get.assert_awaited_once_with(endpoint, params={"with_projects": "false"})


class TestARejectedReadIsLogged:
    """An expired token or a missing scope must not read like a project with no merge requests."""

    @pytest.mark.parametrize(
        ("read", "endpoint", "unanswered"),
        [
            (lambda service: service.get_project_details(100), "/projects/100", None),
            (
                lambda service: service.get_merge_requests_for_commit(100, "9c1d2e3f"),
                "/projects/100/repository/commits/9c1d2e3f/merge_requests",
                [],
            ),
        ],
        ids=["project details", "merge requests of a commit"],
    )
    def test_the_status_is_logged(self, gitlab_instance_a, caplog, read, endpoint, unanswered):
        service = GitLabService(gitlab_instance_a)
        response = httpx.Response(401, json={"message": "401 Unauthorized"})

        with patch.object(service, "_api_get", new=AsyncMock(return_value=response)), caplog.at_level("WARNING"):
            assert asyncio.run(read(service)) == unanswered

        assert f"GitLab API GET {endpoint} returned HTTP 401" in [r.getMessage() for r in caplog.records]


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
