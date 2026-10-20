import asyncio
from typing import ClassVar
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.models.gitlab_api import OIDCPayload
from app.models.gitlab_instance import GitLabInstance
from app.services.gitlab import GitLabGroupLookup, GitLabService
from tests.helpers.oidc import rsa_public_jwk, serve_idp
from tests.mocks.gitlab import make_gitlab_instance


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
            mock_jwks.return_value = {"keys": [rsa_public_jwk("test-key-id")]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "test-key-id"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {"project_id": "123", "project_path": "g/p"}

                    asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    call_kwargs = mock_decode.call_args.kwargs
                    assert call_kwargs["issuer"] == "https://gitlab-a.com"
                    assert call_kwargs["audience"] == "https://app.example.com"

    def test_rejected_when_no_audience_configured(self):
        instance = GitLabInstance(
            name="No Audience",
            url="https://gitlab.com",
            access_token="token",
            oidc_audience=None,
            created_by="test",
        )
        service = GitLabService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [rsa_public_jwk("test-key-id")]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "test-key-id"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {"project_id": "123", "project_path": "g/p"}

                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    assert result is None
                    mock_decode.assert_not_called()

    def test_missing_kid_returns_none(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)
        with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
            mock_header.return_value = {}
            result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
            assert result is None

    def test_no_matching_key_returns_none(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [rsa_public_jwk("other-key")]}
            with patch.object(service, "refresh_jwks", new_callable=AsyncMock, return_value=None):
                with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {"kid": "missing-key"}
                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert result is None

    def test_returns_payload_on_success(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [rsa_public_jwk("k1")]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {"project_id": "123", "project_path": "group/proj"}

                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert isinstance(result, OIDCPayload)
                    assert result.project_id == "123"
                    assert result.project_path == "group/proj"

    def test_issuer_uses_normalized_url(self):
        instance = GitLabInstance(
            name="Trailing Slash",
            url="https://gitlab.com/",
            access_token="token",
            # Without oidc_audience validation fails closed before the decode this test inspects.
            oidc_audience="https://app.example.com",
            created_by="test",
        )
        service = GitLabService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [rsa_public_jwk("k1")]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {"project_id": "123", "project_path": "g/p"}

                    asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    call_kwargs = mock_decode.call_args.kwargs
                    assert call_kwargs["issuer"] == "https://gitlab.com"

    def test_key_rotation_refreshes_jwks(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)
        jwks_old = {"keys": [rsa_public_jwk("old-key")]}
        jwks_new = {"keys": [*jwks_old["keys"], rsa_public_jwk("new-key")]}

        with (
            patch.object(service, "get_jwks", new_callable=AsyncMock, return_value=jwks_old),
            patch.object(service, "refresh_jwks", new_callable=AsyncMock, return_value=jwks_new) as refresh,
            patch("app.services.oidc_utils.jwt.get_unverified_header", return_value={"kid": "new-key"}),
            patch("app.services.oidc_utils.jwt.decode", return_value={"project_id": "42", "project_path": "g/p"}),
        ):
            result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))

        assert isinstance(result, OIDCPayload)
        assert result.project_id == "42"
        refresh.assert_awaited_once()


_JWKS = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}


@pytest.fixture
def jwks_cache(fake_cache, monkeypatch):
    monkeypatch.setattr("app.services.oidc_utils.cache_service", fake_cache)
    monkeypatch.setattr("app.services.git_provider.cache_service", fake_cache)
    return fake_cache


@pytest.mark.asyncio
class TestGitLabJwksSource:
    async def test_a_dead_instance_is_asked_once_per_known_location(self, monkeypatch, jwks_cache, gitlab_instance_a):
        requested = serve_idp(monkeypatch, lambda request: httpx.Response(502))
        service = GitLabService(gitlab_instance_a)

        assert await service.get_jwks() is None
        assert await service.get_jwks() is None
        assert requested == [
            "https://gitlab-a.com/.well-known/openid-configuration",
            "https://gitlab-a.com/oauth/discovery/keys",
            "https://gitlab-a.com/-/jwks",
        ]

    async def test_a_new_issuer_url_is_not_served_the_old_instances_keys(self, monkeypatch, jwks_cache):
        moved = {"keys": [{"kid": "k2", "kty": "RSA", "n": "n2", "e": "AQAB"}]}

        def handler(request):
            if request.url.path == "/.well-known/openid-configuration":
                return httpx.Response(404)
            return httpx.Response(200, json=_JWKS if request.url.host == "gitlab-old.com" else moved)

        serve_idp(monkeypatch, handler)

        assert await GitLabService(make_gitlab_instance(id="same", url="https://gitlab-old.com")).get_jwks() == _JWKS
        assert await GitLabService(make_gitlab_instance(id="same", url="https://gitlab-new.com")).get_jwks() == moved

    async def test_a_failed_refresh_keeps_the_cached_keys(self, monkeypatch, jwks_cache, gitlab_instance_a):
        status = {"code": 200}

        def handler(request):
            if request.url.path == "/.well-known/openid-configuration":
                return httpx.Response(200, json={"jwks_uri": "https://gitlab-a.com/oauth/discovery/keys"})
            return httpx.Response(status["code"], json=_JWKS)

        serve_idp(monkeypatch, handler)
        service = GitLabService(gitlab_instance_a)
        assert await service.get_jwks() == _JWKS

        status["code"] = 503
        assert await service.refresh_jwks() is None
        assert await service.get_jwks() == _JWKS


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
    """An unresolvable group would silently own nothing, so "no such group" must differ from "no answer"."""

    _REFS: ClassVar = {
        "by id": (lambda service: service.get_group(77), "/groups/77"),
        "by path": (lambda service: service.get_group("mo/edge"), "/groups/mo%2Fedge"),
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


def _note(note_id, body="", author_id=7):
    """One item of GET /projects/:id/merge_requests/:iid/notes."""
    return {"id": note_id, "body": body, "system": False, "author": {"id": author_id, "username": f"user{author_id}"}}


def _serve_pages(monkeypatch, *pages):
    """Page n answers pages[n - 1], linking the next while one is left; a None page is refused."""

    def answer(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        if pages[page - 1] is None:
            return httpx.Response(502)
        more = page < len(pages)
        link = {"link": f'<{request.url.copy_set_param("page", page + 1)}>; rel="next"'} if more else {}
        return httpx.Response(200, json=pages[page - 1], headers=link)

    return serve_idp(monkeypatch, answer)


def _own_marker(note):
    return note.author_id == 7 and "marker" in note.body


class TestMergeRequestNotes:
    def test_notes_are_read_oldest_first_up_to_the_first_page_holding_a_match(self, gitlab_instance_a, monkeypatch):
        requested = _serve_pages(
            monkeypatch,
            [_note(1, "chatter"), _note(2, "marker", author_id=99)],
            [_note(3, "marker"), _note(4, "marker")],
            [_note(5, "marker")],
        )

        notes = asyncio.run(GitLabService(gitlab_instance_a).find_merge_request_notes(100, 7, _own_marker))

        assert [note.id for note in notes] == [3, 4]
        urls = [httpx.URL(url) for url in requested]
        assert [(url.path, url.params["sort"], url.params["order_by"]) for url in urls] == [
            ("/api/v4/projects/100/merge_requests/7/notes", "asc", "created_at")
        ] * 2

    def test_every_page_is_read_when_none_holds_a_match(self, gitlab_instance_a, monkeypatch):
        requested = _serve_pages(monkeypatch, [_note(1)], [_note(2)])

        assert asyncio.run(GitLabService(gitlab_instance_a).find_merge_request_notes(100, 7, _own_marker)) == []
        assert len(requested) == 2

    def test_a_failed_read_is_none_rather_than_no_notes(self, gitlab_instance_a, monkeypatch):
        _serve_pages(monkeypatch, [_note(1)], None)

        assert asyncio.run(GitLabService(gitlab_instance_a).find_merge_request_notes(100, 7, _own_marker)) is None


@pytest.fixture
def group_cache(fake_cache, monkeypatch):
    monkeypatch.setattr("app.services.gitlab.cache_service", fake_cache)
    return fake_cache


@pytest.mark.usefixtures("group_cache")
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

    def test_the_picker_reopened_within_the_minute_walks_nothing_again(self, gitlab_instance_a, group_cache):
        """Each dialog open and debounced search term walked up to ten pages of 100 groups."""
        service = GitLabService(gitlab_instance_a)

        async def _pick_twice():
            return [await service.get_groups("edge"), await service.get_groups("edge")]

        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=[{"id": 77}])) as paginated:
            first, second = asyncio.run(_pick_twice())

        assert first == second == [{"id": 77}]
        paginated.assert_awaited_once()
        [key] = asyncio.run(group_cache._client.keys("*group_picker*"))
        assert 0 < asyncio.run(group_cache._client.ttl(key)) <= 60

    def test_each_search_term_is_listed_on_its_own(self, gitlab_instance_a):
        service = GitLabService(gitlab_instance_a)

        async def _pick():
            return [await service.get_groups("edge"), await service.get_groups("core"), await service.get_groups()]

        with patch.object(service, "_api_get_paginated", new=AsyncMock(side_effect=[[{"id": 1}], [{"id": 2}], []])):
            assert asyncio.run(_pick()) == [[{"id": 1}], [{"id": 2}], []]

    def test_a_refused_listing_is_asked_again_rather_than_remembered(self, gitlab_instance_a):
        """An admin who fixes the token must not keep seeing the refusal."""
        service = GitLabService(gitlab_instance_a)

        async def _pick_twice():
            return [await service.get_groups(), await service.get_groups()]

        with patch.object(service, "_api_get_paginated", new=AsyncMock(side_effect=[None, [{"id": 1}]])):
            assert asyncio.run(_pick_twice()) == [None, [{"id": 1}]]


class TestGetCurrentUserId:
    @staticmethod
    def _resolve(service, response):
        with patch.object(service, "_api_get", new=AsyncMock(return_value=response)) as api_get:
            return asyncio.run(service.get_current_user_id()), api_get

    def test_the_tokens_own_account_id(self, gitlab_instance_a):
        # Shape of GET /user for the account the token belongs to.
        response = httpx.Response(
            200, json={"id": 4242, "username": "dc-bot", "name": "DC Bot", "state": "active", "bot": True}
        )

        user_id, api_get = self._resolve(GitLabService(gitlab_instance_a), response)

        assert user_id == 4242
        api_get.assert_awaited_once_with("/user")

    @pytest.mark.parametrize("response", [None, httpx.Response(401, json={"message": "401 Unauthorized"})])
    def test_an_unanswered_or_refused_lookup_resolves_no_one(self, gitlab_instance_a, response):
        assert self._resolve(GitLabService(gitlab_instance_a), response)[0] is None


class TestVersion:
    def test_asks_the_version_endpoint_with_the_token(self, gitlab_instance_a, monkeypatch):
        def answer(request: httpx.Request) -> httpx.Response:
            authorised = request.headers.get("PRIVATE-TOKEN") == "glpat-token-a"
            return httpx.Response(200 if authorised else 401, json={"version": "17.4.1"})

        requested = serve_idp(monkeypatch, answer)

        response = asyncio.run(GitLabService(gitlab_instance_a).get_version())

        assert (response.status_code, response.json()) == (200, {"version": "17.4.1"})
        assert requested == ["https://gitlab-a.com/api/v4/version"]

    def test_a_transport_error_reaches_the_caller(self, gitlab_instance_a, monkeypatch):
        def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        serve_idp(monkeypatch, refuse)

        with pytest.raises(httpx.ConnectError):
            asyncio.run(GitLabService(gitlab_instance_a).get_version())
