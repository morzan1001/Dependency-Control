import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import HTTPException

from app.models.gitlab_instance import GitLabInstance
from tests.mocks.gitlab import make_gitlab_instance


class TestGitLabInstanceModelDefaults:
    def test_default_values(self):
        instance = GitLabInstance(
            name="Test",
            url="https://gitlab.com",
            created_by="admin",
        )
        assert instance.is_active is True
        assert instance.auto_create_projects is False
        assert instance.sync_teams is False
        assert instance.access_token is None
        assert instance.oidc_audience is None

    def test_a_stored_document_with_the_retired_default_flag_loads_without_it(self):
        instance = GitLabInstance(name="Test", url="https://gitlab.com", created_by="admin", is_default=True)
        assert "is_default" not in instance.model_dump()


class TestGitLabInstanceSerialization:
    def test_access_token_excluded_from_model_dump(self):
        instance = make_gitlab_instance(access_token="secret-token")
        dumped = instance.model_dump()
        assert "access_token" not in dumped


MODULE = "app.api.v1.endpoints.gitlab_instances"


def _make_repo_mock(**method_returns):
    mock_repo = MagicMock()
    for method_name, return_value in method_returns.items():
        setattr(mock_repo, method_name, AsyncMock(return_value=return_value))
    return mock_repo


_ONE_GROUP = [{"id": 1, "full_path": "mo", "name": "MO"}]
_SIGNING_KEYS = {"keys": [{"kid": "k1"}, {"kid": "k2"}]}


def _group_page(groups: list[dict] | None, *, total: int | None = None, withheld: bool = False) -> httpx.Response:
    """GitLab's answer to GET /groups?per_page=1; it withholds x-total past 10,000 rows."""
    if groups is None:
        return httpx.Response(403, json={"message": "403 Forbidden"})
    headers = {} if withheld else {"x-total": str(len(groups) if total is None else total)}
    return httpx.Response(200, json=groups[:1], headers=headers)


def _make_gitlab_service_mock(response, groups=_ONE_GROUP, jwks=_SIGNING_KEYS, group_page=None):
    mock_svc = MagicMock()
    mock_svc.get_version = AsyncMock(return_value=response)
    mock_svc.get_groups = AsyncMock(return_value=groups)
    mock_svc._api_get = AsyncMock(return_value=group_page or _group_page(groups))
    mock_svc.get_jwks = AsyncMock(return_value=jwks)
    mock_svc.refresh_jwks = AsyncMock(return_value=jwks)
    return mock_svc


class TestListInstances:
    def test_list_all_instances(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import list_instances

        instances = [
            make_gitlab_instance(id="i1", name="A"),
            make_gitlab_instance(id="i2", name="B"),
        ]
        mock_repo = _make_repo_mock(find_many=instances, count=2)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                list_instances(
                    page=1,
                    size=100,
                    active_only=False,
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result["total"] == 2
        assert len(result["items"]) == 2
        mock_repo.find_many.assert_called_once_with({}, skip=0, limit=100)

    def test_list_active_only(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import list_instances

        active = [make_gitlab_instance(id="i1", name="Active")]
        mock_repo = _make_repo_mock(find_many=active, count=1)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                list_instances(
                    page=1,
                    size=100,
                    active_only=True,
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result["total"] == 1
        mock_repo.find_many.assert_called_once_with({"is_active": True}, skip=0, limit=100)

    def test_pagination_offset(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import list_instances

        mock_repo = _make_repo_mock(find_many=[], count=50)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                list_instances(
                    page=3,
                    size=10,
                    active_only=False,
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        mock_repo.find_many.assert_called_once_with({}, skip=20, limit=10)
        assert result["total"] == 50

    def test_pagination_response_page_reflects_requested_page(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import list_instances

        mock_repo = _make_repo_mock(find_many=[], count=250)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                list_instances(
                    page=2,
                    size=100,
                    active_only=False,
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result["page"] == 2
        assert result["size"] == 100
        assert result["pages"] == 3

    def test_empty_list(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import list_instances

        mock_repo = _make_repo_mock(find_many=[], count=0)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                list_instances(
                    page=1,
                    size=100,
                    active_only=False,
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result["total"] == 0
        assert result["items"] == []


class TestGetInstance:
    def test_returns_instance(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import get_instance

        instance = make_gitlab_instance(id="inst-1", name="My GL")
        mock_repo = _make_repo_mock(get_by_id=instance)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                get_instance(
                    instance_id="inst-1",
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result.id == "inst-1"
        assert result.name == "My GL"

    def test_an_instance_without_a_token_is_not_advertised_as_configured(self, admin_user):
        """The Settings UI only offers to enter a token for an instance that reports none."""
        from app.api.v1.endpoints.gitlab_instances import get_instance

        mock_repo = _make_repo_mock(get_by_id=make_gitlab_instance(id="inst-1", access_token=None))

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(get_instance(instance_id="inst-1", db=MagicMock(), current_user=admin_user))

        assert result.token_configured is False

    def test_an_instance_holding_a_token_is_advertised_as_configured(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import get_instance

        mock_repo = _make_repo_mock(get_by_id=make_gitlab_instance(id="inst-1", access_token="glpat-tok"))

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(get_instance(instance_id="inst-1", db=MagicMock(), current_user=admin_user))

        assert result.token_configured is True

    def test_raises_404_when_not_found(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import get_instance

        mock_repo = _make_repo_mock(get_by_id=None)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_instance(
                        instance_id="missing",
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 404


class TestCreateInstance:
    def _make_create_data(self, **overrides):
        from app.schemas.gitlab_instance import GitLabInstanceCreate

        defaults = {
            "name": "New GL",
            "url": "https://new-gitlab.com",
            "access_token": "glpat-new-token",
            "oidc_audience": "https://app.example.com",
        }
        defaults.update(overrides)
        return GitLabInstanceCreate(**defaults)

    def test_raises_400_on_duplicate_url(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=True)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    create_instance(
                        instance_data=self._make_create_data(),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 400
        assert "URL" in exc_info.value.detail

    def test_raises_400_on_duplicate_name(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=True)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    create_instance(
                        instance_data=self._make_create_data(),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 400
        assert "name" in exc_info.value.detail

    def test_a_rejected_token_reports_the_gitlab_status_exactly_once(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=False)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=_make_gitlab_service_mock(MagicMock(status_code=401))):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        create_instance(
                            instance_data=self._make_create_data(),
                            db=MagicMock(),
                            current_user=admin_user,
                        )
                    )
        assert exc_info.value.detail == "Failed to connect to GitLab instance: HTTP 401"
        mock_repo.create.assert_not_called()

    @pytest.mark.parametrize(
        "error",
        [httpx.ConnectError("connection refused"), httpx.InvalidURL("connection refused")],
        ids=["unreachable", "malformed-url"],
    )
    def test_an_unreachable_instance_reports_the_transport_error(self, admin_user, error):
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=False)
        mock_svc = _make_gitlab_service_mock(MagicMock(status_code=200))
        mock_svc.get_version = AsyncMock(side_effect=error)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=mock_svc):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        create_instance(
                            instance_data=self._make_create_data(),
                            db=MagicMock(),
                            current_user=admin_user,
                        )
                    )
        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "Failed to connect to GitLab instance: connection refused"
        mock_repo.create.assert_not_called()

    def test_a_fault_outside_the_transport_is_not_reported_as_a_connection_failure(self, admin_user):
        """Blaming the instance for a server-side bug sends the admin checking a GitLab that is fine."""
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_svc = _make_gitlab_service_mock(MagicMock(status_code=200))
        mock_svc.get_version = AsyncMock(side_effect=KeyError("api_url"))

        with patch(
            f"{MODULE}.GitLabInstanceRepository",
            return_value=_make_repo_mock(exists_by_url=False, exists_by_name=False),
        ):
            with patch(f"{MODULE}.GitLabService", return_value=mock_svc):
                with pytest.raises(KeyError):
                    asyncio.run(
                        create_instance(
                            instance_data=self._make_create_data(),
                            db=MagicMock(),
                            current_user=admin_user,
                        )
                    )

    @pytest.mark.parametrize("jwks", [None, {"keys": []}], ids=["unreachable", "no-keys"])
    def test_an_oidc_only_instance_whose_issuer_serves_no_signing_keys_is_refused(self, admin_user, jwks):
        """OIDC is all such an instance serves, and every token from its issuer would fail validation."""
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=False, create=None)
        service = _make_gitlab_service_mock(MagicMock(status_code=200), jwks=jwks)

        with (
            patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo),
            patch(f"{MODULE}.GitLabService", return_value=service),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(
                create_instance(
                    instance_data=self._make_create_data(access_token=None), db=MagicMock(), current_user=admin_user
                )
            )

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "OIDC endpoint unreachable or returned no signing keys. Verify the issuer URL."
        mock_repo.create.assert_not_called()

    @pytest.mark.parametrize("jwks", [None, {"keys": []}], ids=["unreachable", "no-keys"])
    def test_an_instance_whose_token_works_is_created_without_fetchable_signing_keys(self, admin_user, jwks):
        """Its token still serves MR decoration, branch and team sync; the Test button reports the missing JWKS."""
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=False)
        mock_repo.create = AsyncMock(side_effect=lambda inst: inst)
        service = _make_gitlab_service_mock(MagicMock(status_code=200), jwks=jwks)

        with (
            patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo),
            patch(f"{MODULE}.GitLabService", return_value=service),
        ):
            result = asyncio.run(
                create_instance(instance_data=self._make_create_data(), db=MagicMock(), current_user=admin_user)
            )

        assert result.name == "New GL"
        mock_repo.create.assert_called_once()
        service.get_version.assert_awaited_once()

    def test_an_oidc_only_instance_is_created_once_its_issuer_serves_keys(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=False)
        mock_repo.create = AsyncMock(side_effect=lambda inst: inst)
        service = _make_gitlab_service_mock(MagicMock(status_code=401))

        with (
            patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo),
            patch(f"{MODULE}.GitLabService", return_value=service),
        ):
            asyncio.run(
                create_instance(
                    instance_data=self._make_create_data(access_token=None), db=MagicMock(), current_user=admin_user
                )
            )

        mock_repo.create.assert_called_once()
        service.get_version.assert_not_called()

    def test_success_creates_and_returns_instance(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=False)
        mock_repo.create = AsyncMock(side_effect=lambda inst: inst)
        mock_response = MagicMock(status_code=200)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=_make_gitlab_service_mock(mock_response)):
                result = asyncio.run(
                    create_instance(
                        instance_data=self._make_create_data(),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )

        assert result.name == "New GL"
        mock_repo.create.assert_called_once()

    def test_a_trailing_slash_never_reaches_the_stored_url(self, admin_user):
        """URL comparisons (dedupe, issuer matching) are literal, so a slash would make one GitLab two instances."""
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=False)
        mock_repo.create = AsyncMock(side_effect=lambda inst: inst)
        mock_response = MagicMock(status_code=200)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=_make_gitlab_service_mock(mock_response)):
                result = asyncio.run(
                    create_instance(
                        instance_data=self._make_create_data(url="https://new-gitlab.com/"),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )

        persisted = mock_repo.create.call_args.args[0]
        assert persisted.url == "https://new-gitlab.com"
        assert result.url == "https://new-gitlab.com"

    def test_create_persists_and_returns_team_sync_depth(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=False)
        mock_repo.create = AsyncMock(side_effect=lambda inst: inst)
        mock_response = MagicMock(status_code=200)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=_make_gitlab_service_mock(mock_response)):
                result = asyncio.run(
                    create_instance(
                        instance_data=self._make_create_data(team_sync_depth=3),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )

        persisted = mock_repo.create.call_args.args[0]
        assert persisted.team_sync_depth == 3
        assert result.team_sync_depth == 3


class TestUpdateInstance:
    def _make_update_data(self, **fields):
        from app.schemas.gitlab_instance import GitLabInstanceUpdate

        return GitLabInstanceUpdate(**fields)

    def test_raises_404_when_not_found(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import update_instance

        mock_repo = _make_repo_mock(get_by_id=None)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    update_instance(
                        instance_id="missing",
                        update_data=self._make_update_data(name="New Name"),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 404

    def test_raises_400_on_duplicate_url(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import update_instance

        existing = make_gitlab_instance(id="inst-1", url="https://old.com")
        mock_repo = _make_repo_mock(get_by_id=existing, exists_by_url=True)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    update_instance(
                        instance_id="inst-1",
                        update_data=self._make_update_data(url="https://taken.com"),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 400
        assert "URL" in exc_info.value.detail

    def test_raises_400_on_duplicate_name(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import update_instance

        existing = make_gitlab_instance(id="inst-1", name="Old Name")
        mock_repo = _make_repo_mock(
            get_by_id=existing,
            exists_by_name=True,
        )

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    update_instance(
                        instance_id="inst-1",
                        update_data=self._make_update_data(name="Taken Name"),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 400
        assert "name" in exc_info.value.detail

    def test_success_returns_updated_instance(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import update_instance

        existing = make_gitlab_instance(id="inst-1", name="Old")
        updated = make_gitlab_instance(id="inst-1", name="New Name")
        mock_repo = _make_repo_mock(exists_by_name=False)
        mock_repo.get_by_id = AsyncMock(return_value=existing)
        mock_repo.update = AsyncMock(return_value=updated)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                update_instance(
                    instance_id="inst-1",
                    update_data=self._make_update_data(name="New Name"),
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result.name == "New Name"
        mock_repo.update.assert_called_once()

    def test_update_applies_and_returns_team_sync_depth(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import update_instance

        existing = make_gitlab_instance(id="inst-1", team_sync_depth=1)
        updated = make_gitlab_instance(id="inst-1", team_sync_depth=2)
        mock_repo = _make_repo_mock()
        mock_repo.get_by_id = AsyncMock(return_value=existing)
        mock_repo.update = AsyncMock(return_value=updated)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                update_instance(
                    instance_id="inst-1",
                    update_data=self._make_update_data(team_sync_depth=2),
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        update_dict = mock_repo.update.call_args.args[1]
        assert update_dict["team_sync_depth"] == 2
        assert result.team_sync_depth == 2


class TestTestConnection:
    def test_raises_404_when_not_found(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import test_connection

        mock_repo = _make_repo_mock(get_by_id=None)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    test_connection(
                        instance_id="missing",
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 404

    @staticmethod
    def _test(admin_user, instance, service):
        from app.api.v1.endpoints.gitlab_instances import test_connection

        with (
            patch(f"{MODULE}.GitLabInstanceRepository", return_value=_make_repo_mock(get_by_id=instance)),
            patch(f"{MODULE}.GitLabService", return_value=service),
        ):
            return asyncio.run(test_connection(instance_id="inst-1", db=MagicMock(), current_user=admin_user))

    def test_an_oidc_only_instance_passes_on_its_signing_keys(self, admin_user):
        """Ingest needs only the issuer's keys; a token-less instance is a complete setup."""
        service = _make_gitlab_service_mock(MagicMock(status_code=401))

        result = self._test(admin_user, make_gitlab_instance(id="inst-1", access_token=None), service)

        assert result.success is True
        assert "2 signing key(s)" in result.message
        service.refresh_jwks.assert_awaited_once()
        service.get_version.assert_not_called()

    @pytest.mark.parametrize("jwks", [None, {"keys": []}], ids=["unreachable", "no-keys"])
    def test_an_oidc_only_instance_whose_issuer_serves_no_signing_keys_fails(self, admin_user, jwks):
        service = _make_gitlab_service_mock(MagicMock(status_code=401), jwks=jwks)

        result = self._test(admin_user, make_gitlab_instance(id="inst-1", access_token=None), service)

        assert result.success is False
        assert result.message == "JWKS endpoint unreachable or returned no signing keys"
        service.get_version.assert_not_called()

    @pytest.mark.parametrize("jwks", [None, {"keys": []}], ids=["unreachable", "no-keys"])
    def test_a_working_token_passes_with_the_missing_signing_keys_as_a_warning(self, admin_user, jwks):
        """The token still serves MR decoration and branch and team sync, as the 1.9.59 test reported."""
        response = MagicMock(status_code=200)
        response.json.return_value = {"version": "16.5.0"}
        service = _make_gitlab_service_mock(response, jwks=jwks)

        result = self._test(admin_user, make_gitlab_instance(id="inst-1", access_token="glpat-tok"), service)

        assert result.success is True
        assert result.gitlab_version == "16.5.0"
        assert result.message.startswith("Warning: JWKS endpoint unreachable or returned no signing keys")
        assert "The access token authenticates. Token reads 1 group(s)." in result.message
        service._api_get.assert_awaited_once_with("/groups", params={"per_page": 1})

    @pytest.mark.parametrize("jwks", [None, {"keys": []}], ids=["unreachable", "no-keys"])
    def test_a_failing_group_probe_still_names_the_missing_signing_keys(self, admin_user, jwks):
        response = MagicMock(status_code=200)
        response.json.return_value = {"version": "16.5.0"}
        service = _make_gitlab_service_mock(response, groups=None, jwks=jwks)

        result = self._test(admin_user, make_gitlab_instance(id="inst-1", access_token="glpat-tok"), service)

        assert result.success is False
        assert result.gitlab_version == "16.5.0"
        assert result.message.startswith("Warning: JWKS endpoint unreachable or returned no signing keys")
        assert "read_api" in result.message
        assert "OIDC endpoint reachable" not in result.message

    def test_success_returns_version(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import test_connection

        instance = make_gitlab_instance(id="inst-1", access_token="glpat-tok")
        mock_repo = _make_repo_mock(get_by_id=instance)

        mock_response = MagicMock(status_code=200)
        mock_response.json.return_value = {"version": "16.5.0"}

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=_make_gitlab_service_mock(mock_response)):
                result = asyncio.run(
                    test_connection(
                        instance_id="inst-1",
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )

        assert result.success is True
        assert result.gitlab_version == "16.5.0"
        assert "1 group(s)" in result.message

    @staticmethod
    def _probe(admin_user, *, sync_teams=True, groups=_ONE_GROUP, group_page=None):
        from app.api.v1.endpoints.gitlab_instances import test_connection

        instance = make_gitlab_instance(id="inst-1", access_token="glpat-tok", sync_teams=sync_teams)
        response = MagicMock(status_code=200)
        response.json.return_value = {"version": "16.5.0"}
        service = _make_gitlab_service_mock(response, groups=groups, group_page=group_page)

        with (
            patch(f"{MODULE}.GitLabInstanceRepository", return_value=_make_repo_mock(get_by_id=instance)),
            patch(f"{MODULE}.GitLabService", return_value=service),
        ):
            result = asyncio.run(test_connection(instance_id="inst-1", db=MagicMock(), current_user=admin_user))
        return result, service

    def test_the_group_probe_reads_one_group_and_counts_by_the_total(self, admin_user):
        """One /groups request; the uncapped count comes from x-total."""
        result, service = self._probe(admin_user, group_page=_group_page(_ONE_GROUP, total=2345))

        assert result.success is True
        assert "Token reads 2345 group(s)." in result.message
        service._api_get.assert_awaited_once_with("/groups", params={"per_page": 1})
        service.get_groups.assert_not_called()

    def test_a_total_gitlab_withholds_is_reported_as_at_least_one_group(self, admin_user):
        result, _ = self._probe(admin_user, group_page=_group_page(_ONE_GROUP, withheld=True))

        assert result.success is True
        assert "Token reads at least one group." in result.message

    def test_a_token_that_cannot_list_groups_fails_a_team_syncing_instance(self, admin_user):
        """Team sync resolves a project's group through this listing, so a green test would hide that nothing syncs."""
        result, _ = self._probe(admin_user, groups=None)

        assert result.success is False
        assert "read_api" in result.message
        assert result.gitlab_version == "16.5.0"

    def test_a_200_html_group_listing_reads_as_a_token_that_cannot_list_groups(self, admin_user):
        html = httpx.Response(200, text="<html>Sign in</html>", headers={"content-type": "text/html"})
        result, _ = self._probe(admin_user, group_page=html)

        assert result.success is False
        assert "read_api" in result.message

    def test_a_token_belonging_to_no_group_fails_a_team_syncing_instance(self, admin_user):
        result, _ = self._probe(admin_user, groups=[])

        assert result.success is False
        assert "no group" in result.message

    def test_a_pure_ingest_instance_is_never_asked_for_groups(self, admin_user):
        """Demanding group access of an instance that syncs no teams would fail a good setup."""
        result, service = self._probe(admin_user, sync_teams=False, groups=None)

        assert result.success is True
        service._api_get.assert_not_called()

    def test_http_error_returns_failure(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import test_connection

        instance = make_gitlab_instance(id="inst-1", access_token="glpat-tok")
        mock_repo = _make_repo_mock(get_by_id=instance)

        mock_response = MagicMock(status_code=403)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=_make_gitlab_service_mock(mock_response)):
                result = asyncio.run(
                    test_connection(
                        instance_id="inst-1",
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )

        assert result.success is False
        assert "403" in result.message

    def test_exception_returns_failure(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import test_connection

        instance = make_gitlab_instance(id="inst-1", access_token="glpat-tok")
        mock_repo = _make_repo_mock(get_by_id=instance)

        mock_response = MagicMock()
        mock_svc = _make_gitlab_service_mock(mock_response)
        mock_svc.get_version = AsyncMock(side_effect=ConnectionError("DNS resolution failed"))

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=mock_svc):
                result = asyncio.run(
                    test_connection(
                        instance_id="inst-1",
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )

        assert result.success is False
        assert "DNS resolution failed" in result.message


class TestBindingPickerListing:
    @staticmethod
    def _run(admin_user, instance, groups, search=None):
        from app.api.v1.endpoints.gitlab_instances import list_instance_groups

        mock_repo = _make_repo_mock(get_by_id=instance)
        service = MagicMock()
        service.get_groups = AsyncMock(return_value=groups)

        with (
            patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo),
            patch(f"{MODULE}.GitLabService", return_value=service),
        ):
            result = asyncio.run(
                list_instance_groups(instance_id="gl-1", db=MagicMock(), current_user=admin_user, search=search)
            )
        return result, service

    def test_each_group_is_offered_with_the_path_that_tells_it_apart(self, admin_user):
        result, _ = self._run(
            admin_user,
            make_gitlab_instance(id="gl-1"),
            [
                {"id": 77, "path": "edge", "full_path": "mo/edge", "name": "Edge"},
                {"id": 12, "path": "mo", "full_path": "mo", "name": "MO"},
                {"path": "no-id", "full_path": "mo/no-id"},
            ],
        )

        assert [(group.id, group.full_path, group.name) for group in result] == [
            (77, "mo/edge", "Edge"),
            (12, "mo", "MO"),
        ]

    def test_the_search_term_reaches_the_instance(self, admin_user):
        """The listing is capped, so a group beyond the cap is only reachable by search."""
        _, service = self._run(admin_user, make_gitlab_instance(id="gl-1"), [], search="edge")

        service.get_groups.assert_awaited_once_with("edge")

    def test_an_instance_that_cannot_list_groups_is_a_bad_gateway(self, admin_user):
        with pytest.raises(HTTPException) as excinfo:
            self._run(admin_user, make_gitlab_instance(id="gl-1"), None)

        assert excinfo.value.status_code == 502

    def test_an_unknown_instance_is_not_found(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import list_instance_groups

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=_make_repo_mock(get_by_id=None)):
            with pytest.raises(HTTPException) as excinfo:
                asyncio.run(
                    list_instance_groups(instance_id="gl-absent", db=MagicMock(), current_user=admin_user, search=None)
                )

        assert excinfo.value.status_code == 404


def _run_gitlab_update(instance, current_user, **fields):
    from app.api.v1.endpoints.gitlab_instances import update_instance
    from app.schemas.gitlab_instance import GitLabInstanceUpdate

    mock_repo = _make_repo_mock(get_by_id=instance, exists_by_url=False, exists_by_name=False, update=instance)
    with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
        asyncio.run(
            update_instance(
                instance_id="inst-1",
                update_data=GitLabInstanceUpdate(**fields),
                db=MagicMock(),
                current_user=current_user,
            )
        )
    return mock_repo


class TestGitLabInstanceNamespaceAllowlist:
    """Auto-create on gitlab.com admits every project there unless a namespace list narrows it."""

    def test_create_persists_and_returns_the_namespace_list(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import create_instance
        from app.schemas.gitlab_instance import GitLabInstanceCreate

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=False)
        mock_repo.create = AsyncMock(side_effect=lambda instance: instance)
        payload = GitLabInstanceCreate(
            name="GitLab.com",
            url="https://gitlab.com",
            oidc_audience="my-aud",
            auto_create_projects=True,
            allowed_namespaces=["acme"],
        )

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            response = asyncio.run(create_instance(instance_data=payload, db=MagicMock(), current_user=admin_user))

        assert mock_repo.create.await_args.args[0].allowed_namespaces == ["acme"]
        assert response.allowed_namespaces == ["acme"]

    def test_enabling_auto_create_on_gitlab_com_without_a_list_is_rejected(self, admin_user):
        instance = make_gitlab_instance(id="inst-1", url="https://gitlab.com", auto_create_projects=False)

        with pytest.raises(HTTPException) as exc_info:
            _run_gitlab_update(instance, admin_user, auto_create_projects=True)

        assert exc_info.value.status_code == 400
        assert "allowed namespace" in exc_info.value.detail

    def test_enabling_auto_create_together_with_a_list_is_allowed(self, admin_user):
        instance = make_gitlab_instance(id="inst-1", url="https://gitlab.com", auto_create_projects=False)

        repo = _run_gitlab_update(instance, admin_user, auto_create_projects=True, allowed_namespaces=["acme"])

        assert repo.update.await_args.args[1]["allowed_namespaces"] == ["acme"]

    def test_emptying_the_list_while_auto_create_stays_on_is_rejected(self, admin_user):
        instance = make_gitlab_instance(
            id="inst-1", url="https://gitlab.com", auto_create_projects=True, allowed_namespaces=["acme"]
        )

        with pytest.raises(HTTPException) as exc_info:
            _run_gitlab_update(instance, admin_user, allowed_namespaces=[])

        assert exc_info.value.status_code == 400

    def test_a_self_managed_instance_auto_creates_without_a_list(self, admin_user):
        instance = make_gitlab_instance(id="inst-1", auto_create_projects=False)

        repo = _run_gitlab_update(instance, admin_user, auto_create_projects=True)

        assert repo.update.await_args.args[1]["auto_create_projects"] is True
