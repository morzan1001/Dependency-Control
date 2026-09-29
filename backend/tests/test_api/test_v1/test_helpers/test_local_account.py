"""One rule decides whether an account is local: no provider, or the local one."""

import pytest

from app.api.v1.helpers.users import is_local_account
from app.models.user import User


@pytest.mark.parametrize(("provider", "expected"), [(None, True), ("", True), ("local", True), ("gitlab", False)])
def test_a_stored_user_document(provider, expected):
    assert is_local_account({"auth_provider": provider}) is expected


def test_a_document_without_the_field_is_local():
    assert is_local_account({}) is True


def test_a_user_model():
    assert is_local_account(User(username="u", email="u@test.com", auth_provider="gitlab")) is False


def test_an_admin_created_user_is_always_local():
    from app.schemas.user import UserCreate

    user_in = UserCreate(email="u@test.com", username="u", password="Str0ng!pass", auth_provider="gitlab")

    assert "auth_provider" not in user_in.model_dump()


@pytest.mark.parametrize("name", ["", "   ", "local", "Local"])
def test_the_oidc_provider_name_cannot_be_mistaken_for_a_local_account(name):
    from pydantic import ValidationError

    from app.schemas.system import SystemSettingsUpdate

    with pytest.raises(ValidationError):
        SystemSettingsUpdate(oidc_provider_name=name)
