"""One rule decides whether an account is local: no provider, or the local one."""

import pytest
from pydantic import ValidationError

from app.models.user import is_local_account
from app.schemas.system import SystemSettingsUpdate


@pytest.mark.parametrize(("provider", "expected"), [(None, True), ("", True), ("local", True), ("gitlab", False)])
def test_a_stored_provider(provider, expected):
    assert is_local_account(provider) is expected


@pytest.mark.parametrize("name", ["", "   ", "local", "Local"])
def test_the_oidc_provider_name_cannot_be_mistaken_for_a_local_account(name):
    with pytest.raises(ValidationError):
        SystemSettingsUpdate(oidc_provider_name=name)
