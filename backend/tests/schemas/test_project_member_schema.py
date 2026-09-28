"""A member role outside the vocabulary must not reach storage, where it fails every read of the project."""

import pytest
from pydantic import ValidationError

from app.core.constants import PROJECT_ROLES
from app.schemas.project import ProjectMemberInvite, ProjectMemberUpdate


@pytest.mark.parametrize("role", ["", "owner", "Admin"])
def test_both_member_schemas_refuse_a_role_outside_the_vocabulary(role):
    with pytest.raises(ValidationError):
        ProjectMemberInvite(email="a@b.c", role=role)
    with pytest.raises(ValidationError):
        ProjectMemberUpdate(role=role)


@pytest.mark.parametrize("role", PROJECT_ROLES)
def test_every_project_role_is_accepted(role):
    assert ProjectMemberInvite(email="a@b.c", role=role).role == role
    assert ProjectMemberUpdate(role=role).role == role
