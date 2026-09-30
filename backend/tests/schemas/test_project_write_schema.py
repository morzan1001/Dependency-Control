"""What the project write schemas let through to storage: the stored Project requires a value for
some fields, and housekeeping must be able to compute a cutoff from the retention."""

import pytest
from pydantic import ValidationError

from app.schemas.project import ProjectCreate, ProjectUpdate

_REQUIRED_IN_STORAGE = (
    "name",
    "active_analyzers",
    "retention_days",
    "retention_action",
    "gitlab_mr_comments_enabled",
    "github_pr_comments_enabled",
)
_CLEARABLE = ("default_branch", "rescan_enabled", "rescan_interval", "gitlab_instance_id", "gitlab_project_id")


@pytest.mark.parametrize("field", _REQUIRED_IN_STORAGE)
def test_an_update_cannot_write_null_into_a_field_the_stored_project_requires(field):
    with pytest.raises(ValidationError):
        ProjectUpdate(**{field: None})


@pytest.mark.parametrize("field", _CLEARABLE)
def test_an_update_can_still_clear_a_nullable_field(field):
    assert ProjectUpdate(**{field: None}).model_dump(exclude_unset=True) == {field: None}


@pytest.mark.parametrize("name", ["", "   ", "x" * 201])
def test_a_rename_is_held_to_the_bounds_creation_enforces(name):
    with pytest.raises(ValidationError):
        ProjectUpdate(name=name)
    with pytest.raises(ValidationError):
        ProjectCreate(name=name)


def test_a_project_name_is_stored_without_surrounding_whitespace():
    assert ProjectCreate(name="  app  ").name == "app"
    assert ProjectUpdate(name="  app  ").name == "app"


@pytest.mark.parametrize("days", [0, 36501, 740000])
def test_retention_days_stay_where_housekeeping_can_compute_a_cutoff(days):
    with pytest.raises(ValidationError):
        ProjectCreate(name="p", retention_days=days)
    with pytest.raises(ValidationError):
        ProjectUpdate(retention_days=days)


def test_the_largest_retention_is_accepted():
    assert ProjectCreate(name="p", retention_days=36500).retention_days == 36500
    assert ProjectUpdate(retention_days=36500).retention_days == 36500
