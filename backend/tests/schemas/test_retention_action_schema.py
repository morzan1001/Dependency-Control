"""An unrecognised retention_action expires nothing at all, and the only symptom is disk growth."""

import pytest
from pydantic import ValidationError

from app.core.constants import RETENTION_ACTIONS
from app.schemas.project import ProjectCreate, ProjectUpdate
from app.schemas.system import SystemSettingsUpdate


@pytest.mark.parametrize("action", ["Delete", "DELETE", "purge", "archive_to_s3", ""])
def test_project_schemas_reject_unknown_actions(action):
    with pytest.raises(ValidationError):
        ProjectCreate(name="p", retention_action=action)
    with pytest.raises(ValidationError):
        ProjectUpdate(retention_action=action)


@pytest.mark.parametrize("action", RETENTION_ACTIONS)
def test_project_schemas_accept_every_documented_action(action):
    assert ProjectCreate(name="p", retention_action=action).retention_action == action
    assert ProjectUpdate(retention_action=action).retention_action == action


@pytest.mark.parametrize("action", ["Delete", "purge"])
def test_system_settings_update_rejects_unknown_actions(action):
    with pytest.raises(ValidationError):
        SystemSettingsUpdate(global_retention_action=action)


@pytest.mark.parametrize("action", RETENTION_ACTIONS)
def test_system_settings_update_accepts_every_documented_action(action):
    assert SystemSettingsUpdate(global_retention_action=action).global_retention_action == action


def test_the_constant_and_the_type_cannot_drift():
    from typing import get_args

    from app.core.constants import RetentionAction

    assert list(get_args(RetentionAction)) == RETENTION_ACTIONS
