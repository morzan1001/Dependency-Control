import pytest

from app.api.v1.endpoints.ingest import get_project_config
from app.core.constants import (
    RETENTION_ACTION_ARCHIVE,
    RETENTION_ACTION_DELETE,
    RETENTION_ACTION_NONE,
    SETTINGS_MODE_GLOBAL,
    SETTINGS_MODE_PROJECT,
)
from app.models.project import Project
from app.models.system import SystemSettings


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("project", "system", "days"),
    [
        pytest.param(
            {"retention_days": 30, "retention_action": RETENTION_ACTION_DELETE},
            {
                "retention_mode": SETTINGS_MODE_GLOBAL,
                "global_retention_days": 365,
                "global_retention_action": RETENTION_ACTION_ARCHIVE,
            },
            365,
            id="global-mode-overrides-the-project",
        ),
        pytest.param(
            {"retention_days": 30, "retention_action": RETENTION_ACTION_ARCHIVE},
            {"retention_mode": SETTINGS_MODE_PROJECT, "global_retention_days": 365},
            30,
            id="project-mode-uses-the-project",
        ),
        pytest.param(
            {"retention_days": 30, "retention_action": RETENTION_ACTION_NONE},
            {"retention_mode": SETTINGS_MODE_PROJECT},
            0,
            id="no-action-keeps-forever",
        ),
        pytest.param(
            {"retention_days": 30},
            {
                "retention_mode": SETTINGS_MODE_GLOBAL,
                "global_retention_days": 365,
                "global_retention_action": RETENTION_ACTION_NONE,
            },
            0,
            id="global-no-action-keeps-forever",
        ),
    ],
)
async def test_the_pipeline_config_reports_the_retention_housekeeping_applies(project, system, days):
    config = await get_project_config(Project(id="p-1", name="p", **project), SystemSettings(**system))

    assert config.retention_days == days
