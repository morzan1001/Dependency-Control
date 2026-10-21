import os
import subprocess
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).parents[2]
_PROBE = "import logging, app.main; print(logging.getLevelName(logging.getLogger().level))"


def _root_level(configured: str | None) -> str:
    env = {key: value for key, value in os.environ.items() if key != "LOG_LEVEL"}
    if configured is not None:
        env["LOG_LEVEL"] = configured
    started = subprocess.run(
        [sys.executable, "-c", _PROBE],
        cwd=_BACKEND,
        env={**env, "SECRET_KEY": "test-secret"},
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    return started.stdout.split()[-1]


@pytest.mark.parametrize(("configured", "level"), [(None, "INFO"), ("debug", "DEBUG"), ("WARNING", "WARNING")])
def test_the_app_logs_at_the_level_the_chart_configures(configured, level):
    assert _root_level(configured) == level
