"""Registry access for tests: the registry stores factories, not instances."""

from typing import Any

import pytest

from app.services.analysis import registry
from app.services.analyzers import Analyzer


def build_analyzer(name: str) -> Any:
    """The instance a run would get for this name."""
    return registry.analyzer_factories[name]()


def serve_analyzer(monkeypatch: pytest.MonkeyPatch, name: str, analyzer: Analyzer | Any) -> Any:
    """Hand this one instance to every resolution of ``name``, so a test can inspect it afterwards."""
    monkeypatch.setitem(registry.analyzer_factories, name, lambda: analyzer)
    return analyzer
