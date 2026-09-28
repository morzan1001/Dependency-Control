"""The operator scripts ship in the image but sit outside mypy's and the other tests' reach, so a
moved app module would otherwise surface as an ImportError only in a prod pod."""

import importlib
from pathlib import Path

import pytest

_SCRIPTS = sorted(p.stem for p in (Path(__file__).resolve().parents[2] / "scripts").glob("*.py"))


@pytest.mark.parametrize("script", _SCRIPTS)
def test_script_imports(script):
    importlib.import_module(f"scripts.{script}")
