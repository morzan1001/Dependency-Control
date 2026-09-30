"""Importing one enrichment module must not build the enrichment service and its dependency graph."""

import subprocess
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize("module", ["app.services.normalizers.secret", "app.services.enrichment.scoring"])
def test_a_module_that_scores_with_enrichment_imports_on_its_own(module):
    """aggregation -> normalizers.secret -> enrichment -> aggregation is a cycle if the package init loads the service."""
    probe = f"import sys, {module}; sys.exit('app.services.enrichment.service' in sys.modules)"

    result = subprocess.run([sys.executable, "-c", probe], cwd=_BACKEND, capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr or "the enrichment service was loaded"
