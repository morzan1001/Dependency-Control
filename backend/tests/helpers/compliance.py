"""Framework inputs shaped the way ComplianceReportEngine._gather_inputs assembles them."""

from typing import Any
from unittest.mock import MagicMock

from app.schemas.compliance import EvaluationCoverage, InputCoverage
from app.schemas.project import LicensePolicySchema
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.base import EvaluationInput


def full_coverage(n_findings: int = 0, n_assets: int = 0) -> EvaluationCoverage:
    return EvaluationCoverage(
        findings=InputCoverage(evaluated=n_findings, in_scope=n_findings, limit=max(n_findings, 1)),
        crypto_assets=InputCoverage(evaluated=n_assets, in_scope=n_assets, limit=max(n_assets, 1)),
    )


def evaluation_input(**fields: Any) -> EvaluationInput:
    """An input over one user-scoped project; `coverage` defaults to every finding and asset read."""
    values: dict[str, Any] = {
        "resolved": ResolvedScope(scope="user", scope_id=None, project_ids=["p"]),
        "scope_description": "user",
        "crypto_assets": [],
        "findings": [],
        "policy_rules": [],
        "policy_version": 1,
        "iana_catalog_version": 1,
        "scan_ids": ["s1"],
        "override_version": None,
        "license_policy": LicensePolicySchema(),
        "db": MagicMock(),
        **fields,
    }
    values.setdefault("coverage", full_coverage(len(values["findings"]), len(values["crypto_assets"])))
    return EvaluationInput(**values)
