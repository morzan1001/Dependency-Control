"""/analytics/summary: the severity breakdown must reconcile with the headline total, so UNKNOWN/NEGLIGIBLE/INFO vulnerabilities cannot be counted in one and omitted from the other."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.api.v1.endpoints.analytics.summary import get_analytics_summary
from app.core.permissions import ALL_PERMISSIONS
from app.models.user import User

MODULE = "app.api.v1.endpoints.analytics.summary"


def _admin_user():
    return User(
        id="admin-1",
        username="admin",
        email="admin@test.com",
        permissions=list(ALL_PERMISSIONS),
    )


def _run_summary(severity_counts):
    with (
        patch(f"{MODULE}.get_user_project_ids", new=AsyncMock(return_value=["p1"])),
        patch(f"{MODULE}.get_latest_scan_ids", new=AsyncMock(return_value=["s1"])),
        patch(f"{MODULE}.DependencyRepository") as dep_repo_cls,
        patch(f"{MODULE}.FindingRepository") as finding_repo_cls,
    ):
        dep_repo = dep_repo_cls.return_value
        dep_repo.count = AsyncMock(return_value=0)
        dep_repo.get_unique_packages = AsyncMock(return_value=0)
        dep_repo.get_type_distribution = AsyncMock(return_value=[])
        finding_repo_cls.return_value.get_severity_distribution = AsyncMock(return_value=severity_counts)
        return asyncio.run(get_analytics_summary(current_user=_admin_user(), db=MagicMock()))


# Prod-observed distribution: UNKNOWN is the third-largest vulnerability bucket.
_PROD_COUNTS = {
    "MEDIUM": 3495,
    "HIGH": 3183,
    "LOW": 1161,
    "CRITICAL": 633,
    "UNKNOWN": 562,
    "NEGLIGIBLE": 172,
}


class TestSummarySeverityReconciliation:
    def test_unknown_and_negligible_appear_in_breakdown(self):
        summary = _run_summary(_PROD_COUNTS)
        dist = summary.severity_distribution
        assert dist.unknown == 562
        assert dist.negligible == 172

    def test_headline_total_equals_breakdown_sum(self):
        summary = _run_summary(_PROD_COUNTS)
        dist = summary.severity_distribution
        rendered = dist.critical + dist.high + dist.medium + dist.low + dist.info + dist.negligible + dist.unknown
        assert summary.total_vulnerabilities == rendered == sum(_PROD_COUNTS.values())

    def test_unmapped_severity_folds_into_unknown(self):
        summary = _run_summary({"CRITICAL": 1, "Moderate": 3})
        dist = summary.severity_distribution
        assert dist.unknown == 3
        assert summary.total_vulnerabilities == 4
