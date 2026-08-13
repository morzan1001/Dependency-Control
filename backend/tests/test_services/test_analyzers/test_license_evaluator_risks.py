"""Every evaluator branch must carry the license's risks — they are a property of the license, not the policy context."""

import pytest

from app.models.license import (
    DeploymentModel,
    DistributionModel,
    LicenseCategory,
    LicenseInfo,
    LicensePolicy,
)
from app.services.analyzers.license_compliance import evaluator

RISKS = ["Copyleft obligations may apply", "Legal review required"]


def _info(category: LicenseCategory) -> LicenseInfo:
    return LicenseInfo(
        spdx_id="TEST-1.0",
        category=category,
        name="Test License",
        description="A test license.",
        obligations=["Include license text"],
        risks=RISKS,
    )


_POLICY_CASES = [
    ("proprietary_default", LicenseCategory.PROPRIETARY, LicensePolicy()),
    ("weak_copyleft_mixed_usage", LicenseCategory.WEAK_COPYLEFT, LicensePolicy()),
    (
        "strong_copyleft_internal_only",
        LicenseCategory.STRONG_COPYLEFT,
        LicensePolicy(distribution_model=DistributionModel.INTERNAL_ONLY),
    ),
    (
        "strong_copyleft_open_source",
        LicenseCategory.STRONG_COPYLEFT,
        LicensePolicy(distribution_model=DistributionModel.OPEN_SOURCE),
    ),
    (
        "strong_copyleft_allowed_by_policy",
        LicenseCategory.STRONG_COPYLEFT,
        LicensePolicy(allow_strong_copyleft=True),
    ),
    ("strong_copyleft_default", LicenseCategory.STRONG_COPYLEFT, LicensePolicy()),
    (
        "network_copyleft_non_network_deployment",
        LicenseCategory.NETWORK_COPYLEFT,
        LicensePolicy(deployment_model=DeploymentModel.CLI_BATCH),
    ),
    (
        "network_copyleft_internal_service",
        LicenseCategory.NETWORK_COPYLEFT,
        LicensePolicy(distribution_model=DistributionModel.INTERNAL_ONLY),
    ),
    (
        "network_copyleft_allowed_by_policy",
        LicenseCategory.NETWORK_COPYLEFT,
        LicensePolicy(allow_network_copyleft=True),
    ),
    ("network_copyleft_default", LicenseCategory.NETWORK_COPYLEFT, LicensePolicy()),
]


@pytest.mark.parametrize(("label", "category", "policy"), _POLICY_CASES, ids=[c[0] for c in _POLICY_CASES])
def test_issue_carries_license_risks(label, category, policy):
    issue = evaluator.evaluate_license(
        component="pkg",
        version="1.0",
        license_info=_info(category),
        lic_url=None,
        purl="pkg:npm/pkg@1.0",
        policy=policy,
    )
    assert issue is not None
    assert issue["risks"] == RISKS
