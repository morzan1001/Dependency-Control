"""The inputs fingerprint identifies which inputs a report was computed over, so two reports over
the same scans must carry the same one however Mongo happened to order them."""

import re

from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.fips_140_3 import Fips1403Framework

_ALGORITHM_TAGGED_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _fingerprint(scan_ids: list[str], *, policy_version: int = 1) -> str:
    data = EvaluationInput(
        resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["p"]),
        scope_description="user 'alice'",
        crypto_assets=[],
        findings=[],
        policy_rules=[],
        policy_version=policy_version,
        iana_catalog_version=1,
        scan_ids=scan_ids,
    )
    return Fips1403Framework().evaluate(data).inputs_fingerprint


def test_the_fingerprint_ignores_the_order_the_scans_were_resolved_in():
    assert _fingerprint(["s2", "s1", "s3"]) == _fingerprint(["s1", "s2", "s3"])


def test_a_different_scan_set_gets_a_different_fingerprint():
    assert _fingerprint(["s1", "s2"]) != _fingerprint(["s1", "s3"])


def test_a_different_policy_version_gets_a_different_fingerprint():
    assert _fingerprint(["s1"], policy_version=1) != _fingerprint(["s1"], policy_version=2)


def test_the_fingerprint_names_the_algorithm_that_produced_it():
    assert _ALGORITHM_TAGGED_DIGEST.match(_fingerprint(["s1"]))
