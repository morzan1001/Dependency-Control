"""Two reports over the same scans must carry the same fingerprint however Mongo ordered the inputs."""

import re
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.schemas.compliance import ReportFramework
from app.schemas.project import LicensePolicySchema
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from tests.helpers.compliance import evaluation_input
from tests.unit.test_framework_pqc_migration_plan import _evaluate, _plan

_ALGORITHM_TAGGED_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


async def _fingerprint(scan_ids: list[str], *, policy_version: int = 1, override_version: int | None = None) -> str:
    data = evaluation_input(scan_ids=scan_ids, policy_version=policy_version, override_version=override_version)
    return (await FRAMEWORK_REGISTRY[ReportFramework.FIPS_140_3].evaluate(data)).inputs_fingerprint


@pytest.mark.asyncio
async def test_the_fingerprint_ignores_the_order_the_scans_were_resolved_in():
    assert await _fingerprint(["s2", "s1", "s3"]) == await _fingerprint(["s1", "s2", "s3"])


@pytest.mark.asyncio
async def test_a_different_scan_set_gets_a_different_fingerprint():
    assert await _fingerprint(["s1", "s2"]) != await _fingerprint(["s1", "s3"])


@pytest.mark.asyncio
async def test_a_different_policy_version_gets_a_different_fingerprint():
    assert await _fingerprint(["s1"], policy_version=1) != await _fingerprint(["s1"], policy_version=2)


@pytest.mark.asyncio
async def test_a_project_override_gets_a_different_fingerprint():
    assert await _fingerprint(["s1"]) != await _fingerprint(["s1"], override_version=1)


@pytest.mark.asyncio
async def test_the_fingerprint_names_the_algorithm_that_produced_it():
    assert _ALGORITHM_TAGGED_DIGEST.match(await _fingerprint(["s1"]))


@pytest.fixture
def _stub_pqc_plan():
    with patch("app.services.compliance.frameworks.pqc_migration_plan.PQCMigrationPlanGenerator") as generator:
        generator.return_value = MagicMock(generate=AsyncMock(return_value=_plan()))
        yield


@pytest.mark.parametrize("key", list(FRAMEWORK_REGISTRY))
@pytest.mark.asyncio
@pytest.mark.usefixtures("_stub_pqc_plan")
async def test_every_framework_fingerprints_the_scans_it_read(key):
    framework = FRAMEWORK_REGISTRY[key]
    one = (await framework.evaluate(evaluation_input(scan_ids=["s1"]))).inputs_fingerprint
    other = (await framework.evaluate(evaluation_input(scan_ids=["s2"]))).inputs_fingerprint

    assert one != other
    assert _ALGORITHM_TAGGED_DIGEST.match(one)


@pytest.mark.asyncio
async def test_a_license_audit_under_another_license_policy_gets_a_different_fingerprint():
    framework = FRAMEWORK_REGISTRY[ReportFramework.LICENSE_AUDIT]
    strict = await framework.evaluate(evaluation_input(license_policy=LicensePolicySchema()))
    lenient = await framework.evaluate(evaluation_input(license_policy=LicensePolicySchema(allow_strong_copyleft=True)))

    assert strict.inputs_fingerprint != lenient.inputs_fingerprint


@pytest.mark.asyncio
async def test_a_pqc_plan_from_another_mapping_table_gets_a_different_fingerprint():
    current = await _evaluate(_plan())
    remapped = await _evaluate(_plan().model_copy(update={"mappings_version": 2}))

    assert current.inputs_fingerprint != remapped.inputs_fingerprint


def _overdue_vulnerability(**fields) -> dict:
    return {
        "_id": "rec-1",
        "finding_id": "pkg:1.0",
        "type": "vulnerability",
        "severity": "CRITICAL",
        "scan_id": "s1",
        "waived": False,
        "first_seen_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "details": {"vulnerabilities": [{"severity": "CRITICAL", "waived": False}]},
        **fields,
    }


async def _sla_fingerprint(findings: list[dict]) -> str:
    framework = FRAMEWORK_REGISTRY[ReportFramework.CVE_REMEDIATION_SLA]
    return (await framework.evaluate(evaluation_input(findings=findings))).inputs_fingerprint


@pytest.mark.asyncio
async def test_a_finding_waived_since_under_the_same_scans_gets_a_different_fingerprint():
    waived = _overdue_vulnerability(waived=True, waiver_reason="accepted")

    assert await _sla_fingerprint([_overdue_vulnerability()]) != await _sla_fingerprint([waived])


@pytest.mark.asyncio
async def test_an_advisory_waived_since_under_the_same_scans_gets_a_different_fingerprint():
    waived = _overdue_vulnerability(details={"vulnerabilities": [{"severity": "CRITICAL", "waived": True}]})

    assert await _sla_fingerprint([_overdue_vulnerability()]) != await _sla_fingerprint([waived])


@pytest.mark.asyncio
async def test_the_fingerprint_ignores_the_order_the_findings_were_read_in():
    one, two = _overdue_vulnerability(), _overdue_vulnerability(_id="rec-2", finding_id="other:2.0")

    assert await _sla_fingerprint([one, two]) == await _sla_fingerprint([two, one])
