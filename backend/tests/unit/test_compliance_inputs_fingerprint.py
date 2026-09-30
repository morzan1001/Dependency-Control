"""The inputs fingerprint identifies which inputs a report was computed over, so two reports over
the same scans must carry the same one however Mongo happened to order them."""

import re

import pytest

from app.schemas.compliance import ReportFramework
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from tests.helpers.compliance import evaluation_input

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
