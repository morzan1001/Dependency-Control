"""CRYPTO_* FindingType values work with the existing waiver machinery: waiver_query and the restamp."""

import pytest

from app.models.finding import FindingType
from app.models.waiver import Waiver
from app.repositories.findings import FindingRepository
from app.services.waivers.apply import restamp_waivers
from app.services.waivers.matching import waiver_query
from tests.mocks.fake_mongo import FakeDatabase


def _crypto_waiver(finding_type: FindingType, **extra) -> Waiver:
    """Build a type-scoped Waiver targeting the given FindingType."""
    return Waiver(
        finding_type=finding_type,
        reason="accepted for test",
        created_by="tester",
        scope="finding",
        **extra,
    )


def test_waiver_query_crypto_weak_algorithm():
    """waiver_query maps a type-scoped waiver's finding_type to the 'type' field."""
    waiver = _crypto_waiver(FindingType.CRYPTO_WEAK_ALGORITHM)
    query = waiver_query(waiver)

    assert "type" in query, f"Expected 'type' key in query, got: {query!r}"
    assert query["type"] == "crypto_weak_algorithm", (
        f"Expected query['type'] == 'crypto_weak_algorithm', got: {query['type']!r}"
    )


def test_waiver_query_crypto_weak_key():
    waiver = _crypto_waiver(FindingType.CRYPTO_WEAK_KEY)
    query = waiver_query(waiver)
    assert query.get("type") == "crypto_weak_key"


def test_waiver_query_crypto_quantum_vulnerable():
    waiver = _crypto_waiver(FindingType.CRYPTO_QUANTUM_VULNERABLE)
    query = waiver_query(waiver)
    assert query.get("type") == "crypto_quantum_vulnerable"


def test_waiver_query_component_scoped():
    """waiver_query includes 'component' when package_name is set."""
    waiver = Waiver(
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        package_name="MD5 [bom-ref:a]",
        reason="test",
        created_by="tester",
        scope="finding",
    )
    query = waiver_query(waiver)
    assert query.get("type") == "crypto_weak_algorithm"
    assert query.get("component") == "MD5 [bom-ref:a]"


@pytest.mark.asyncio
async def test_the_restamp_waives_a_crypto_finding_by_its_type():
    db = FakeDatabase()
    await db.findings.insert_many(
        [
            {"_id": "md5", "scan_id": "scan-xyz", "type": "crypto_weak_algorithm", "component": "MD5 [bom-ref:a]"},
            {"_id": "rsa", "scan_id": "scan-xyz", "type": "crypto_weak_key", "component": "RSA-1024 [bom-ref:b]"},
        ]
    )

    await restamp_waivers(FindingRepository(db), None, "scan-xyz", [_crypto_waiver(FindingType.CRYPTO_WEAK_ALGORITHM)])

    assert [doc["_id"] async for doc in db.findings.find({"waived": True})] == ["md5"]
