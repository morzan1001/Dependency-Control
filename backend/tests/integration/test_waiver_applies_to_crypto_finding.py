"""CRYPTO_* FindingType values work with the existing waiver machinery: _build_waiver_query and FindingRepository.apply_finding_waiver."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.models.finding import FindingType
from app.models.waiver import Waiver
from app.repositories.findings import FindingRepository
from app.services.stats import _build_waiver_query
from tests.mocks.mongodb import create_mock_collection


def _crypto_waiver(finding_type: FindingType, **extra) -> Waiver:
    """Build a type-scoped Waiver targeting the given FindingType."""
    return Waiver(
        finding_type=finding_type,
        reason="accepted for test",
        created_by="tester",
        scope="finding",
        **extra,
    )


def test_build_waiver_query_crypto_weak_algorithm():
    """_build_waiver_query maps a type-scoped waiver's finding_type to the 'type' field."""
    waiver = _crypto_waiver(FindingType.CRYPTO_WEAK_ALGORITHM)
    query = _build_waiver_query(waiver)

    assert "type" in query, f"Expected 'type' key in query, got: {query!r}"
    assert query["type"] == "crypto_weak_algorithm", (
        f"Expected query['type'] == 'crypto_weak_algorithm', got: {query['type']!r}"
    )


def test_build_waiver_query_crypto_weak_key():
    waiver = _crypto_waiver(FindingType.CRYPTO_WEAK_KEY)
    query = _build_waiver_query(waiver)
    assert query.get("type") == "crypto_weak_key"


def test_build_waiver_query_crypto_quantum_vulnerable():
    waiver = _crypto_waiver(FindingType.CRYPTO_QUANTUM_VULNERABLE)
    query = _build_waiver_query(waiver)
    assert query.get("type") == "crypto_quantum_vulnerable"


def test_build_waiver_query_component_scoped():
    """_build_waiver_query includes 'component' when package_name is set."""
    waiver = Waiver(
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        package_name="MD5 [bom-ref:a]",
        reason="test",
        created_by="tester",
        scope="finding",
    )
    query = _build_waiver_query(waiver)
    assert query.get("type") == "crypto_weak_algorithm"
    assert query.get("component") == "MD5 [bom-ref:a]"


def _make_repo_with_mock_col(modified_count: int):
    """BaseRepository sets self.collection = db[name], so the mock DB must support __getitem__."""
    mock_col = create_mock_collection()
    mock_col.update_many = AsyncMock(return_value=MagicMock(modified_count=modified_count))

    mock_db = MagicMock()
    mock_db.__getitem__ = MagicMock(return_value=mock_col)

    repo = FindingRepository(mock_db)
    return repo, mock_col


@pytest.mark.asyncio
async def test_apply_finding_waiver_calls_update_many_for_crypto_type():
    """apply_finding_waiver issues update_many combining the scan_id filter with the waiver query and setting waived/waiver_reason."""
    repo, mock_col = _make_repo_with_mock_col(modified_count=3)

    waiver_query = {"type": "crypto_weak_algorithm"}
    modified = await repo.apply_finding_waiver(
        scan_id="scan-123",
        query=waiver_query,
        waived=True,
        waiver_reason="accepted risk for MD5 use",
    )

    assert modified == 3

    mock_col.update_many.assert_called_once()
    actual_filter, actual_update = mock_col.update_many.call_args[0]

    assert actual_filter == {"scan_id": "scan-123", "type": "crypto_weak_algorithm"}, (
        f"Unexpected filter: {actual_filter!r}"
    )
    assert actual_update == {"$set": {"waived": True, "waiver_reason": "accepted risk for MD5 use"}}, (
        f"Unexpected update: {actual_update!r}"
    )


@pytest.mark.asyncio
async def test_full_waiver_flow_crypto_finding():
    """_build_waiver_query feeds FindingRepository.apply_finding_waiver, asserting the combined filter."""
    repo, mock_col = _make_repo_with_mock_col(modified_count=2)

    waiver = _crypto_waiver(FindingType.CRYPTO_WEAK_ALGORITHM)
    query = _build_waiver_query(waiver)

    modified = await repo.apply_finding_waiver(
        scan_id="scan-xyz",
        query=query,
        waived=True,
        waiver_reason=waiver.reason,
    )

    assert modified == 2

    actual_filter, actual_update = mock_col.update_many.call_args[0]
    assert actual_filter["type"] == "crypto_weak_algorithm"
    assert actual_filter["scan_id"] == "scan-xyz"
    assert actual_update["$set"]["waived"] is True
