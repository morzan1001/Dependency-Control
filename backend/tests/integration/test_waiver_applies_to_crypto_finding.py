"""
Integration tests: waiver machinery applies to new CRYPTO_WEAK_ALGORITHM findings.

Waiver application in the production path goes through:
  1. engine._apply_waivers (calls stats._build_waiver_query + finding_repo.apply_finding_waiver)
  2. FindingRepository.apply_finding_waiver (update_many on the findings collection)

The in-process _FakeDb does NOT support `update_many`, and the WaiverRepository
requires `insert_one`, `delete_one`, and cursor `.sort()` — none of which are
implemented by _FakeCollection.  Exercising the full engine path requires a live
worker+engine pipeline (which is absent in this environment).

Strategy (Option A from the task spec):
  - Test `_build_waiver_query` directly (pure function, no DB) to verify it
    translates a FindingType.CRYPTO_WEAK_ALGORITHM waiver into the correct
    MongoDB query dict.
  - Test `FindingRepository.apply_finding_waiver` using the mock collection from
    tests/mocks/mongodb.py, which supports `update_many`, to verify the method
    issues the right bulk update and returns the modified count.

This demonstrates that the new FindingType values are fully compatible with the
existing waiver infrastructure without needing a live engine.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, call

from app.models.finding import FindingType, Severity
from app.models.waiver import Waiver
from app.repositories.findings import FindingRepository
from app.services.stats import _build_waiver_query
from tests.mocks.mongodb import create_mock_collection, create_mock_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _crypto_waiver(finding_type: FindingType, **extra) -> Waiver:
    """Build a type-scoped Waiver targeting the given FindingType."""
    return Waiver(
        finding_type=finding_type,
        reason="accepted for test",
        created_by="tester",
        scope="finding",
        **extra,
    )


# ---------------------------------------------------------------------------
# Tests: _build_waiver_query (pure function, no DB required)
# ---------------------------------------------------------------------------

def test_build_waiver_query_crypto_weak_algorithm():
    """_build_waiver_query maps finding_type → 'type' field in the query dict.

    A type-scoped waiver for CRYPTO_WEAK_ALGORITHM should produce a query that
    matches findings by their `type` field, which is how FindingRepository
    (and the engine) applies waivers to findings in bulk.
    """
    waiver = _crypto_waiver(FindingType.CRYPTO_WEAK_ALGORITHM)
    query = _build_waiver_query(waiver)

    # The 'finding_type' waiver field maps to the 'type' field on findings
    assert "type" in query, (
        f"Expected 'type' key in query, got: {query!r}"
    )
    assert query["type"] == "crypto_weak_algorithm", (
        f"Expected query['type'] == 'crypto_weak_algorithm', got: {query['type']!r}"
    )


def test_build_waiver_query_crypto_weak_key():
    """_build_waiver_query handles CRYPTO_WEAK_KEY finding type correctly."""
    waiver = _crypto_waiver(FindingType.CRYPTO_WEAK_KEY)
    query = _build_waiver_query(waiver)
    assert query.get("type") == "crypto_weak_key"


def test_build_waiver_query_crypto_quantum_vulnerable():
    """_build_waiver_query handles CRYPTO_QUANTUM_VULNERABLE finding type correctly."""
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


# ---------------------------------------------------------------------------
# Tests: FindingRepository.apply_finding_waiver (uses mock collection)
# ---------------------------------------------------------------------------

def _make_repo_with_mock_col(modified_count: int):
    """Create a FindingRepository backed by a mock collection.

    BaseRepository.__init__ does `self.collection = db[self.collection_name]`,
    so the mock DB must support dict-style access via __getitem__.
    """
    mock_col = create_mock_collection()
    mock_col.update_many = AsyncMock(return_value=MagicMock(modified_count=modified_count))

    mock_db = MagicMock()
    mock_db.__getitem__ = MagicMock(return_value=mock_col)

    repo = FindingRepository(mock_db)
    # repo.collection is now mock_col (set by BaseRepository.__init__)
    return repo, mock_col


@pytest.mark.asyncio
async def test_apply_finding_waiver_calls_update_many_for_crypto_type():
    """apply_finding_waiver issues update_many with the correct filter for a crypto type.

    This verifies that FindingRepository.apply_finding_waiver correctly:
    - Combines the scan_id filter with the waiver query
    - Sets waived=True and waiver_reason on matching finding documents

    The test uses a mock collection (not _FakeDb) because apply_finding_waiver
    calls update_many which is absent from _FakeCollection.
    """
    repo, mock_col = _make_repo_with_mock_col(modified_count=3)

    waiver_query = {"type": "crypto_weak_algorithm"}
    modified = await repo.apply_finding_waiver(
        scan_id="scan-123",
        query=waiver_query,
        waived=True,
        waiver_reason="accepted risk for MD5 use",
    )

    assert modified == 3

    # Verify update_many was called with the correct combined filter and update
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
    """End-to-end waiver flow: build query → apply to crypto findings via mock DB.

    This test chains _build_waiver_query (which converts a Waiver model into a
    MongoDB filter dict) with FindingRepository.apply_finding_waiver (which
    issues the update_many).  Together they form the engine's waiver-application
    path.

    The test does NOT require a live engine — it uses a mock collection that
    captures the update_many call, letting us assert the full filter constructed
    from a real Waiver object with a CRYPTO_WEAK_ALGORITHM FindingType.
    """
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
