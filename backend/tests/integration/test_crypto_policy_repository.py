"""Tests for CryptoPolicyRepository. Uses mocked MongoDB."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock


from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from tests.mocks.mongodb import create_mock_collection


def _make_mock_db(collection):
    """Create a mock database that supports dict-style access."""
    db = MagicMock()
    db.__getitem__ = MagicMock(return_value=collection)
    return db


def _rule(rule_id: str) -> CryptoRule:
    return CryptoRule(
        rule_id=rule_id,
        name=rule_id,
        description="",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=Severity.HIGH,
        source=CryptoPolicySource.NIST_SP_800_131A,
    )


def _policy_doc(**overrides):
    """Create a raw crypto policy document."""
    doc = {
        "_id": "policy-1",
        "scope": "system",
        "project_id": None,
        "rules": [],
        "version": 1,
        "updated_at": datetime.now(timezone.utc),
    }
    doc.update(overrides)
    return doc


class TestUpsertAndGetSystem:
    def test_upsert_and_get_system(self):
        sys_doc = _policy_doc(scope="system", rules=[], version=1)
        collection = create_mock_collection(find_one=sys_doc)
        db = _make_mock_db(collection)
        repo = CryptoPolicyRepository(db)

        p = CryptoPolicy(scope="system", rules=[_rule("r1")], version=1)
        asyncio.run(repo.upsert_system_policy(p))
        got = asyncio.run(repo.get_system_policy())
        assert got is not None
        assert got.version == 1


class TestUpsertSystemReplaces:
    def test_upsert_system_replaces(self):
        sys_doc = _policy_doc(scope="system", rules=[], version=2)
        collection = create_mock_collection(find_one=sys_doc)
        db = _make_mock_db(collection)
        repo = CryptoPolicyRepository(db)

        asyncio.run(repo.upsert_system_policy(CryptoPolicy(scope="system", rules=[_rule("b")], version=2)))
        got = asyncio.run(repo.get_system_policy())
        assert got.version == 2


class TestProjectOverrideIsolation:
    def test_project_override_isolation(self):
        p1_doc = _policy_doc(_id="p1", scope="project", project_id="p1", rules=[], version=1)
        p2_doc = _policy_doc(_id="p2", scope="project", project_id="p2", rules=[], version=1)

        collection1 = create_mock_collection(find_one=p1_doc)
        db1 = _make_mock_db(collection1)
        repo1 = CryptoPolicyRepository(db1)

        collection2 = create_mock_collection(find_one=p2_doc)
        db2 = _make_mock_db(collection2)
        repo2 = CryptoPolicyRepository(db2)

        p1 = CryptoPolicy(scope="project", project_id="p1", rules=[_rule("x")], version=1)
        asyncio.run(repo1.upsert_project_policy(p1))
        got1 = asyncio.run(repo1.get_project_policy("p1"))

        p2 = CryptoPolicy(scope="project", project_id="p2", rules=[_rule("y")], version=1)
        asyncio.run(repo2.upsert_project_policy(p2))
        got2 = asyncio.run(repo2.get_project_policy("p2"))

        assert got1 is not None
        assert got2 is not None


class TestDeleteProjectOverride:
    def test_delete_project_override(self):
        collection = create_mock_collection(find_one=None)
        db = _make_mock_db(collection)
        repo = CryptoPolicyRepository(db)

        p = CryptoPolicy(scope="project", project_id="pd", rules=[_rule("z")], version=1)
        asyncio.run(repo.upsert_project_policy(p))
        asyncio.run(repo.delete_project_policy("pd"))
        got = asyncio.run(repo.get_project_policy("pd"))
        assert got is None


class TestSeedPreservesProjectOverride:
    def test_seed_preserves_project_override(self):
        override_doc = _policy_doc(_id="keep", scope="project", project_id="keep", rules=[], version=1)
        collection = create_mock_collection(find_one=override_doc)
        db = _make_mock_db(collection)
        repo = CryptoPolicyRepository(db)

        override = asyncio.run(repo.get_project_policy("keep"))
        assert override is not None
