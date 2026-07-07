"""Tests that create_indexes targets the collections the app actually uses.

Regression for the audit finding: init_db created the invitation token/email
indexes on ``project_invitations`` and the policy-audit indexes on
``policy_audit_entries``, but the repositories store those documents in
``invitations`` (InvitationRepository.project_invitations = db.invitations) and
``crypto_policy_history`` (PolicyAuditRepository.collection_name). The result was
a missing unique token index on the real invitations collection (uniqueness
unenforced, token lookups full-scan) and four indexes stranded on a permanently
empty collection while every policy-audit query ran unindexed.
"""

import asyncio
from unittest.mock import AsyncMock

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase


def _spy(db, name):
    col = db[name]
    col.create_index = AsyncMock()
    return col


def test_invitation_indexes_target_real_invitations_collection():
    db = FakeDatabase()
    real = _spy(db, "invitations")
    wrong = _spy(db, "project_invitations")

    asyncio.run(create_indexes(db))

    assert wrong.create_index.await_count == 0, (
        "No index should be created on the unused 'project_invitations' collection"
    )
    # token (unique) + email indexes must land on the real 'invitations' collection.
    assert real.create_index.await_count == 2
    token_call = real.create_index.await_args_list[0]
    assert token_call.args == ("token",)
    assert token_call.kwargs.get("unique") is True
    assert real.create_index.await_args_list[1].args == ("email",)


def test_policy_audit_indexes_target_crypto_policy_history_collection():
    db = FakeDatabase()
    real = _spy(db, "crypto_policy_history")
    wrong = _spy(db, "policy_audit_entries")

    asyncio.run(create_indexes(db))

    assert wrong.create_index.await_count == 0, (
        "No index should be created on the unused 'policy_audit_entries' collection"
    )
    # All four policy-audit indexes must land on 'crypto_policy_history'.
    assert real.create_index.await_count == 4
