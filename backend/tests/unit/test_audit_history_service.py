from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.schemas.policy_audit import PolicyAuditAction
from app.services.audit.history import record_policy_change
from app.services.webhooks import webhook_service


def _rule(rule_id):
    return CryptoRule(
        rule_id=rule_id,
        name=rule_id,
        description="",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=Severity.HIGH,
        source=CryptoPolicySource.CUSTOM,
    )


@pytest.mark.asyncio
async def test_record_policy_change_persists_entry():
    db = MagicMock()
    insert_mock = AsyncMock()
    with (
        patch(
            "app.services.audit.history.PolicyAuditRepository",
            return_value=MagicMock(create=insert_mock),
        ),
        patch(
            "app.services.audit.history._dispatch_webhook",
            new=AsyncMock(),
        ),
        patch(
            "app.services.audit.history._notify_relevant_users",
            new=AsyncMock(),
        ),
    ):
        new = CryptoPolicy(scope="system", version=2, rules=[_rule("a")])
        entry = await record_policy_change(
            db,
            policy_scope="system",
            project_id=None,
            old_policy=None,
            new_policy=new,
            action=PolicyAuditAction.SEED,
            actor=None,
            comment=None,
        )

    insert_mock.assert_awaited_once()
    assert entry.version == 2
    assert entry.action == PolicyAuditAction.SEED
    assert "Initial policy" in entry.change_summary


@pytest.mark.asyncio
async def test_record_policy_change_survives_webhook_failure():
    """Webhook dispatch failure must not block the audit persist."""
    db = MagicMock()
    insert_mock = AsyncMock()
    delivery_mock = AsyncMock(side_effect=RuntimeError("webhook down"))
    notify_mock = AsyncMock()
    with (
        patch(
            "app.services.audit.history.PolicyAuditRepository",
            return_value=MagicMock(create=insert_mock),
        ),
        patch.object(webhook_service, "trigger_webhooks", new=delivery_mock),
        patch(
            "app.services.audit.history._notify_relevant_users",
            new=notify_mock,
        ),
    ):
        new = CryptoPolicy(scope="system", version=1, rules=[])
        entry = await record_policy_change(
            db,
            policy_scope="system",
            project_id=None,
            old_policy=None,
            new_policy=new,
            action=PolicyAuditAction.SEED,
            actor=None,
            comment=None,
        )

    insert_mock.assert_awaited_once()
    delivery_mock.assert_awaited_once()
    assert entry is not None
    notify_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_record_policy_change_denormalises_actor():
    db = MagicMock()
    insert_mock = AsyncMock()
    actor = MagicMock(id="u42", display_name="alice", email="alice@example.com")
    with (
        patch(
            "app.services.audit.history.PolicyAuditRepository",
            return_value=MagicMock(create=insert_mock),
        ),
        patch(
            "app.services.audit.history._dispatch_webhook",
            new=AsyncMock(),
        ),
        patch(
            "app.services.audit.history._notify_relevant_users",
            new=AsyncMock(),
        ),
    ):
        new = CryptoPolicy(scope="project", project_id="p", version=3, rules=[_rule("a")])
        entry = await record_policy_change(
            db,
            policy_scope="project",
            project_id="p",
            old_policy=None,
            new_policy=new,
            action=PolicyAuditAction.CREATE,
            actor=actor,
            comment="first override",
        )

    assert entry.actor_user_id == "u42"
    assert entry.actor_display_name == "alice"
    assert entry.comment == "first override"
