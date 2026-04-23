"""
Policy audit history service.

Public functions:
    - compute_change_summary(old, new): pure, no I/O. Deterministic one-line
      summary of rule-set differences.
    - record_policy_change(...): async, performs the full persist + webhook +
      notification workflow. (Added in Task B.3.)
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED
from app.models.crypto_policy import CryptoPolicy
from app.models.policy_audit_entry import PolicyAuditEntry
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.schemas.crypto_policy import CryptoRule
from app.schemas.policy_audit import PolicyAuditAction

logger = logging.getLogger(__name__)

# Fields compared when detecting "modified" rules. Not exhaustive — only the
# fields users actually adjust.
_COMPARED_FIELDS: Tuple[str, ...] = (
    "enabled",
    "default_severity",
    "finding_type",
    "match_primitive",
    "match_name_patterns",
    "match_min_key_size_bits",
    "match_curves",
    "match_protocol_versions",
    "quantum_vulnerable",
    "match_cipher_weaknesses",
    "expiry_critical_days",
    "expiry_high_days",
    "expiry_medium_days",
    "expiry_low_days",
    "validity_too_long_days",
)


def compute_change_summary(old: Optional[CryptoPolicy], new: CryptoPolicy) -> str:
    """Deterministic human-readable diff summary (<=200 chars)."""
    if old is None:
        return f"Initial policy ({len(new.rules)} rules)"

    old_by_id = {r.rule_id: r for r in old.rules}
    new_by_id = {r.rule_id: r for r in new.rules}
    added = new_by_id.keys() - old_by_id.keys()
    removed = old_by_id.keys() - new_by_id.keys()
    common = old_by_id.keys() & new_by_id.keys()

    toggled: List[str] = []
    modified: List[str] = []
    for rid in common:
        o_rule = old_by_id[rid]
        n_rule = new_by_id[rid]
        diff_fields = [f for f in _COMPARED_FIELDS if getattr(o_rule, f, None) != getattr(n_rule, f, None)]
        if not diff_fields:
            continue
        if diff_fields == ["enabled"]:
            toggled.append(rid)
        else:
            modified.append(rid)

    parts: List[str] = []
    if added:
        parts.append(f"added {len(added)} rule(s)")
    if removed:
        parts.append(f"removed {len(removed)}")
    if toggled:
        parts.append(f"toggled enabled on {len(toggled)}")
    if modified:
        parts.append(f"modified {len(modified)}")

    if not parts:
        summary = "No effective changes"
    else:
        summary = ", ".join(parts).capitalize()

    return summary[:200]


async def record_policy_change(
    db: AsyncIOMotorDatabase,
    *,
    policy_scope: str,
    project_id: Optional[str],
    old_policy: Optional[CryptoPolicy],
    new_policy: CryptoPolicy,
    action: PolicyAuditAction,
    actor,
    comment: Optional[str],
    reverted_from_version: Optional[int] = None,
) -> PolicyAuditEntry:
    """Persist an audit entry, fire webhook + notifications.

    Best-effort: webhook/notification failures are logged but do not raise.
    """
    summary = compute_change_summary(old_policy, new_policy)
    entry = PolicyAuditEntry(
        policy_scope=policy_scope,
        project_id=project_id,
        version=new_policy.version,
        action=action,
        actor_user_id=_actor_id(actor),
        actor_display_name=_actor_display_name(actor),
        timestamp=datetime.now(timezone.utc),
        snapshot=new_policy.model_dump(by_alias=True),
        change_summary=summary,
        comment=comment,
        reverted_from_version=reverted_from_version,
    )
    try:
        await PolicyAuditRepository(db).insert(entry)
    except Exception:
        logger.exception("Policy audit persistence failed (non-blocking)")
    try:
        await _dispatch_webhook(db, entry)
    except Exception:
        logger.exception("Policy audit webhook dispatch failed (non-blocking)")
    try:
        await _notify_relevant_users(db, entry)
    except Exception:
        logger.exception("Policy audit notification failed (non-blocking)")
    return entry


def _actor_id(actor) -> Optional[str]:
    if actor is None:
        return None
    return getattr(actor, "id", None) or getattr(actor, "user_id", None)


def _actor_display_name(actor) -> Optional[str]:
    if actor is None:
        return None
    for attr in ("display_name", "full_name", "username", "email"):
        val = getattr(actor, attr, None)
        if val:
            return str(val)
    return None


async def _dispatch_webhook(db, entry: PolicyAuditEntry) -> None:
    """Fire crypto_policy.changed webhook. Best-effort."""
    from app.services.webhooks import webhook_service

    payload = {
        "event": WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED,
        "timestamp": entry.timestamp.isoformat(),
        "policy_scope": entry.policy_scope,
        "project_id": entry.project_id,
        "version": entry.version,
        "action": entry.action.value if hasattr(entry.action, "value") else entry.action,
        "actor": {
            "user_id": entry.actor_user_id,
            "display_name": entry.actor_display_name,
        },
        "change_summary": entry.change_summary,
        "comment": entry.comment,
        "reverted_from_version": entry.reverted_from_version,
    }
    await webhook_service.trigger_webhooks(
        db,
        event_type=WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED,
        payload=payload,
        project_id=entry.project_id,
    )


async def _notify_relevant_users(db, entry: PolicyAuditEntry) -> None:
    """Create in-app notifications for users affected by the policy change.

    Skipped for SEED (system-initiated, no info value).
    Adapts to the actual notification_service API.
    """
    if entry.action == PolicyAuditAction.SEED or entry.action == "seed":
        return
    try:
        from app.services.notifications import service as notification_service
    except ImportError:
        return

    title_scope = "System" if entry.policy_scope == "system" else f"Project {entry.project_id}"
    title = f"{title_scope} crypto policy changed"
    body = f"{entry.actor_display_name or 'A user'} updated the policy: {entry.change_summary}"
    # Attempt common helper names; swallow AttributeError if none match.
    if entry.policy_scope == "project":
        if hasattr(notification_service, "notify_project_members"):
            await notification_service.notify_project_members(
                db,
                project_id=entry.project_id,
                title=title,
                body=body,
                link=f"/projects/{entry.project_id}?tab=crypto-policy",
            )
    else:
        if hasattr(notification_service, "notify_users_with_permission"):
            await notification_service.notify_users_with_permission(
                db,
                permission="system:manage",
                title=title,
                body=body,
                link="/settings/crypto-policy",
            )
