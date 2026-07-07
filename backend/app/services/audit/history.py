"""Policy audit history: change summaries and persistence for crypto/license policy edits."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import (
    WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED,
    WEBHOOK_EVENT_LICENSE_POLICY_CHANGED,
)
from app.models.crypto_policy import CryptoPolicy
from app.models.policy_audit_entry import PolicyAuditEntry
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.schemas.policy_audit import PolicyAuditAction

logger = logging.getLogger(__name__)

_NO_CHANGES_SUMMARY = "No effective changes"

# Fields compared to detect a modified rule; not exhaustive.
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
        summary = _NO_CHANGES_SUMMARY
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
    actor: Any,
    comment: Optional[str],
    reverted_from_version: Optional[int] = None,
) -> PolicyAuditEntry:
    """Persist an audit entry and fire webhook + notifications (best-effort)."""
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
    # A policy change invalidates cached analytics derived from it; flush the TTL cache.
    try:
        from app.services.analytics.cache import get_analytics_cache

        get_analytics_cache().clear()
    except Exception:
        logger.exception("Analytics cache invalidation failed (non-blocking)")
    try:
        await _dispatch_webhook(db, entry, event_type=WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED)
    except Exception:
        logger.exception("Policy audit webhook dispatch failed (non-blocking)")
    try:
        await _notify_relevant_users(db, entry)
    except Exception:
        logger.exception("Policy audit notification failed (non-blocking)")
    return entry


def _actor_id(actor: Any) -> Optional[str]:
    if actor is None:
        return None
    result = getattr(actor, "id", None) or getattr(actor, "user_id", None)
    return str(result) if result is not None else None


def _actor_display_name(actor: Any) -> Optional[str]:
    if actor is None:
        return None
    for attr in ("display_name", "full_name", "username", "email"):
        val = getattr(actor, attr, None)
        if val:
            return str(val)
    return None


async def _dispatch_webhook(
    db: AsyncIOMotorDatabase,
    entry: PolicyAuditEntry,
    *,
    event_type: str,
) -> None:
    """Fire a policy.changed webhook. Best-effort."""
    from app.services.webhooks import webhook_service

    policy_type = getattr(entry, "policy_type", "crypto") or "crypto"
    payload = {
        "event": event_type,
        "timestamp": entry.timestamp.isoformat(),
        "policy_type": policy_type,
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
    await webhook_service.safe_trigger_webhooks(
        db,
        event_type=event_type,
        payload=payload,
        project_id=entry.project_id,
        context=f"policy_audit:{policy_type}",
    )


async def _notify_relevant_users(
    db: AsyncIOMotorDatabase,
    entry: PolicyAuditEntry,
    *,
    subject_noun: str = "crypto policy",
    event_type: str = "crypto_policy_changed",
) -> None:
    """Notify users affected by a policy change; system-scope hits system:manage/analytics:global holders, project-scope hits members. Skipped for SEED."""
    if entry.action == PolicyAuditAction.SEED or entry.action == "seed":
        return

    from app.services.notifications.service import notification_service

    title_scope = "System" if entry.policy_scope == "system" else f"Project {entry.project_id}"
    subject = f"{title_scope} {subject_noun} changed"
    message = f"{entry.actor_display_name or 'A user'} updated the policy: {entry.change_summary}"

    if entry.policy_scope == "project":
        if entry.project_id is None:
            return
        from app.repositories.projects import ProjectRepository

        project = await ProjectRepository(db).get_by_id(entry.project_id)
        if project is None:
            return
        await notification_service.notify_project_members(
            project=project,
            event_type=event_type,
            subject=subject,
            message=message,
            db=db,
        )
    else:
        await notification_service.notify_users_with_permission(
            db,
            permission=["system:manage", "analytics:global"],
            event_type=event_type,
            subject=subject,
            message=message,
        )


# Fields compared to detect a license-policy change; all values are scalar.
_LICENSE_COMPARED_FIELDS: Tuple[str, ...] = (
    "distribution_model",
    "deployment_model",
    "library_usage",
    "allow_strong_copyleft",
    "allow_network_copyleft",
    "ignore_dev_dependencies",
    "ignore_transitive",
)


def compute_license_policy_change_summary(
    old: Optional[Dict[str, Any]],
    new: Optional[Dict[str, Any]],
) -> str:
    """Deterministic one-line summary of a license-policy transition (<=200 chars)."""
    if old is None and new is None:
        return _NO_CHANGES_SUMMARY
    old = old or {}
    new = new or {}
    if not old:
        return f"Initial license policy ({len(new)} setting(s))"
    if not new:
        return "License policy cleared"

    parts: List[str] = []
    for field in _LICENSE_COMPARED_FIELDS:
        old_v = old.get(field)
        new_v = new.get(field)
        if old_v == new_v:
            continue
        if old_v is None:
            parts.append(f"added {field}={new_v}")
        elif new_v is None:
            parts.append(f"removed {field}")
        else:
            parts.append(f"{field}: {old_v} -> {new_v}")
    if not parts:
        return _NO_CHANGES_SUMMARY
    return ", ".join(parts)[:200]


async def record_license_policy_change(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    old_policy: Optional[Dict[str, Any]],
    new_policy: Optional[Dict[str, Any]],
    action: PolicyAuditAction,
    actor: Any,
    comment: Optional[str] = None,
) -> Optional[PolicyAuditEntry]:
    """Persist a license-policy audit entry (best-effort); returns None if no effective change. Version derives from existing entry count since the project doc has no version column."""
    summary = compute_license_policy_change_summary(old_policy, new_policy)
    if summary == _NO_CHANGES_SUMMARY:
        return None

    repo = PolicyAuditRepository(db)
    existing = await repo.count_entries(
        policy_scope="project",
        project_id=project_id,
        policy_type="license",
    )
    version = existing + 1

    entry = PolicyAuditEntry(
        policy_type="license",
        policy_scope="project",
        project_id=project_id,
        version=version,
        action=action,
        actor_user_id=_actor_id(actor),
        actor_display_name=_actor_display_name(actor),
        timestamp=datetime.now(timezone.utc),
        snapshot=dict(new_policy or {}),
        change_summary=summary,
        comment=comment,
    )
    try:
        await repo.insert(entry)
    except Exception:
        logger.exception("License-policy audit persistence failed (non-blocking)")
    try:
        await _dispatch_webhook(db, entry, event_type=WEBHOOK_EVENT_LICENSE_POLICY_CHANGED)
    except Exception:
        logger.exception("License-policy webhook dispatch failed (non-blocking)")
    try:
        await _notify_relevant_users(
            db,
            entry,
            subject_noun="license policy",
            event_type="license_policy_changed",
        )
    except Exception:
        logger.exception("License-policy notification failed (non-blocking)")
    return entry
