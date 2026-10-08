"""Policy audit history: change summaries and persistence for crypto/license policy edits."""

import logging
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import (
    NOTIFICATION_EVENT_CRYPTO_POLICY_CHANGED,
    NOTIFICATION_EVENT_LICENSE_POLICY_CHANGED,
    POLICY_CHANGE_SUMMARY_MAX_LENGTH,
    WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED,
    WEBHOOK_EVENT_LICENSE_POLICY_CHANGED,
    NotificationEvent,
)
from app.core.permissions import Permissions
from app.models.crypto_policy import CryptoPolicy
from app.models.policy_audit_entry import PolicyAuditEntry, PolicyType
from app.models.user import User
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.repositories.projects import ProjectRepository
from app.schemas.policy_audit import PolicyAuditAction
from app.schemas.project import LicensePolicySchema
from app.services.notifications.service import notification_service
from app.services.webhooks import webhook_service

logger = logging.getLogger(__name__)

_NO_CHANGES_SUMMARY = "No effective changes"

_POLICY_EVENTS: dict[PolicyType, tuple[str, NotificationEvent, str]] = {
    "crypto": (WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED, NOTIFICATION_EVENT_CRYPTO_POLICY_CHANGED, "crypto policy"),
    "license": (WEBHOOK_EVENT_LICENSE_POLICY_CHANGED, NOTIFICATION_EVENT_LICENSE_POLICY_CHANGED, "license policy"),
}


def compute_change_summary(old: CryptoPolicy | None, new: CryptoPolicy) -> str:
    """Deterministic human-readable diff summary."""
    if old is None:
        return f"Initial policy ({len(new.rules)} rules)"

    old_by_id = {r.rule_id: r.model_dump() for r in old.rules}
    new_by_id = {r.rule_id: r.model_dump() for r in new.rules}
    added = new_by_id.keys() - old_by_id.keys()
    removed = old_by_id.keys() - new_by_id.keys()

    toggled: list[str] = []
    modified: list[str] = []
    for rid in old_by_id.keys() & new_by_id.keys():
        o_rule, n_rule = old_by_id[rid], new_by_id[rid]
        if o_rule == n_rule:
            continue
        if {**o_rule, "enabled": n_rule["enabled"]} == n_rule:
            toggled.append(rid)
        else:
            modified.append(rid)

    parts: list[str] = []
    if added:
        parts.append(f"added {len(added)} rule(s)")
    if removed:
        parts.append(f"removed {len(removed)}")
    if toggled:
        parts.append(f"toggled enabled on {len(toggled)}")
    if modified:
        parts.append(f"modified {len(modified)}")

    return ", ".join(parts).capitalize() if parts else _NO_CHANGES_SUMMARY


async def record_policy_change(
    db: AsyncIOMotorDatabase,
    *,
    policy_scope: str,
    project_id: str | None,
    old_policy: CryptoPolicy | None,
    new_policy: CryptoPolicy,
    action: PolicyAuditAction,
    actor: User | None,
    comment: str | None,
    reverted_from_version: int | None = None,
) -> PolicyAuditEntry:
    """Persist an audit entry and fire webhook + notifications (best-effort)."""
    entry = PolicyAuditEntry(
        policy_scope=policy_scope,
        project_id=project_id,
        version=new_policy.version,
        action=action,
        actor_user_id=actor.id if actor else None,
        actor_display_name=(actor.username or actor.email) if actor else None,
        timestamp=datetime.now(timezone.utc),
        snapshot=new_policy.model_dump(by_alias=True),
        change_summary=compute_change_summary(old_policy, new_policy),
        comment=comment,
        reverted_from_version=reverted_from_version,
    )
    await _persist_and_announce(db, entry)
    return entry


async def _persist_and_announce(db: AsyncIOMotorDatabase, entry: PolicyAuditEntry) -> None:
    """Persist the entry, then fire its webhook and notifications; each step is best-effort."""
    try:
        await PolicyAuditRepository(db).create(entry)
    except Exception:
        logger.exception("Policy audit persistence failed (non-blocking)")
    await _dispatch_webhook(db, entry)
    try:
        await _notify_relevant_users(db, entry)
    except Exception:
        logger.exception("Policy audit notification failed (non-blocking)")


async def _dispatch_webhook(db: AsyncIOMotorDatabase, entry: PolicyAuditEntry) -> None:
    event_type = _POLICY_EVENTS[entry.policy_type][0]
    payload = {
        "event": event_type,
        "timestamp": entry.timestamp.isoformat(),
        "policy_type": entry.policy_type,
        "policy_scope": entry.policy_scope,
        "project_id": entry.project_id,
        "version": entry.version,
        "action": entry.action,
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
        context=f"policy_audit:{entry.policy_type}",
    )


async def _notify_relevant_users(db: AsyncIOMotorDatabase, entry: PolicyAuditEntry) -> None:
    """Notify users affected by a policy change; system-scope hits system:manage/analytics:global holders, project-scope hits members. Skipped for SEED."""
    if entry.action == PolicyAuditAction.SEED:
        return

    _, event_type, noun = _POLICY_EVENTS[entry.policy_type]
    message = f"{entry.actor_display_name or 'A user'} updated the policy: {entry.change_summary}"

    if entry.policy_scope == "project":
        project = await ProjectRepository(db).get_by_id(entry.project_id) if entry.project_id else None
        if project is None:
            return
        await notification_service.notify_project_members(
            project=project,
            event_type=event_type,
            subject=f"Project {project.name} {noun} changed",
            message=message,
            db=db,
        )
    else:
        await notification_service.notify_users_with_permission(
            db,
            permission=[Permissions.SYSTEM_MANAGE, Permissions.ANALYTICS_GLOBAL],
            event_type=event_type,
            subject=f"System {noun} changed",
            message=message,
        )


def compute_license_policy_change_summary(old: dict[str, Any], new: dict[str, Any]) -> str:
    """Deterministic one-line summary of the change between two resolved license policies."""
    parts = [
        f"{field}: {old[field]} -> {new[field]}"
        for field in LicensePolicySchema.model_fields
        if old[field] != new[field]
    ]
    return ", ".join(parts)[:POLICY_CHANGE_SUMMARY_MAX_LENGTH]


async def record_license_policy_change(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    old_policy: dict[str, Any],
    new_policy: dict[str, Any],
    action: PolicyAuditAction,
    actor: User | None,
    comment: str | None = None,
) -> PolicyAuditEntry | None:
    """Persist a license-policy audit entry (best-effort); returns None if no effective change. Version continues the highest audited one since the project doc has no version column."""
    if old_policy == new_policy:
        return None

    repo = PolicyAuditRepository(db)
    version = await repo.max_version(policy_scope="project", project_id=project_id, policy_type="license") + 1

    entry = PolicyAuditEntry(
        policy_type="license",
        policy_scope="project",
        project_id=project_id,
        version=version,
        action=action,
        actor_user_id=actor.id if actor else None,
        actor_display_name=(actor.username or actor.email) if actor else None,
        timestamp=datetime.now(timezone.utc),
        snapshot=new_policy,
        change_summary=compute_license_policy_change_summary(old_policy, new_policy),
        comment=comment,
    )
    await _persist_and_announce(db, entry)
    return entry
