"""Persisted audit entry for policy changes; one document per save keyed on (policy_scope, project_id, version)."""

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import Field

from app.core.constants import POLICY_CHANGE_SUMMARY_MAX_LENGTH, POLICY_COMMENT_MAX_LENGTH
from app.models.types import MongoDocument
from app.schemas.policy_audit import PolicyAuditAction

PolicyType = Literal["crypto", "license"]


class PolicyAuditEntry(MongoDocument):
    policy_type: PolicyType = Field(default="crypto", description="Which policy subsystem this entry belongs to")
    policy_scope: Literal["system", "project"] = Field(..., description="Scope of the audited policy")
    project_id: str | None = Field(None, description="Project ID when scope='project', None for system policy")
    version: int = Field(..., ge=0, description="Version of the audited policy at time of save")
    action: PolicyAuditAction = Field(..., description="Action that produced this entry")
    actor_user_id: str | None = Field(None, description="User who triggered the change, None for SEED")
    actor_display_name: str | None = Field(
        None,
        description="Denormalised display name — preserves attribution if the user is later deleted",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the change was recorded (UTC)",
    )
    snapshot: dict[str, Any] = Field(
        ...,
        description="Full snapshot of the audited policy at save time",
    )
    change_summary: str = Field(
        ...,
        max_length=POLICY_CHANGE_SUMMARY_MAX_LENGTH,
        description="Human-readable one-line summary of what changed",
    )
    comment: str | None = Field(
        None, max_length=POLICY_COMMENT_MAX_LENGTH, description="User-entered comment at save time"
    )
    reverted_from_version: int | None = Field(
        None,
        description="For REVERT actions: the source version being restored",
    )
