"""
PolicyAuditEntry — persisted audit entry for crypto-policy changes.
One document per save (including SEED), keyed on (policy_scope, project_id,
version). Snapshot is the full post-change CryptoPolicy dump.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.types import PyObjectId
from app.schemas.policy_audit import PolicyAuditAction


class PolicyAuditEntry(BaseModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    policy_type: Literal["crypto", "license"] = Field(
        default="crypto",
        description=(
            "Which policy subsystem this entry belongs to. Defaults to "
            "'crypto' for backward compatibility with entries written "
            "before the discriminator was added."
        ),
    )
    policy_scope: Literal["system", "project"] = Field(..., description="Scope of the audited policy")
    project_id: Optional[str] = Field(None, description="Project ID when scope='project', None for system policy")
    version: int = Field(..., ge=0, description="Version of the CryptoPolicy at time of save")
    action: PolicyAuditAction = Field(..., description="Action that produced this entry")
    actor_user_id: Optional[str] = Field(None, description="User who triggered the change, None for SEED")
    actor_display_name: Optional[str] = Field(
        None,
        description="Denormalised display name — preserves attribution if the user is later deleted",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the change was recorded (UTC)",
    )
    snapshot: Dict[str, Any] = Field(
        ...,
        description="Full CryptoPolicy.model_dump(by_alias=True) at save time",
    )
    change_summary: str = Field(
        ...,
        max_length=200,
        description="Human-readable one-line summary of what changed",
    )
    comment: Optional[str] = Field(None, max_length=1000, description="User-entered comment at save time")
    reverted_from_version: Optional[int] = Field(
        None,
        description="For REVERT actions: the source version being restored",
    )

    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)
