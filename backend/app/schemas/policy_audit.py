"""Policy audit schemas — shared enums and API shapes."""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import POLICY_COMMENT_MAX_LENGTH


class PolicyAuditAction(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REVERT = "revert"
    SEED = "seed"


class PolicyRevertRequest(BaseModel):
    """Body of a policy revert. Mirrors PolicyAuditEntry's own comment limit so an over-long
    comment is a 422 here rather than a failure when the audit entry is persisted."""

    target_version: int
    comment: str | None = Field(None, max_length=POLICY_COMMENT_MAX_LENGTH)

    model_config = ConfigDict(extra="forbid")
