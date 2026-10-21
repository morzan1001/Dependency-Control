from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import POLICY_COMMENT_MAX_LENGTH


class PolicyRevertRequest(BaseModel):
    """Shares PolicyAuditEntry's comment limit, so an over-long comment is a 422 rather than a failed audit write."""

    target_version: int
    comment: str | None = Field(None, max_length=POLICY_COMMENT_MAX_LENGTH)

    model_config = ConfigDict(extra="forbid")
