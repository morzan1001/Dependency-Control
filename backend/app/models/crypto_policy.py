"""
CryptoPolicy MongoDB model.

One document per scope. scope='system' has exactly one document (the seed).
scope='project' has one document per project that has an override.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.types import PyObjectId
from app.schemas.crypto_policy import CryptoRule


class CryptoPolicy(BaseModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
        description="Unique identifier for the policy document",
    )
    scope: Literal["system", "project"] = Field(..., description="Policy scope: 'system' for the seed policy, 'project' for per-project overrides")
    project_id: Optional[str] = Field(None, description="Project ID when scope='project'; None for system policy")
    rules: List[CryptoRule] = Field(default_factory=list, description="Rules carried by this policy document")
    version: int = Field(1, description="Monotonically increasing version for cache invalidation and audit trail")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Last write timestamp (UTC)")
    updated_by: Optional[str] = Field(None, description="User ID of the last editor")

    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)
