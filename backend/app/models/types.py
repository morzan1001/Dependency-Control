"""
Shared Pydantic types and base classes for MongoDB integration.
"""

import uuid
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


def convert_objectid_to_str(v: Any) -> str:
    """Convert MongoDB ObjectId to string before Pydantic validation."""
    return str(v)


# Annotated str type that coerces MongoDB '_id' values before validation.
PyObjectId = Annotated[str, BeforeValidator(convert_objectid_to_str)]


class MongoDocument(BaseModel):
    """Base for MongoDB-backed models: a string ``_id`` field (uuid4 default) plus populate_by_name and use_enum_values config."""

    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)

    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
