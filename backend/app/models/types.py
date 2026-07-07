"""
Shared Pydantic types and base classes for MongoDB integration.
"""

import uuid
from typing import Annotated, Any

from bson import ObjectId
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


def convert_objectid_to_str(v: Any) -> str:
    """Convert MongoDB ObjectId to string before Pydantic validation."""
    if isinstance(v, ObjectId):
        return str(v)
    return str(v)


# Annotated type that converts MongoDB ObjectId to str before validation.
# Use this for 'id' fields that map to MongoDB's '_id' field.
PyObjectId = Annotated[str, BeforeValidator(convert_objectid_to_str)]


class MongoDocument(BaseModel):
    """Base for Pydantic models that round-trip through MongoDB.

    Centralises the string ``_id`` field and the two ConfigDict options
    that every persisted model needs:

    * an ``id`` field aliased to Mongo's ``_id`` for both validation and
      serialization, defaulting to a fresh ``uuid4`` string. Subclasses
      inherit it, so they no longer repeat the identical declaration.
    * ``populate_by_name=True`` so the document can be validated from
      either the field name (``id``) or its serialization alias
      (``_id``) — the latter being how MongoDB stores it.
    * ``use_enum_values=True`` so enum-typed fields serialize as plain
      strings (compatible with BSON, downstream JSON, and SARIF).

    Subclasses still declare their own fields and may extend
    ``model_config``; Pydantic v2 merges configs across the inheritance
    chain. A subclass may also override ``id`` (e.g. to add a
    ``description``) — the override wins over this base declaration.
    """

    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)

    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
