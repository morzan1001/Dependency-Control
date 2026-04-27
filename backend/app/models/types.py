"""
Shared Pydantic types and base classes for MongoDB integration.
"""

from typing import Annotated, Any

from bson import ObjectId
from pydantic import BaseModel, BeforeValidator, ConfigDict


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

    Centralises the two ConfigDict options that every persisted model
    needs:

    * ``populate_by_name=True`` so the document can be validated from
      either the field name (``id``) or its serialization alias
      (``_id``) — the latter being how MongoDB stores it.
    * ``use_enum_values=True`` so enum-typed fields serialize as plain
      strings (compatible with BSON, downstream JSON, and SARIF).

    Subclasses still declare their own fields and may extend
    ``model_config``; Pydantic v2 merges configs across the inheritance
    chain.
    """

    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)
