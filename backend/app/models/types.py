"""
Shared Pydantic types for MongoDB integration.
"""

from typing import Annotated, Any

from bson import ObjectId
from pydantic import BeforeValidator


def convert_objectid_to_str(v: Any) -> str:
    """Convert MongoDB ObjectId to string before Pydantic validation."""
    if isinstance(v, ObjectId):
        return str(v)
    return v


# Annotated type that converts MongoDB ObjectId to str before validation.
# Use this for 'id' fields that map to MongoDB's '_id' field.
PyObjectId = Annotated[str, BeforeValidator(convert_objectid_to_str)]
