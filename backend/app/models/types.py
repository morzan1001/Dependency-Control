from typing import Annotated, Any

from bson import ObjectId
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


def convert_objectid_to_str(v: Any) -> str:
    return str(v)


PyObjectId = Annotated[str, BeforeValidator(convert_objectid_to_str)]


class MongoDocument(BaseModel):
    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)

    # Time-ordered, so inserts append to the _id index instead of scattering across it.
    id: PyObjectId = Field(
        default_factory=lambda: str(ObjectId()),
        validation_alias="_id",
        serialization_alias="_id",
    )
