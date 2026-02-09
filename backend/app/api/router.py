"""
Custom APIRouter with response_model_by_alias=False default.

This ensures API responses use field names (e.g., 'id') instead of
serialization aliases (e.g., '_id') for Pydantic models.

Models can still use serialization_alias="_id" for MongoDB serialization
with model_dump(by_alias=True), while API responses will use the field name.
"""

from typing import Any

from fastapi import APIRouter
from fastapi.routing import APIRoute


class APIRouteByFieldName(APIRoute):
    """Custom APIRoute that forces response_model_by_alias=False."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # Force to False - this ensures API responses use field names (e.g., 'id')
        # instead of serialization aliases (e.g., '_id')
        kwargs["response_model_by_alias"] = False
        super().__init__(*args, **kwargs)


class CustomAPIRouter(APIRouter):
    """
    Custom APIRouter that uses field names instead of aliases in responses.

    This router automatically sets response_model_by_alias=False for all routes,
    ensuring that Pydantic models are serialized using field names (e.g., 'id')
    rather than serialization aliases (e.g., '_id') in API responses.

    Usage:
        from app.api.router import CustomAPIRouter

        router = CustomAPIRouter()

        @router.get("/items/{item_id}")
        async def get_item(item_id: str) -> Item:
            ...
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("route_class", APIRouteByFieldName)
        super().__init__(*args, **kwargs)
