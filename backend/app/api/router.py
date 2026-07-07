"""APIRouter defaulting response_model_by_alias=False so responses use field names, not aliases."""

from typing import Any

from fastapi import APIRouter
from fastapi.routing import APIRoute


class APIRouteByFieldName(APIRoute):
    """Custom APIRoute that forces response_model_by_alias=False."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["response_model_by_alias"] = False
        super().__init__(*args, **kwargs)


class CustomAPIRouter(APIRouter):
    """APIRouter whose routes serialize responses by field name instead of alias."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("route_class", APIRouteByFieldName)
        super().__init__(*args, **kwargs)
