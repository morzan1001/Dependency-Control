from typing import Any

from fastapi import APIRouter
from fastapi.routing import APIRoute


class APIRouteByFieldName(APIRoute):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["response_model_by_alias"] = False
        super().__init__(*args, **kwargs)


class CustomAPIRouter(APIRouter):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("route_class", APIRouteByFieldName)
        super().__init__(*args, **kwargs)
