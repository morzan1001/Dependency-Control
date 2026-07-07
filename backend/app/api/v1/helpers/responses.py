"""Shared OpenAPI response definitions for FastAPI route decorators."""

from typing import Any, Dict

_Responses = Dict[int | str, Dict[str, Any]]

RESP_400: _Responses = {400: {"description": "Bad request"}}
RESP_401: _Responses = {401: {"description": "Not authenticated"}}
RESP_403: _Responses = {403: {"description": "Not enough permissions"}}
RESP_404: _Responses = {404: {"description": "Resource not found"}}
RESP_500: _Responses = {500: {"description": "Internal server error"}}
RESP_501: _Responses = {501: {"description": "Feature not configured"}}

RESP_400_403: _Responses = {**RESP_400, **RESP_403}
RESP_400_404: _Responses = {**RESP_400, **RESP_404}
RESP_400_401_500: _Responses = {**RESP_400, **RESP_401, **RESP_500}
RESP_400_403_404: _Responses = {**RESP_400, **RESP_403, **RESP_404}
RESP_400_500: _Responses = {**RESP_400, **RESP_500}
RESP_403_404: _Responses = {**RESP_403, **RESP_404}

RESP_AUTH: _Responses = {**RESP_401, **RESP_403}
RESP_AUTH_400: _Responses = {**RESP_AUTH, **RESP_400}
RESP_AUTH_404: _Responses = {**RESP_AUTH, **RESP_404}
RESP_AUTH_400_404: _Responses = {**RESP_AUTH, **RESP_400, **RESP_404}
RESP_AUTH_400_500: _Responses = {**RESP_AUTH, **RESP_400, **RESP_500}
RESP_AUTH_400_501: _Responses = {**RESP_AUTH, **RESP_400, **RESP_501}
RESP_AUTH_404_500: _Responses = {**RESP_AUTH, **RESP_404, **RESP_500}
RESP_AUTH_400_404_500: _Responses = {**RESP_AUTH, **RESP_400, **RESP_404, **RESP_500}
