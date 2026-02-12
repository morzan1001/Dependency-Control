"""
Shared OpenAPI response definitions for FastAPI route decorators.

Usage:
    from app.api.v1.helpers.responses import RESP_AUTH_404

    @router.get("/items/{item_id}", responses={**RESP_AUTH_404})
    async def get_item(...): ...
"""

# Atomic response definitions
RESP_400 = {400: {"description": "Bad request"}}
RESP_401 = {401: {"description": "Not authenticated"}}
RESP_403 = {403: {"description": "Not enough permissions"}}
RESP_404 = {404: {"description": "Resource not found"}}
RESP_500 = {500: {"description": "Internal server error"}}
RESP_501 = {501: {"description": "Feature not configured"}}

# Common composites
RESP_AUTH = {**RESP_401, **RESP_403}
RESP_AUTH_404 = {**RESP_AUTH, **RESP_404}
RESP_AUTH_400 = {**RESP_AUTH, **RESP_400}
RESP_AUTH_400_404 = {**RESP_AUTH, **RESP_400, **RESP_404}
