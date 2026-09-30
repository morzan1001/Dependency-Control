"""The one JSON body path of every upload route, read after the route's auth dependencies ran."""

import asyncio

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ValidationError


async def read_json_body[M: BaseModel](request: Request, model: type[M]) -> M:
    """Validate the streamed body; the 422 echoes no input, so no part of the upload leaves in the error."""
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
    try:
        return await asyncio.to_thread(model.model_validate_json, body)
    except ValidationError as exc:
        errors = exc.errors(include_url=False, include_input=False)
        raise RequestValidationError([{**error, "loc": ("body", *error["loc"])} for error in errors]) from None
