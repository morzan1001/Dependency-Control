"""Request-body size guards: a declared-size fast path plus a streaming ceiling."""

from collections.abc import Callable

from fastapi import HTTPException, Request


def _too_large(limit: int, received: str) -> HTTPException:
    return HTTPException(
        status_code=413,
        detail=f"Request body exceeds {limit} bytes ({received} bytes received).",
    )


def enforce_declared_body_size(limit: int) -> Callable[[Request], None]:
    """Route dependency rejecting an oversized declared Content-Length before any byte is read."""

    def _guard(request: Request) -> None:
        raw = request.headers.get("content-length")
        if raw is None:
            return
        try:
            size = int(raw)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header")
        if size > limit:
            raise _too_large(limit, str(size))

    return _guard


async def read_body_within_limit(request: Request, limit: int) -> bytes:
    """Read the body, aborting the moment it exceeds ``limit``.

    A chunked upload declares no Content-Length, so the ceiling has to be enforced
    while reading rather than from the header alone.
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise _too_large(limit, f"{total}+")
        chunks.append(chunk)
    return b"".join(chunks)
