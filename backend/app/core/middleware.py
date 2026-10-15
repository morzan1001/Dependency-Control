from urllib.parse import urlsplit

from starlette.datastructures import URL
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_LOCATION = b"location"


def _relative_location(location: str, own_origin: tuple[str, str]) -> str | None:
    parsed = urlsplit(location)
    if not parsed.netloc or (parsed.scheme, parsed.netloc) != own_origin:
        return None
    relative = parsed.path or "/"
    if parsed.query:
        relative = f"{relative}?{parsed.query}"
    if parsed.fragment:
        relative = f"{relative}#{parsed.fragment}"
    return relative


def _rewrite_header(name: bytes, value: bytes, own_origin: tuple[str, str]) -> tuple[bytes, bytes]:
    if name.lower() != _LOCATION:
        return name, value
    # latin-1 is the header codec; a Location is ASCII in practice and round-trips either way.
    relative = _relative_location(value.decode("latin-1"), own_origin)
    return name, value if relative is None else relative.encode("latin-1")


class RelativeLocationMiddleware:
    """Behind the proxy an absolute redirect would name the in-cluster Host; RFC 7231 7.1.2 allows a relative one."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        own = URL(scope=scope)
        own_origin = (own.scheme, own.netloc)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [_rewrite_header(name, value, own_origin) for name, value in message["headers"]]
            await send(message)

        await self.app(scope, receive, send_wrapper)
