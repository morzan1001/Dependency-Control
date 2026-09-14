from urllib.parse import urlsplit

from starlette.datastructures import URL
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_LOCATION = b"location"


def _relative_location(location: str, own_origin: tuple[str, str]) -> str | None:
    """``location`` as a path, or None when it does not point back at this same origin."""
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
    """Answers a redirect back to this same origin with a relative ``Location``.

    Behind the reverse proxy the app only ever sees the in-cluster Host, so Starlette's
    slash redirect would hand the client an absolute URL naming the internal service --
    which discloses it and resolves for nobody outside the cluster. RFC 7231 section 7.1.2
    allows a relative reference, and the client resolves it against the host it used.

    A redirect to a *different* origin (the OIDC provider, the frontend) is left absolute:
    only a self-referential one can be expressed relatively.
    """

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
