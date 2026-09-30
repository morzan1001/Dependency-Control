"""DNS-pinned transport that keeps webhook delivery on the address that was vetted."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any

import httpx

from app.core.constants import WEBHOOK_LOOPBACK_HOSTS
from app.core.http_utils import SSL_CONTEXT
from app.schemas.webhook import is_blocked_ip, validate_webhook_url


class WebhookTargetBlocked(ValueError):
    """Carries the resolved address in ``detail`` for the server log; the public message stays fixed."""

    def __init__(self, detail: str) -> None:
        super().__init__("Target is not an allowed webhook destination")
        self.detail = detail


async def _resolve_and_vet(host: str) -> str | None:
    """Return the first vetted IP for ``host``; None only for loopback hosts, which are exempt from pinning."""
    if host in WEBHOOK_LOOPBACK_HOSTS:
        return None
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise httpx.ConnectError(f"Could not resolve webhook host '{host}': {exc}") from exc

    safe_ip: str | None = None
    for info in infos:
        addr = info[4][0]
        if not isinstance(addr, str):
            continue
        try:
            resolved = ipaddress.ip_address(addr.split("%", 1)[0])
        except ValueError:
            continue
        if is_blocked_ip(resolved):
            raise WebhookTargetBlocked(f"host '{host}' resolves to blocked address {resolved}")
        if safe_ip is None:
            safe_ip = str(resolved)
    if safe_ip is None:
        raise WebhookTargetBlocked(f"host '{host}' resolved to no usable IP address")
    return safe_ip


class _PinnedIPTransport(httpx.AsyncHTTPTransport):
    """Sends every request for ``hostname`` to the vetted ``ip``; Host header and TLS SNI keep the hostname."""

    def __init__(self, hostname: str, ip: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._hostname = hostname
        self._ip = ip

    def _pin(self, request: httpx.Request) -> httpx.Request:
        resolved = ipaddress.ip_address(self._ip)
        if is_blocked_ip(resolved):
            raise WebhookTargetBlocked(f"pinned address {resolved} is in a blocked range")
        request.extensions = {**request.extensions, "sni_hostname": self._hostname}
        request.url = request.url.copy_with(host=self._ip)
        return request

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.raw_host.decode("ascii") != self._hostname:
            raise WebhookTargetBlocked(f"request for '{request.url.host}' on a transport pinned to '{self._hostname}'")
        return await super().handle_async_request(self._pin(request))


async def build_pinned_transport(url: str) -> httpx.AsyncHTTPTransport:
    """Transport pinned to the vetted IP of ``url``'s host, so a rebinding DNS answer cannot redirect delivery."""
    try:
        # A stored URL predates today's rules, which WebhookCreate/WebhookUpdate enforce only inbound.
        validate_webhook_url(url)
    except ValueError as exc:
        raise WebhookTargetBlocked(str(exc)) from exc
    host = httpx.URL(url).raw_host.decode("ascii")
    safe_ip = await _resolve_and_vet(host)
    if safe_ip is None:
        return httpx.AsyncHTTPTransport(verify=SSL_CONTEXT)
    return _PinnedIPTransport(host, safe_ip, verify=SSL_CONTEXT)
