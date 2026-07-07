"""Shared validation for webhook URLs and events."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any, List, Literal, Optional, Union
from urllib.parse import urlparse

import httpx

from app.core.config import settings
from app.core.constants import (
    WEBHOOK_ACCEPTED_EVENT_NAMES,
    WEBHOOK_BLOCKED_HOSTNAMES,
    WEBHOOK_LOOPBACK_HOSTS,
    WEBHOOK_VALID_EVENTS,
)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def _is_blocked_ip(ip: IPAddress) -> bool:
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def _parse_ip(host: str) -> Optional[IPAddress]:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def validate_webhook_url(url: str) -> str:
    """Reject empty, non-http(s), userinfo-bypass, and private/metadata targets."""
    if not url:
        raise ValueError("URL cannot be empty")

    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError("Webhook URL scheme must be http or https")

    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("Webhook URL must have a hostname")

    if host in WEBHOOK_BLOCKED_HOSTNAMES:
        raise ValueError(f"Webhook host '{host}' is not an allowed target")

    is_loopback_host = host in WEBHOOK_LOOPBACK_HOSTS

    if is_loopback_host and not settings.WEBHOOK_ALLOW_LOCALHOST:
        raise ValueError("Localhost webhook targets are disabled in this environment")

    if scheme == "http" and not is_loopback_host:
        raise ValueError("Plain HTTP is only allowed for loopback hosts")

    ip = _parse_ip(host)
    if ip is not None and not is_loopback_host and _is_blocked_ip(ip):
        raise ValueError(f"Webhook host '{host}' is in a private, reserved, or link-local range")

    return url


def validate_webhook_url_optional(url: Optional[str]) -> Optional[str]:
    if url is None:
        return None
    return validate_webhook_url(url)


async def _resolve_and_vet(url: str) -> Optional[str]:
    """Resolve the host once, reject if any resolved IP is in a blocked range.

    Returns the first vetted-safe IP literal to connect to, or ``None`` only when
    the target genuinely does not need pinning (empty or loopback host). Raises
    ``ValueError`` if any resolved address is in a blocked range, if the host
    cannot be resolved, or if a non-loopback host resolves to entries that yield
    no usable IP address (fail-closed: never silently fall back to an unpinned,
    re-resolving connection).
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host or host in WEBHOOK_LOOPBACK_HOSTS:
        return None

    ip_literal = _parse_ip(host)
    if ip_literal is not None:
        if _is_blocked_ip(ip_literal):
            raise ValueError(f"Refusing webhook delivery: host '{host}' is in a blocked IP range")
        return str(ip_literal)

    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve webhook host '{host}': {exc}") from exc

    safe_ip: Optional[str] = None
    for info in infos:
        ip_str = info[4][0].split("%", 1)[0]
        try:
            resolved = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked_ip(resolved):
            raise ValueError(f"Refusing webhook delivery: host '{host}' resolves to blocked address {resolved}")
        if safe_ip is None:
            safe_ip = str(resolved)
    if safe_ip is None:
        # getaddrinfo returned entries but none parsed as a usable IP. Fail
        # closed instead of returning None (which build_pinned_transport treats
        # as "no pinning needed" and would connect via an unpinned transport
        # that re-resolves the hostname, reopening the DNS-rebinding window).
        raise ValueError(f"Refusing webhook delivery: host '{host}' resolved to no usable IP address")
    return safe_ip


async def assert_safe_webhook_target(url: str) -> Optional[str]:
    """Resolve the host, reject delivery if any IP is blocked, and return the
    vetted-safe IP the delivery connection should be pinned to.

    IMPORTANT: knowing the safe IP is not, on its own, defense against DNS
    rebinding. Because httpx re-resolves the hostname independently at connect
    time, the delivery client MUST pin the connection to the returned address
    (use :func:`build_pinned_transport`) — otherwise an attacker controlling
    authoritative DNS with a short TTL can return a public IP here and an
    internal/metadata IP at connect time (TOCTOU).
    """
    return await _resolve_and_vet(url)


class _PinnedIPTransport(httpx.AsyncHTTPTransport):
    """httpx transport that forces every connection for ``hostname`` to the
    pre-vetted ``ip``, closing the DNS-rebinding window.

    The original hostname is preserved for the ``Host`` header (already set on
    the request at build time) and for TLS SNI / certificate validation via the
    ``sni_hostname`` request extension, so only the TCP connect target changes.
    """

    def __init__(self, hostname: str, ip: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._hostname = hostname.lower()
        self._ip = ip

    def _pin(self, request: httpx.Request) -> httpx.Request:
        resolved = ipaddress.ip_address(self._ip)
        if _is_blocked_ip(resolved):
            raise ValueError(f"Refusing webhook delivery: pinned address {resolved} is in a blocked range")
        request.extensions = {**request.extensions, "sni_hostname": self._hostname}
        request.url = request.url.copy_with(host=self._ip)
        return request

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if (request.url.host or "").lower() == self._hostname:
            request = self._pin(request)
        return await super().handle_async_request(request)


async def build_pinned_transport(url: str, **transport_kwargs: Any) -> httpx.AsyncHTTPTransport:
    """Resolve and vet ``url``'s host once, then return an httpx transport that
    pins the delivery connection to the vetted IP (defeating DNS rebinding).

    Raises ``ValueError`` if the host resolves to a blocked address. For
    loopback/unpinnable targets a plain transport is returned. Adopt via
    ``InstrumentedAsyncClient(..., transport=await build_pinned_transport(url))``
    in place of a bare ``assert_safe_webhook_target`` check.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    safe_ip = await _resolve_and_vet(url)
    if safe_ip is None:
        # Only reached for empty/loopback hosts, which _resolve_and_vet has
        # already deemed pin-exempt. A non-loopback host that resolves to no
        # usable IP now raises inside _resolve_and_vet (fail-closed) rather than
        # reaching this unpinned fallback.
        return httpx.AsyncHTTPTransport(**transport_kwargs)
    return _PinnedIPTransport(host, safe_ip, **transport_kwargs)


def validate_webhook_events(events: List[str], allow_empty: bool = False) -> List[str]:
    if not allow_empty and not events:
        raise ValueError("At least one event type is required")

    invalid_events = [e for e in events if e not in WEBHOOK_ACCEPTED_EVENT_NAMES]
    if invalid_events:
        raise ValueError(f"Invalid event types: {invalid_events}. Valid events: {WEBHOOK_VALID_EVENTS}")
    return events


def validate_webhook_events_optional(
    events: Optional[List[str]],
) -> Optional[List[str]]:
    if events is None:
        return None
    return validate_webhook_events(events, allow_empty=False)


def validate_webhook_event_type(event_type: str) -> str:
    if event_type not in WEBHOOK_ACCEPTED_EVENT_NAMES:
        raise ValueError(f"Invalid event type: {event_type}. Valid events: {WEBHOOK_VALID_EVENTS}")
    return event_type


def detect_webhook_type(url: str) -> Literal["generic", "teams"]:
    """Returns "teams" for *.webhook.office.com, *.logic.azure.com/workflows/, and *.api.powerplatform.com/workflows/."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""

    if hostname == "webhook.office.com" or hostname.endswith(".webhook.office.com"):
        return "teams"
    if (hostname == "logic.azure.com" or hostname.endswith(".logic.azure.com")) and "/workflows/" in path:
        return "teams"
    if (hostname == "api.powerplatform.com" or hostname.endswith(".api.powerplatform.com")) and "/workflows/" in path:
        return "teams"
    return "generic"
