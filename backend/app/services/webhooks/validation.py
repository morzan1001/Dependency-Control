"""Shared validation for webhook URLs and events."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import List, Optional, Union
from urllib.parse import urlparse

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
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
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
        raise ValueError(
            f"Webhook host '{host}' is in a private, reserved, or link-local range"
        )

    return url


def validate_webhook_url_optional(url: Optional[str]) -> Optional[str]:
    if url is None:
        return None
    return validate_webhook_url(url)


async def assert_safe_webhook_target(url: str) -> None:
    """Resolve the host and reject delivery if any IP is in a blocked range.

    Defense in depth against DNS rebinding: a hostname that passed static
    validation may still resolve to an internal IP at delivery time.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host or host in WEBHOOK_LOOPBACK_HOSTS:
        return

    ip_literal = _parse_ip(host)
    if ip_literal is not None:
        if _is_blocked_ip(ip_literal):
            raise ValueError(
                f"Refusing webhook delivery: host '{host}' is in a blocked IP range"
            )
        return

    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve webhook host '{host}': {exc}") from exc

    for info in infos:
        ip_str = info[4][0].split("%", 1)[0]
        try:
            resolved = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked_ip(resolved):
            raise ValueError(
                f"Refusing webhook delivery: host '{host}' resolves to "
                f"blocked address {resolved}"
            )


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
