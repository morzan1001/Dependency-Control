"""Webhook API schemas and the network-free validators they apply."""

import ipaddress
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator

from app.core.config import settings
from app.core.constants import (
    WEBHOOK_ACCEPTED_EVENT_NAMES,
    WEBHOOK_BLOCKED_HOSTNAMES,
    WEBHOOK_EVENT_ALIASES,
    WEBHOOK_EVENT_SCAN_COMPLETED,
    WEBHOOK_LOOPBACK_HOSTS,
    WEBHOOK_VALID_EVENTS,
    WebhookType,
)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_HEADER_VALUE = re.compile(r"[\x20-\x7e\xa0-\xff]*")
_RESERVED_HEADER_NAMES = frozenset(
    {"content-type", "content-length", "transfer-encoding", "host", "user-agent", "accept-encoding"}
)


def is_blocked_ip(ip: IPAddress) -> bool:
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def _parse_ip(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def validate_webhook_url(url: str) -> str:
    """Reject empty, non-http(s), userinfo-bypass, and private/metadata targets."""
    if not url:
        raise ValueError("URL cannot be empty")

    try:
        parsed = httpx.URL(url)
    except httpx.InvalidURL as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc

    scheme = parsed.scheme
    if scheme not in ("http", "https"):
        raise ValueError("Webhook URL scheme must be http or https")

    # The A-label is what delivery resolves, so lookalike spellings of loopback or metadata names are caught here.
    host = parsed.raw_host.decode("ascii")
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
    if ip is not None and not is_loopback_host and is_blocked_ip(ip):
        raise ValueError(f"Webhook host '{host}' is in a private, reserved, or link-local range")

    return url


def validate_webhook_events(events: list[str]) -> list[str]:
    if not events:
        raise ValueError("At least one event type is required")

    invalid_events = [e for e in events if e not in WEBHOOK_ACCEPTED_EVENT_NAMES]
    if invalid_events:
        raise ValueError(f"Invalid event types: {invalid_events}. Valid events: {WEBHOOK_VALID_EVENTS}")
    return list(dict.fromkeys(WEBHOOK_EVENT_ALIASES.get(e, e) for e in events))


def validate_webhook_event_type(event_type: str) -> str:
    if event_type not in WEBHOOK_ACCEPTED_EVENT_NAMES:
        raise ValueError(f"Invalid event type: {event_type}. Valid events: {WEBHOOK_VALID_EVENTS}")
    return WEBHOOK_EVENT_ALIASES.get(event_type, event_type)


def validate_webhook_headers(headers: dict[str, str] | None) -> dict[str, str] | None:
    """Delivery sends custom headers as latin-1 beside its own protocol headers, which they may not shadow."""
    for name, value in (headers or {}).items():
        lowered = name.lower()
        if not _HEADER_NAME.fullmatch(name) or lowered in _RESERVED_HEADER_NAMES or lowered.startswith("x-webhook-"):
            raise ValueError(f"Header name '{name}' is not allowed")
        if not _HEADER_VALUE.fullmatch(value) or value != value.strip(" "):
            raise ValueError(f"Header '{name}' must be printable latin-1 text without surrounding spaces")
    return headers


def detect_webhook_type(url: str) -> WebhookType:
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


class WebhookCreate(BaseModel):
    """Schema for creating a new webhook."""

    url: str
    events: list[str]
    secret: str | None = None
    headers: dict[str, str] | None = None
    webhook_type: WebhookType | None = None

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: list[str]) -> list[str]:
        """Validate that all events are valid event types."""
        return validate_webhook_events(v)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        """Validate that URL is HTTPS (except for localhost in development)."""
        return validate_webhook_url(v)

    @field_validator("headers")
    @classmethod
    def _validate_headers(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        return validate_webhook_headers(v)


class WebhookUpdate(BaseModel):
    """Only the sent fields change; a null clears secret or headers and is refused for the rest."""

    url: str | None = None
    events: list[str] | None = None
    is_active: bool | None = None
    secret: str | None = None
    headers: dict[str, str] | None = None
    webhook_type: WebhookType | None = None

    @field_validator("url", "events", "is_active", "webhook_type")
    @classmethod
    def _reject_null(cls, v: Any, info: ValidationInfo) -> Any:
        if v is None:
            raise ValueError(f"{info.field_name} cannot be null")
        return v

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: list[str]) -> list[str]:
        return validate_webhook_events(v)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        return validate_webhook_url(v)

    @field_validator("headers")
    @classmethod
    def _validate_headers(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        return validate_webhook_headers(v)


class WebhookResponse(BaseModel):
    """Schema for webhook response (excludes secret for security)."""

    id: str
    project_id: str | None = None
    team_id: str | None = None
    url: str
    events: list[str]
    headers: dict[str, str] | None = None
    is_active: bool
    created_at: datetime
    last_triggered_at: datetime | None = None
    last_failure_at: datetime | None = None
    webhook_type: WebhookType

    model_config = ConfigDict(from_attributes=True)


class WebhookTestRequest(BaseModel):
    """Schema for testing a webhook."""

    event_type: str = WEBHOOK_EVENT_SCAN_COMPLETED

    @field_validator("event_type")
    @classmethod
    def _validate_event_type(cls, v: str) -> str:
        """Validate that the event type is valid."""
        return validate_webhook_event_type(v)


class WebhookTestResponse(BaseModel):
    """Schema for webhook test response."""

    success: bool
    status_code: int | None = None
    error: str | None = None
    response_time_ms: float | None = None
