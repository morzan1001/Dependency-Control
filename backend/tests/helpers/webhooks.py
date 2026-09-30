"""What the webhook producers hand to delivery, captured before anything is sent."""

from collections.abc import Awaitable
from typing import Any
from unittest.mock import AsyncMock, patch

from app.services.webhooks import webhook_service


async def delivered(producer: Awaitable[None]) -> tuple[str, dict[str, Any]]:
    """The event and payload ``producer`` gives webhook delivery."""
    with patch.object(webhook_service, "trigger_webhooks", new=AsyncMock()) as deliver:
        await producer
    return deliver.await_args.kwargs["event_type"], deliver.await_args.kwargs["payload"]


async def teams_card(producer: Awaitable[None]) -> dict[str, Any]:
    """The Adaptive Card a Teams subscriber receives for what ``producer`` delivers."""
    event, payload = await delivered(producer)
    return webhook_service._format_payload("teams", event, payload)["attachments"][0]["content"]
