"""Message text the Teams and Slack formatters share."""

from collections.abc import Mapping
from typing import Any

_ENVELOPE = ("event", "timestamp")


def policy_change_text(payload: Mapping[str, Any]) -> str:
    scope = f"project {payload['project_id']}" if payload["project_id"] else payload["policy_scope"]
    # SEED entries have no actor.
    actor = payload["actor"]["display_name"] or "A user"
    return f"{actor} updated the {scope} policy: {payload['change_summary']} (version {payload['version']})"


def event_summary(event_type: str, payload: Mapping[str, Any]) -> tuple[str, str]:
    """(subject, details) of an event without its own layout; SBOM, CBOM and compliance payloads are flat."""
    project = payload.get("project")
    name = project.get("name") if isinstance(project, Mapping) else None
    where = name or (f"project {payload['project_id']}" if payload.get("project_id") else None)
    subject = f"{event_type} for {where}" if where else event_type
    details = "\n".join(
        f"{key}: {value}"
        for key, value in payload.items()
        if key not in _ENVELOPE and value is not None and not isinstance(value, Mapping | list)
    )
    return subject, details or subject
