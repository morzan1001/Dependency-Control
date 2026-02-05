import logging
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

logger = logging.getLogger(__name__)


class User(BaseModel):
    # Use validation_alias so _id is accepted from MongoDB, but 'id' is used in JSON output
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), validation_alias="_id")
    username: str
    email: EmailStr
    hashed_password: Optional[str] = None
    is_active: bool = True
    is_verified: bool = False
    auth_provider: str = "local"  # "local", "gitlab", "google", etc.
    permissions: list[str] = []  # e.g. "project:create", "user:read_all"
    last_logout_at: Optional[datetime] = None

    # 2FA settings
    totp_secret: Optional[str] = None
    totp_enabled: bool = False

    # Notification settings
    slack_username: Optional[str] = None
    mattermost_username: Optional[str] = None
    notification_preferences: Optional[dict[str, list[str]]] = Field(
        default_factory=lambda: {
            "analysis_completed": ["email"],
            "vulnerability_found": ["email", "slack"],
        }
    )

    @field_validator("id", mode="before")
    @classmethod
    def convert_objectid(cls, v):
        if not isinstance(v, str):
            return str(v)
        return v

    @field_validator("notification_preferences")
    @classmethod
    def validate_notification_preferences(cls, v):
        """
        Validate notification preferences to prevent typos and invalid configurations.
        """
        if v is None:
            return {
                "analysis_completed": ["email"],
                "vulnerability_found": ["email", "slack"],
            }

        # Valid event types
        valid_events = {"analysis_completed", "vulnerability_found"}

        # Valid channels
        valid_channels = {"email", "slack", "mattermost"}

        # Validate structure
        if not isinstance(v, dict):
            logger.warning(
                f"Invalid notification_preferences type: {type(v)}. Using defaults."
            )
            return {
                "analysis_completed": ["email"],
                "vulnerability_found": ["email", "slack"],
            }

        validated = {}
        for event, channels in v.items():
            # Check if event is valid
            if event not in valid_events:
                logger.warning(
                    f"Unknown notification event type '{event}' (valid: {valid_events}). Skipping."
                )
                continue

            # Validate channels
            if not isinstance(channels, list):
                logger.warning(
                    f"Invalid channels for event '{event}': expected list, got {type(channels)}"
                )
                continue

            valid_event_channels = [c for c in channels if c in valid_channels]
            if len(valid_event_channels) != len(channels):
                invalid = set(channels) - valid_channels
                logger.warning(
                    f"Invalid channels for event '{event}': {invalid} (valid: {valid_channels})"
                )

            if valid_event_channels:
                validated[event] = valid_event_channels

        # Ensure at least default events exist
        if "analysis_completed" not in validated:
            validated["analysis_completed"] = ["email"]
        if "vulnerability_found" not in validated:
            validated["vulnerability_found"] = ["email"]

        return validated

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
