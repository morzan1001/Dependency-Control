from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from app.models.system import SystemSettings


class NotificationProvider(ABC):
    @abstractmethod
    async def send(
        self,
        destination: str,
        subject: str,
        message: str,
        system_settings: Optional["SystemSettings"] = None,
        **kwargs: Any,
    ) -> bool:
        """
        Send a notification.

        Args:
            destination: The destination (email address, slack channel/user id)
            subject: The subject of the notification
            message: The body of the notification
            system_settings: System configuration for the provider
            **kwargs: Additional provider-specific arguments (e.g., html_message for email)

        Returns:
            True if successful, False otherwise
        """
        pass
