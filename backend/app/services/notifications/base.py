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
        """Send a notification; return True on success."""
        pass
