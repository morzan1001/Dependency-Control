from abc import ABC, abstractmethod


class NotificationProvider(ABC):
    @abstractmethod
    async def send(self, destination: str, subject: str, message: str) -> bool:
        """
        Send a notification.
        :param destination: The destination (email address, slack channel/user id)
        :param subject: The subject of the notification
        :param message: The body of the notification
        :return: True if successful, False otherwise
        """
        pass
