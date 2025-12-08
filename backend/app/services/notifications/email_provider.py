import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from app.core.config import settings
from app.services.notifications.base import NotificationProvider

logger = logging.getLogger(__name__)

class EmailProvider(NotificationProvider):
    async def send(self, destination: str, subject: str, message: str) -> bool:
        if not settings.SMTP_HOST:
            logger.warning("SMTP_HOST not configured. Skipping email.")
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = settings.EMAILS_FROM_EMAIL
            msg["To"] = destination
            msg["Subject"] = subject

            msg.attach(MIMEText(message, "plain"))

            # Send email
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.starttls()
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.send_message(msg)
            
            logger.info(f"Email sent to {destination}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email to {destination}: {e}")
            return False
