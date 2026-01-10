import asyncio
import logging
import os
import smtplib
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from app.models.system import SystemSettings
from app.services.notifications.base import NotificationProvider

logger = logging.getLogger(__name__)


class EmailProvider(NotificationProvider):
    def _send_sync(
        self, smtp_host, smtp_port, smtp_user, smtp_password, encryption, msg
    ):
        timeout = 60
        try:
            if encryption == "ssl":
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=timeout) as server:
                    if smtp_user and smtp_password:
                        server.login(smtp_user, smtp_password)
                    server.send_message(msg)
            elif encryption == "starttls":
                with smtplib.SMTP(smtp_host, smtp_port, timeout=timeout) as server:
                    if smtp_user and smtp_password:
                        server.starttls()
                        server.login(smtp_user, smtp_password)
                    server.send_message(msg)
            else:  # none
                with smtplib.SMTP(smtp_host, smtp_port, timeout=timeout) as server:
                    if smtp_user and smtp_password:
                        server.login(smtp_user, smtp_password)
                    server.send_message(msg)
        except Exception as e:
            logger.error(f"SMTP send failed: {e}")
            raise

    async def send(
        self,
        destination: str,
        subject: str,
        message: str,
        html_message: Optional[str] = None,
        logo_path: Optional[str] = None,
        system_settings: Optional[SystemSettings] = None,
    ) -> bool:
        if not system_settings:
            logger.warning("System settings not provided. Skipping email.")
            return False

        # Determine configuration to use
        smtp_host = system_settings.smtp_host
        smtp_port = system_settings.smtp_port
        smtp_user = system_settings.smtp_user
        smtp_password = system_settings.smtp_password
        smtp_encryption = system_settings.smtp_encryption
        emails_from = system_settings.emails_from_email

        if not smtp_host:
            logger.warning("SMTP_HOST not configured. Skipping email.")
            return False

        try:
            if logo_path and os.path.exists(logo_path):
                msg = MIMEMultipart("related")
            else:
                msg = MIMEMultipart("alternative")

            msg["From"] = emails_from
            msg["To"] = destination
            msg["Subject"] = subject

            if logo_path and os.path.exists(logo_path):
                msg_alternative = MIMEMultipart("alternative")
                msg.attach(msg_alternative)
                msg_alternative.attach(MIMEText(message, "plain"))
                if html_message:
                    msg_alternative.attach(MIMEText(html_message, "html"))

                with open(logo_path, "rb") as f:
                    img_data = f.read()
                image = MIMEImage(img_data)
                image.add_header("Content-ID", "<logo>")
                image.add_header("Content-Disposition", "inline", filename="logo.png")
                msg.attach(image)
            else:
                msg.attach(MIMEText(message, "plain"))
                if html_message:
                    msg.attach(MIMEText(html_message, "html"))

            # Send email
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                self._send_sync,
                smtp_host,
                smtp_port,
                smtp_user,
                smtp_password,
                smtp_encryption,
                msg,
            )

            logger.info(f"Email sent to {destination}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email to {destination}: {e}")
            return False
