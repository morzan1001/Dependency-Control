import logging
import os
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from typing import Optional

from app.core.constants import SMTP_TIMEOUT_SECONDS
from app.models.system import SystemSettings
from app.services.notifications.base import NotificationProvider

logger = logging.getLogger(__name__)

# Import metrics for notification tracking
try:
    from app.core.metrics import notifications_failed_total, notifications_sent_total
except ImportError:
    notifications_sent_total = None
    notifications_failed_total = None

# Import aiosmtplib for async SMTP (required dependency)
try:
    import aiosmtplib
except ImportError as e:
    logger.error("aiosmtplib is required for async SMTP. Install with: poetry install")
    raise ImportError("aiosmtplib is required") from e


class EmailProvider(NotificationProvider):
    async def _send_async(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_user: Optional[str],
        smtp_password: Optional[str],
        encryption: str,
        msg: MIMEMultipart,
    ) -> None:
        """
        Send email using async SMTP (aiosmtplib).
        Does not block the event loop.
        """
        timeout = SMTP_TIMEOUT_SECONDS

        try:
            # Configure SMTP client based on encryption
            if encryption == "ssl":
                smtp = aiosmtplib.SMTP(
                    hostname=smtp_host,
                    port=smtp_port,
                    use_tls=True,
                    timeout=timeout,
                )
            else:
                smtp = aiosmtplib.SMTP(
                    hostname=smtp_host,
                    port=smtp_port,
                    use_tls=False,
                    timeout=timeout,
                )

            async with smtp:
                if encryption == "starttls":
                    await smtp.starttls()

                # Login if credentials provided
                if smtp_user and smtp_password:
                    await smtp.login(smtp_user, smtp_password)

                # Send message
                await smtp.send_message(msg)

        except Exception as e:
            logger.error(f"Async SMTP send failed: {e}")
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
        emails_from_email = system_settings.emails_from_email
        emails_from_name = system_settings.emails_from_name

        if not smtp_host:
            logger.warning("SMTP_HOST not configured. Skipping email.")
            return False

        if not emails_from_email:
            logger.warning("EMAILS_FROM not configured. Skipping email.")
            return False

        if emails_from_name:
            sanitized_name = emails_from_name.replace("\r", "").replace("\n", "")
            emails_from = formataddr((sanitized_name, emails_from_email))
        else:
            emails_from = emails_from_email

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

            # Send email asynchronously using aiosmtplib
            await self._send_async(
                smtp_host,
                smtp_port,
                smtp_user,
                smtp_password,
                smtp_encryption,
                msg,
            )

            logger.info(f"Email sent to {destination}")
            if notifications_sent_total:
                notifications_sent_total.labels(type="email").inc()
            return True
        except Exception as e:
            logger.error(f"Failed to send email to {destination}: {e}")
            if notifications_failed_total:
                notifications_failed_total.labels(type="email").inc()
            return False
