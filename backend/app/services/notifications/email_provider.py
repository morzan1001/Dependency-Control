import asyncio
import logging
import os
from pathlib import Path
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from typing import Optional

from prometheus_client import Counter

from app.core.constants import SMTP_TIMEOUT_SECONDS
from app.models.system import SystemSettings
from app.services.notifications.base import NotificationProvider

logger = logging.getLogger(__name__)

notifications_sent_total: Optional[Counter] = None
notifications_failed_total: Optional[Counter] = None

try:
    from app.core.metrics import notifications_failed_total, notifications_sent_total
except ImportError:
    pass

try:
    import aiosmtplib
except ImportError as e:
    logger.exception("aiosmtplib is required for async SMTP. Install with: poetry install")
    raise ImportError("aiosmtplib is required") from e


class EmailProvider(NotificationProvider):
    def _build_message(
        self,
        emails_from: str,
        destination: str,
        subject: str,
        message: str,
        html_message: Optional[str],
        logo_path: Optional[str],
    ) -> MIMEMultipart:
        """Build the MIME message, attaching logo if available."""
        has_logo = bool(logo_path and os.path.exists(logo_path))

        if has_logo:
            msg = MIMEMultipart("related")
        else:
            msg = MIMEMultipart("alternative")

        msg["From"] = emails_from
        msg["To"] = destination
        msg["Subject"] = subject

        if has_logo:
            msg_alternative = MIMEMultipart("alternative")
            msg.attach(msg_alternative)
            msg_alternative.attach(MIMEText(message, "plain"))
            if html_message:
                msg_alternative.attach(MIMEText(html_message, "html"))
        else:
            msg.attach(MIMEText(message, "plain"))
            if html_message:
                msg.attach(MIMEText(html_message, "html"))

        return msg

    async def _attach_logo(self, msg: MIMEMultipart, logo_path: str) -> None:
        img_data = await asyncio.to_thread(Path(logo_path).read_bytes)
        image = MIMEImage(img_data)
        image.add_header("Content-ID", "<logo>")
        image.add_header("Content-Disposition", "inline", filename="logo.png")
        msg.attach(image)

    async def _send_async(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_user: Optional[str],
        smtp_password: Optional[str],
        encryption: str,
        msg: MIMEMultipart,
    ) -> None:
        """Send email via async SMTP without blocking the event loop."""
        timeout = SMTP_TIMEOUT_SECONDS

        try:
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

                if smtp_user and smtp_password:
                    await smtp.login(smtp_user, smtp_password)

                await smtp.send_message(msg)

        except Exception as e:
            logger.exception("Async SMTP send failed: %s", e)
            raise

    async def send(  # type: ignore[override]
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
            msg = self._build_message(
                emails_from,
                destination,
                subject,
                message,
                html_message,
                logo_path,
            )

            if logo_path and os.path.exists(logo_path):
                await self._attach_logo(msg, logo_path)

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
            logger.exception("Failed to send email to %s: %s", destination, e)
            if notifications_failed_total:
                notifications_failed_total.labels(type="email").inc()
            return False
