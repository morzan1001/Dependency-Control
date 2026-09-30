import logging
from email.charset import QP, Charset
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path

import aiosmtplib

from app.core.constants import SMTP_TIMEOUT_SECONDS
from app.core.metrics import notifications_failed_total, notifications_sent_total
from app.models.system import SystemSettings
from app.services.notifications.base import NotificationProvider

logger = logging.getLogger(__name__)

_LOGO = (Path(__file__).resolve().parents[2] / "static" / "logo.png").read_bytes()

# Quoted-printable keeps every body line under the SMTP limit and leaves ASCII readable.
_UTF8_QP = Charset("utf-8")
_UTF8_QP.body_encoding = QP


class EmailProvider(NotificationProvider):
    def _build_message(
        self,
        settings: SystemSettings,
        destination: str,
        subject: str,
        message: str,
        html_message: str | None,
    ) -> MIMEMultipart:
        """Build the MIME message; HTML that shows the logo nests the body in a related part for the inline image."""
        with_logo = bool(html_message and "cid:logo" in html_message)
        msg = MIMEMultipart("related" if with_logo else "alternative")
        sender_name = " ".join((settings.emails_from_name or "").splitlines())
        msg["From"] = formataddr((sender_name, settings.emails_from_email))
        msg["To"] = destination
        msg["Subject"] = " ".join(subject.splitlines())
        msg["Date"] = formatdate()
        msg["Message-ID"] = make_msgid(domain=settings.emails_from_email.rpartition("@")[2])

        body = MIMEMultipart("alternative") if with_logo else msg
        # typeshed types _charset as str, but MIMEText documents Charset instances as accepted.
        body.attach(MIMEText(message, "plain", _UTF8_QP))  # type: ignore[arg-type]
        if html_message:
            body.attach(MIMEText(html_message, "html", _UTF8_QP))  # type: ignore[arg-type]
        if with_logo:
            msg.attach(body)
            logo = MIMEImage(_LOGO, "png")
            logo.add_header("Content-ID", "<logo>")
            logo.add_header("Content-Disposition", "inline", filename="logo.png")
            msg.attach(logo)
        return msg

    async def send(  # type: ignore[override]
        self,
        destination: str,
        subject: str,
        message: str,
        html_message: str | None = None,
        system_settings: SystemSettings | None = None,
    ) -> bool:
        if not (system_settings and system_settings.email_configured):
            logger.warning("SMTP host or sender address not configured. Skipping email.")
            return False

        try:
            msg = self._build_message(system_settings, destination, subject, message, html_message)
            async with aiosmtplib.SMTP(
                hostname=system_settings.smtp_host,
                port=system_settings.smtp_port,
                use_tls=system_settings.smtp_encryption == "ssl",
                start_tls=system_settings.smtp_encryption == "starttls",
                timeout=SMTP_TIMEOUT_SECONDS,
            ) as smtp:
                if system_settings.smtp_user and system_settings.smtp_password:
                    await smtp.login(system_settings.smtp_user, system_settings.smtp_password)
                await smtp.send_message(msg)
        except Exception as e:
            logger.exception("Failed to send email to %s: %s", destination, e)
            notifications_failed_total.labels(type="email").inc()
            return False

        logger.info("Email sent to %s", destination)
        notifications_sent_total.labels(type="email").inc()
        return True
