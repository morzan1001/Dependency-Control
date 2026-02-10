"""
Auth Helper Functions

Helper functions for authentication endpoints, extracted for better
code organization and reusability.
"""

import os
from typing import Optional

from fastapi import BackgroundTasks

from app.core import security
from app.core.config import settings
from app.models.system import SystemSettings
from app.services.notifications.email_provider import EmailProvider
from app.services.notifications.templates import (
    get_password_reset_template,
    get_system_invitation_template,
    get_verification_email_template,
)


def get_logo_path() -> str:
    """Get the absolute path to the logo file for emails."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "..", "..", "..", "static", "logo.png")


async def send_verification_email(
    background_tasks: BackgroundTasks,
    email: str,
    system_settings: Optional[SystemSettings] = None,
) -> None:
    """
    Send a verification email to the user.

    Args:
        background_tasks: FastAPI background tasks for async email sending
        email: Destination email address
        system_settings: Optional system settings for email provider configuration
    """
    if not settings.SMTP_HOST:
        return

    token = security.create_email_verification_token(email)
    link = f"{settings.FRONTEND_BASE_URL}/verify-email?token={token}"
    html_content = get_verification_email_template(link, settings.PROJECT_NAME)

    email_provider = EmailProvider()
    background_tasks.add_task(
        email_provider.send,
        destination=email,
        subject=f"Verify your email for {settings.PROJECT_NAME}",
        message=f"Please verify your email by clicking this link: {link}",
        html_message=html_content,
        logo_path=get_logo_path(),
        system_settings=system_settings,
    )


async def send_password_reset_email(
    background_tasks: BackgroundTasks,
    email: str,
    username: str,
    system_settings: Optional[SystemSettings] = None,
) -> None:
    """
    Send a password reset email to the user.

    Args:
        background_tasks: FastAPI background tasks for async email sending
        email: Destination email address
        username: Username for personalization
        system_settings: Optional system settings for email provider configuration
    """
    if not settings.SMTP_HOST:
        return

    token = security.create_password_reset_token(email)
    link = f"{settings.FRONTEND_BASE_URL}/reset-password?token={token}"
    html_content = get_password_reset_template(
        username=username,
        link=link,
        project_name=settings.PROJECT_NAME,
        valid_hours=1,
    )

    email_provider = EmailProvider()
    background_tasks.add_task(
        email_provider.send,
        destination=email,
        subject=f"Reset your password for {settings.PROJECT_NAME}",
        message=f"Reset your password by clicking this link: {link}",
        html_message=html_content,
        logo_path=get_logo_path(),
        system_settings=system_settings,
    )


async def send_system_invitation_email(
    background_tasks: BackgroundTasks,
    email: str,
    invitation_link: str,
    inviter_name: str,
    system_settings: Optional[SystemSettings] = None,
) -> None:
    """
    Send a system invitation email to a new user.

    Args:
        background_tasks: FastAPI background tasks for async email sending
        email: Destination email address
        invitation_link: Full URL for accepting the invitation
        inviter_name: Name of the user who sent the invitation
        system_settings: Optional system settings for email provider configuration
    """
    if not settings.SMTP_HOST:
        return

    html_content = get_system_invitation_template(
        invitation_link=invitation_link,
        project_name=settings.PROJECT_NAME,
        inviter_name=inviter_name,
    )

    email_provider = EmailProvider()
    background_tasks.add_task(
        email_provider.send,
        destination=email,
        subject=f"Invitation to join {settings.PROJECT_NAME}",
        message=f"You have been invited to join {settings.PROJECT_NAME}. Click here to accept: {invitation_link}",
        html_message=html_content,
        logo_path=get_logo_path(),
        system_settings=system_settings,
    )
