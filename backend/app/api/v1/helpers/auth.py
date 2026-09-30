"""Account mails and the email precondition of the endpoints that send them."""

from fastapi import BackgroundTasks, HTTPException, status

from app.core import security
from app.core.config import settings
from app.models.system import SystemSettings
from app.services.notifications import templates
from app.services.notifications.email_provider import EmailProvider

_MSG_EMAIL_NOT_CONFIGURED = "Email server not configured"
_CONTACT_ADMIN = "please contact your administrator immediately."


def require_email_configured(system_settings: SystemSettings) -> None:
    if not system_settings.email_configured:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=_MSG_EMAIL_NOT_CONFIGURED)


def _queue_email(
    background_tasks: BackgroundTasks,
    system_settings: SystemSettings,
    destination: str,
    subject: str,
    message: str,
    html_message: str,
) -> bool:
    """Queue the mail when the stored settings can deliver it; report whether it was queued."""
    if not system_settings.email_configured:
        return False
    background_tasks.add_task(
        EmailProvider().send,
        destination=destination,
        subject=subject,
        message=message,
        html_message=html_message,
        system_settings=system_settings,
    )
    return True


def send_verification_email(background_tasks: BackgroundTasks, email: str, system_settings: SystemSettings) -> bool:
    link = f"{settings.FRONTEND_BASE_URL}/verify-email?token={security.create_email_verification_token(email)}"
    return _queue_email(
        background_tasks,
        system_settings,
        email,
        f"Verify your email for {settings.PROJECT_NAME}",
        f"Please verify your email by clicking this link: {link}",
        templates.get_verification_email_template(link),
    )


def send_email_change_email(
    background_tasks: BackgroundTasks, user_id: str, new_email: str, system_settings: SystemSettings
) -> bool:
    token = security.create_email_change_token(user_id, new_email)
    link = f"{settings.FRONTEND_BASE_URL}/confirm-email?token={token}"
    return _queue_email(
        background_tasks,
        system_settings,
        new_email,
        f"Confirm your new email for {settings.PROJECT_NAME}",
        f"Confirm your new email address by clicking this link: {link}",
        templates.get_email_change_template(link),
    )


def send_password_reset_email(
    background_tasks: BackgroundTasks, email: str, username: str, system_settings: SystemSettings
) -> bool:
    link = f"{settings.FRONTEND_BASE_URL}/reset-password?token={security.create_password_reset_token(email)}"
    return _queue_email(
        background_tasks,
        system_settings,
        email,
        f"Reset your password for {settings.PROJECT_NAME}",
        f"Reset your password by clicking this link: {link}",
        templates.get_password_reset_template(username=username, link=link),
    )


def send_system_invitation_email(
    background_tasks: BackgroundTasks,
    email: str,
    invitation_link: str,
    inviter_name: str,
    system_settings: SystemSettings,
) -> bool:
    return _queue_email(
        background_tasks,
        system_settings,
        email,
        f"Invitation to join {settings.PROJECT_NAME}",
        f"You have been invited to join {settings.PROJECT_NAME}. Click here to accept: {invitation_link}",
        templates.get_system_invitation_template(invitation_link=invitation_link, inviter_name=inviter_name),
    )


def send_project_member_added_email(
    background_tasks: BackgroundTasks,
    email: str,
    project_name: str,
    project_id: str,
    inviter_name: str,
    role: str,
    system_settings: SystemSettings,
) -> bool:
    return _queue_email(
        background_tasks,
        system_settings,
        email,
        f"You've been added to project '{project_name}'",
        f"You have been added to the project '{project_name}' with the role '{role}'.",
        templates.get_project_member_added_template(
            target_project_name=project_name,
            inviter_name=inviter_name,
            role=role,
            link=f"{settings.FRONTEND_BASE_URL}/projects/{project_id}",
        ),
    )


def send_password_changed_email(
    background_tasks: BackgroundTasks, email: str, username: str, system_settings: SystemSettings
) -> bool:
    return _queue_email(
        background_tasks,
        system_settings,
        email,
        "Security Alert: Password Changed",
        f"Hello {username},\n\nYour password for {settings.PROJECT_NAME} was successfully changed.\n\n"
        f"If you did not initiate this change, {_CONTACT_ADMIN}",
        templates.get_password_changed_template(username=username, login_link=f"{settings.FRONTEND_BASE_URL}/login"),
    )


def send_2fa_enabled_email(
    background_tasks: BackgroundTasks, email: str, username: str, system_settings: SystemSettings
) -> bool:
    return _queue_email(
        background_tasks,
        system_settings,
        email,
        "Security Alert: 2FA Enabled",
        f"Hello {username},\n\nTwo-Factor Authentication (2FA) has been enabled for your account.\n\n"
        f"If you did not initiate this change, {_CONTACT_ADMIN}",
        templates.get_2fa_enabled_template(username=username),
    )


def send_2fa_disabled_email(
    background_tasks: BackgroundTasks, email: str, username: str, system_settings: SystemSettings, *, by_admin: bool
) -> bool:
    if by_admin:
        subject, actor, unexpected = " by Admin", " by an administrator", "If you did not request this"
    else:
        subject, actor, unexpected = "", "", "If you did not initiate this change"
    return _queue_email(
        background_tasks,
        system_settings,
        email,
        f"Security Alert: 2FA Disabled{subject}",
        f"Hello {username},\n\nTwo-Factor Authentication (2FA) has been disabled for your account{actor}.\n\n"
        f"{unexpected}, {_CONTACT_ADMIN}",
        templates.get_2fa_disabled_template(username=username),
    )
