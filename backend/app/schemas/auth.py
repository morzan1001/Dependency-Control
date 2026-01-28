"""
Auth Schema Definitions

Pydantic models for authentication API endpoints.
"""

from pydantic import BaseModel


class MessageResponse(BaseModel):
    """Generic message response for auth endpoints."""

    message: str


class LogoutResponse(MessageResponse):
    """Response for logout endpoint."""

    pass


class VerificationEmailResponse(MessageResponse):
    """Response for verification email endpoints."""

    pass


class EmailVerifyResponse(MessageResponse):
    """Response for email verification endpoint."""

    pass


class PasswordResetResponse(MessageResponse):
    """Response for password reset endpoint."""

    pass


class ForgotPasswordResponse(MessageResponse):
    """Response for forgot password endpoint."""

    pass
