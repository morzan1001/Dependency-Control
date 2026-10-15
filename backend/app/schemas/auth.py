from pydantic import BaseModel


class MessageResponse(BaseModel):
    message: str


class LogoutResponse(MessageResponse):
    """Response for logout endpoint."""


class VerificationEmailResponse(MessageResponse):
    """Response for verification email endpoints."""


class EmailVerifyResponse(MessageResponse):
    """Response for email verification endpoint."""


class PasswordResetResponse(MessageResponse):
    """Response for password reset endpoint."""


class ForgotPasswordResponse(MessageResponse):
    """Response for forgot password endpoint."""
