"""Shared OIDC audience validation for provider-instance schemas.

SECURITY (Finding 7 / W1.1): ``oidc_audience`` is fail-closed. OIDC tokens are
verified with mandatory audience checking, so an instance whose audience is
blank could never authenticate a token. The blank-check therefore belongs ONLY
on the Create/Update schemas (reject empty -> HTTP 422). It must NOT be applied
to the Response schemas, which have to serialize legacy instances whose audience
is null so admins can see and fix them.

This module centralizes the check so the GitLab and GitHub schema files stay DRY
and cannot drift apart.
"""


def validate_audience_not_blank(value: str) -> str:
    """Reject empty / whitespace-only audiences (fail-closed).

    Used by the *required* ``oidc_audience`` field on Create schemas.
    """
    if not value or not value.strip():
        raise ValueError("oidc_audience is required and must not be empty")
    return value


def validate_optional_audience_not_blank(value: "str | None") -> "str | None":
    """Allow omitting the audience, but reject clearing it to a blank value.

    Used by the *optional* ``oidc_audience`` field on Update schemas: ``None``
    (field not supplied) is fine, but an empty / whitespace-only string is not.
    """
    if value is not None and not value.strip():
        raise ValueError("oidc_audience must not be empty")
    return value
