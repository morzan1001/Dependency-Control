"""Shared OIDC audience validation for provider-instance schemas.

The blank-check belongs only on Create/Update schemas; Response schemas must
serialize instances whose audience is null so admins can see and fix them.
"""


def validate_audience_not_blank(value: str | None) -> str:
    """Reject a null or blank audience (fail-closed) and store it trimmed; the token check matches it exactly."""
    stripped = (value or "").strip()
    if not stripped:
        raise ValueError("oidc_audience must not be empty")
    return stripped
