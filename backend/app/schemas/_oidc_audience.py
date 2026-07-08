"""Shared OIDC audience validation for provider-instance schemas.

The blank-check belongs only on Create/Update schemas; Response schemas must
serialize instances whose audience is null so admins can see and fix them.
"""


def validate_audience_not_blank(value: str) -> str:
    """Reject empty / whitespace-only audiences (fail-closed)."""
    if not value or not value.strip():
        raise ValueError("oidc_audience is required and must not be empty")
    return value


def validate_optional_audience_not_blank(value: "str | None") -> "str | None":
    """Allow omitting the audience, but reject clearing it to a blank value."""
    if value is not None and not value.strip():
        raise ValueError("oidc_audience must not be empty")
    return value
