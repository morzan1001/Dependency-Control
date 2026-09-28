"""Inbound normalisation of a VCS instance URL; the OIDC issuer lookup matches it without a trailing slash."""


def strip_trailing_slash(value: str | None) -> str | None:
    return value.rstrip("/") if value is not None else None
