from collections.abc import Iterable

from app.core.security import create_access_token


def bearer_headers(username: str, permissions: Iterable[str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(username, permissions=list(permissions))}"}
