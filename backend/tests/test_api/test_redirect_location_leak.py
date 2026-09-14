"""The slash redirect must not hand out the address the app is reached on internally."""

from urllib.parse import urlsplit

import pytest
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient

from app.core.middleware import RelativeLocationMiddleware

INTERNAL_ORIGIN = "https://dependency-control-backend.dependency-control.svc.cluster.local:8443"
INTERNAL_HOST = "dependency-control-backend.dependency-control.svc.cluster.local"


def _schema_paths() -> set[str]:
    from app.main import app

    # From the schema, not app.routes: include_router nests the routes under an opaque
    # _IncludedRouter, so walking app.routes finds none of them.
    return set(app.openapi()["paths"])


def _is_shadowed(bare: str, schema_paths: set[str]) -> bool:
    """True when a path-parameter route already answers the slash-less form, so nothing redirects.

    ``/webhooks/global`` is one: it is swallowed by ``/webhooks/{webhook_id}``.
    """
    wanted = bare.strip("/").split("/")
    for candidate in schema_paths:
        if "{" not in candidate:
            continue
        segments = candidate.strip("/").split("/")
        if len(segments) == len(wanted) and all(
            seg.startswith("{") or seg == want for seg, want in zip(segments, wanted)
        ):
            return True
    return False


def _collection_paths() -> list[str]:
    """Every parameter-free API path that exists only with its trailing slash."""
    paths = _schema_paths()
    return sorted(
        path.rstrip("/")
        for path in paths
        if path.endswith("/")
        and path != "/"
        and "{" not in path
        and path.startswith("/api/v1")
        and path.rstrip("/") not in paths
    )


COLLECTION_PATHS = _collection_paths()
REDIRECTING_PATHS = [p for p in COLLECTION_PATHS if not _is_shadowed(p, _schema_paths())]


@pytest.fixture(scope="module")
def internal_client():
    """The app as the reverse proxy reaches it: the Host it sees is the in-cluster service."""
    from app.main import app

    return TestClient(app, base_url=INTERNAL_ORIGIN, raise_server_exceptions=False)


def test_collection_paths_were_discovered():
    """Guards the sweeps below: an empty list would make every parametrised case vacuous."""
    assert len(REDIRECTING_PATHS) >= 5, REDIRECTING_PATHS
    assert "/api/v1/projects" in REDIRECTING_PATHS


@pytest.mark.parametrize("path", REDIRECTING_PATHS)
def test_slash_redirect_location_is_relative(internal_client, path):
    response = internal_client.get(path, follow_redirects=False)

    assert response.status_code == 307, f"{path} did not redirect: {response.status_code}"
    location = response.headers["location"]
    parsed = urlsplit(location)
    assert not parsed.netloc, f"{path} redirected to an absolute URL: {location}"
    assert location == f"{path}/"


@pytest.mark.parametrize("path", COLLECTION_PATHS)
def test_slash_redirect_names_no_internal_host(internal_client, path):
    response = internal_client.get(path, follow_redirects=False)

    haystack = " ".join([*(f"{k}: {v}" for k, v in response.headers.items()), response.text])
    assert INTERNAL_HOST not in haystack, f"{path} disclosed the internal host: {haystack}"


def test_unauthenticated_redirect_still_leaks_nothing(internal_client):
    """The redirect answers before auth, so it is the anonymous reader's view that matters."""
    response = internal_client.get("/api/v1/projects", follow_redirects=False)

    assert "authorization" not in {k.lower() for k in response.request.headers}
    assert INTERNAL_HOST not in response.headers["location"]


def test_openapi_declares_no_internal_server():
    from app.main import app

    assert INTERNAL_HOST not in str(app.openapi().get("servers"))


def test_cross_origin_redirect_stays_absolute():
    """Only a self-referential Location can go relative; the OIDC hand-off must not."""
    app = FastAPI()

    @app.get("/to-idp")
    def to_idp():
        return RedirectResponse("https://idp.example.com/authorize?client_id=x")

    app.add_middleware(RelativeLocationMiddleware)
    client = TestClient(app, base_url=INTERNAL_ORIGIN)

    response = client.get("/to-idp", follow_redirects=False)
    assert response.headers["location"] == "https://idp.example.com/authorize?client_id=x"


def test_self_referential_redirect_keeps_query_and_fragment():
    app = FastAPI()

    @app.get("/onwards")
    def onwards():
        return RedirectResponse(f"{INTERNAL_ORIGIN}/landing?a=1&b=2#frag")

    app.add_middleware(RelativeLocationMiddleware)
    client = TestClient(app, base_url=INTERNAL_ORIGIN)

    response = client.get("/onwards", follow_redirects=False)
    assert response.headers["location"] == "/landing?a=1&b=2#frag"
