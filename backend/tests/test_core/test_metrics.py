"""Tests for HTTP metric labels, the /metrics endpoint and removed dead helpers."""

import secrets
import threading

import httpx
import pytest
from fastapi import APIRouter, FastAPI
from prometheus_client import REGISTRY, generate_latest

from app.core import metrics
from app.core.metrics import (
    PrometheusMiddleware,
    http_request_duration_seconds,
    http_request_size_bytes,
    http_requests_total,
    http_response_size_bytes,
    metrics_endpoint,
)

UNMATCHED = "<unmatched>"
TOKEN_TEMPLATE = "/api/v1/invitations/system/{token}"


def _build_app() -> FastAPI:
    router = APIRouter()

    @router.get("/system/{token}")
    async def read_invitation(token: str) -> dict[str, str]:
        return {"status": "valid"}

    @router.post("/system/{token}")
    async def update_invitation(token: str, body: dict[str, str]) -> dict[str, str]:
        return {"status": "updated"}

    @router.get("/{invitation_id}/files/{file_path:path}")
    async def read_file(invitation_id: str, file_path: str) -> dict[str, str]:
        return {"status": "ok"}

    app = FastAPI()
    app.add_middleware(PrometheusMiddleware)
    app.get("/metrics", include_in_schema=False)(metrics_endpoint)
    app.include_router(router, prefix="/api/v1/invitations")
    return app


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=_build_app()), base_url="http://test")


def _sample(name: str, labels: dict[str, str]) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def _endpoint_labels() -> set[str]:
    return {
        sample.labels["endpoint"]
        for metric in (
            http_requests_total,
            http_request_duration_seconds,
            http_request_size_bytes,
            http_response_size_bytes,
        )
        for family in metric.collect()
        for sample in family.samples
        if "endpoint" in sample.labels
    }


class TestRouteTemplateLabel:
    @pytest.mark.asyncio
    async def test_token_path_is_labeled_with_its_prefixed_route_template(self) -> None:
        token = secrets.token_urlsafe(32)
        labels = {"method": "GET", "endpoint": TOKEN_TEMPLATE, "status": "200"}
        before = _sample("http_requests_total", labels)

        async with _client() as client:
            response = await client.get(f"/api/v1/invitations/system/{token}")

        assert response.status_code == 200
        assert _sample("http_requests_total", labels) == before + 1
        assert token not in generate_latest(REGISTRY).decode()

    @pytest.mark.asyncio
    async def test_request_and_response_sizes_are_labeled_with_the_route_template(self) -> None:
        labels = {"method": "POST", "endpoint": TOKEN_TEMPLATE}
        requests_before = _sample("http_request_size_bytes_count", labels)
        responses_before = _sample("http_response_size_bytes_count", labels)

        async with _client() as client:
            response = await client.post(
                f"/api/v1/invitations/system/{secrets.token_urlsafe(32)}", json={"password": "x"}
            )

        assert response.status_code == 200
        assert _sample("http_request_size_bytes_count", labels) == requests_before + 1
        assert _sample("http_response_size_bytes_count", labels) == responses_before + 1

    @pytest.mark.asyncio
    async def test_multi_segment_path_parameter_is_labeled_with_its_route_template(self) -> None:
        labels = {"method": "GET", "endpoint": "/api/v1/invitations/{invitation_id}/files/{file_path}", "status": "200"}
        before = _sample("http_requests_total", labels)

        async with _client() as client:
            response = await client.get(
                f"/api/v1/invitations/{secrets.token_urlsafe(8)}/files/a/b/{secrets.token_urlsafe(8)}"
            )

        assert response.status_code == 200
        assert _sample("http_requests_total", labels) == before + 1

    @pytest.mark.asyncio
    async def test_unknown_path_is_labeled_unmatched(self) -> None:
        labels = {"method": "GET", "endpoint": UNMATCHED, "status": "404"}
        before = _sample("http_requests_total", labels)

        async with _client() as client:
            response = await client.get("/api/v1/does-not-exist")

        assert response.status_code == 404
        assert _sample("http_requests_total", labels) == before + 1

    @pytest.mark.asyncio
    async def test_random_unknown_paths_share_one_label_value(self) -> None:
        labels = {"method": "GET", "endpoint": UNMATCHED, "status": "404"}
        before = _sample("http_requests_total", labels)
        labels_before = _endpoint_labels()

        async with _client() as client:
            for _ in range(1000):
                await client.get(f"/api/{secrets.token_urlsafe(12)}/{secrets.token_urlsafe(12)}")

        assert _sample("http_requests_total", labels) == before + 1000
        assert _endpoint_labels() - labels_before <= {UNMATCHED}


class TestInProgressGauge:
    """The gauge counts requests in flight, so every increment needs its matching decrement."""

    @staticmethod
    def _in_progress() -> float:
        return _sample("http_requests_in_progress", {"method": "GET"})

    @staticmethod
    async def _drive(app) -> None:
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(_message):
            return None

        scope = {"type": "http", "path": "/api/v1/anything", "method": "GET", "headers": []}
        await PrometheusMiddleware(app)(scope, receive, send)

    @pytest.mark.asyncio
    async def test_gauge_is_labeled_by_method_and_returns_to_baseline_after_a_request(self) -> None:
        baseline = self._in_progress()
        in_flight: list[float] = []

        async def app(_scope, _receive, send):
            in_flight.append(self._in_progress())
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        await self._drive(app)

        assert in_flight == [baseline + 1]
        assert self._in_progress() == baseline

    @pytest.mark.asyncio
    async def test_gauge_returns_to_its_baseline_when_the_app_raises(self) -> None:
        baseline = self._in_progress()

        async def app(_scope, _receive, _send):
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            await self._drive(app)

        assert self._in_progress() == baseline


class TestMetricsEndpoint:
    @pytest.mark.asyncio
    async def test_exposition_is_generated_off_the_event_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        generating_threads: list[threading.Thread] = []

        def recording_generate_latest(registry) -> bytes:
            generating_threads.append(threading.current_thread())
            return b""

        monkeypatch.setattr(metrics, "generate_latest", recording_generate_latest)

        async with _client() as client:
            response = await client.get("/metrics")

        assert response.status_code == 200
        assert len(generating_threads) == 1
        assert generating_threads[0] is not threading.current_thread()


class TestDeadCodeRemoved:
    def test_track_db_operation_present(self) -> None:
        assert hasattr(metrics, "track_db_operation")

    def test_track_cache_operation_removed(self) -> None:
        assert not hasattr(metrics, "track_cache_operation")

    def test_track_external_api_removed(self) -> None:
        assert not hasattr(metrics, "track_external_api")
