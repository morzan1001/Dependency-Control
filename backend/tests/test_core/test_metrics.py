"""Tests for metrics path normalization and removed dead helpers."""

import pytest

from app.core import metrics
from app.core.metrics import PrometheusMiddleware, http_requests_in_progress


def _normalize(path: str) -> str:
    middleware = PrometheusMiddleware(app=None)  # type: ignore[arg-type]
    return middleware._normalize_path(path)


class TestNormalizePath:
    def test_numeric_id_replaced(self) -> None:
        assert _normalize("/api/v1/projects/123") == "/api/v1/projects/{id}"

    def test_uuid_replaced(self) -> None:
        assert _normalize("/api/v1/users/550e8400-e29b-41d4-a716-446655440000") == "/api/v1/users/{id}"

    def test_objectid_replaced(self) -> None:
        # 24-hex ObjectId that starts with a digit. The numeric rule must NOT
        # consume the leading digit before the ObjectId rule can match.
        assert _normalize("/api/v1/scans/5f1a2b3c4d5e6f7a8b9c0d1e") == "/api/v1/scans/{id}"

    def test_token_starting_with_digit_not_mangled(self) -> None:
        # A urlsafe token starting with a digit must not have its leading digit
        # replaced, which would create a unique never-repeated label.
        path = "/api/v1/invitations/system/9Kx9fQabcDEF"
        result = _normalize(path)
        assert "{id}Kx" not in result
        assert result == path

    def test_consecutive_numeric_segments(self) -> None:
        assert _normalize("/api/v1/a/123/b/456") == "/api/v1/a/{id}/b/{id}"

    def test_non_id_path_unchanged(self) -> None:
        assert _normalize("/api/v1/health") == "/api/v1/health"


class TestInProgressGauge:
    """The gauge counts requests in flight, so every increment needs its matching decrement."""

    @staticmethod
    async def _drive(app, endpoint: str) -> None:
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(_message):
            return None

        scope = {"type": "http", "path": endpoint, "method": "GET", "headers": []}
        await PrometheusMiddleware(app)(scope, receive, send)

    @pytest.mark.asyncio
    async def test_gauge_returns_to_its_baseline_after_a_successful_request(self) -> None:
        endpoint = "/api/v1/gauge-success"
        gauge = http_requests_in_progress.labels(method="GET", endpoint=endpoint)
        baseline = gauge._value.get()
        in_flight: list[float] = []

        async def app(_scope, _receive, send):
            in_flight.append(gauge._value.get())
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        await self._drive(app, endpoint)

        assert in_flight == [baseline + 1]
        assert gauge._value.get() == baseline

    @pytest.mark.asyncio
    async def test_gauge_returns_to_its_baseline_when_the_app_raises(self) -> None:
        endpoint = "/api/v1/gauge-crash"
        gauge = http_requests_in_progress.labels(method="GET", endpoint=endpoint)
        baseline = gauge._value.get()

        async def app(_scope, _receive, _send):
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            await self._drive(app, endpoint)

        assert gauge._value.get() == baseline


class TestDeadCodeRemoved:
    def test_track_db_operation_present(self) -> None:
        assert hasattr(metrics, "track_db_operation")

    def test_track_cache_operation_removed(self) -> None:
        assert not hasattr(metrics, "track_cache_operation")

    def test_track_external_api_removed(self) -> None:
        assert not hasattr(metrics, "track_external_api")
