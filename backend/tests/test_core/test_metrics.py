"""Tests for backend/app/core/metrics.py.

Covers audit findings for backend_app_core_metrics_py.md:
  1. _normalize_path must anchor ID substitutions to whole path segments and
     run the ObjectId rule before the numeric rule, so mixed alphanumeric
     segments (e.g. urlsafe tokens) and hex ids starting with a digit are not
     partially mangled into unbounded-cardinality labels.
  2. track_cache_operation / track_external_api were dead code and removed.
"""

from app.core import metrics
from app.core.metrics import PrometheusMiddleware


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


class TestDeadCodeRemoved:
    def test_track_db_operation_present(self) -> None:
        assert hasattr(metrics, "track_db_operation")

    def test_track_cache_operation_removed(self) -> None:
        assert not hasattr(metrics, "track_cache_operation")

    def test_track_external_api_removed(self) -> None:
        assert not hasattr(metrics, "track_external_api")
