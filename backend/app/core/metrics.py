"""
Prometheus Metrics Collection for Dependency Control Backend

This module provides comprehensive metrics for monitoring the backend in a
multi-pod Kubernetes environment. All metrics are designed to work correctly
when multiple backend containers run simultaneously.
"""

import logging
import re
import time
from contextlib import contextmanager
from importlib.metadata import version as get_version
from typing import Callable

from fastapi import Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# =============================================================================
# Application Info Metrics
# =============================================================================

# Get version from package metadata (pyproject.toml)
try:
    APP_VERSION = get_version("dependency-checks")
except Exception:
    APP_VERSION = "unknown"

app_info = Info("dependency_control_app", "Application information")
app_info.info(
    {
        "version": APP_VERSION,
        "app_name": "Dependency Control",
    }
)

# =============================================================================
# HTTP Request Metrics
# =============================================================================

http_requests_total = Counter(
    "http_requests_total",
    "Total HTTP requests by method, endpoint and status",
    ["method", "endpoint", "status"],
)

http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

http_requests_in_progress = Gauge(
    "http_requests_in_progress",
    "Number of HTTP requests currently being processed",
    ["method", "endpoint"],
)

http_request_size_bytes = Histogram(
    "http_request_size_bytes",
    "HTTP request size in bytes",
    ["method", "endpoint"],
    buckets=(100, 1000, 10000, 100000, 1000000, 10000000),
)

http_response_size_bytes = Histogram(
    "http_response_size_bytes",
    "HTTP response size in bytes",
    ["method", "endpoint"],
    buckets=(100, 1000, 10000, 100000, 1000000, 10000000),
)

# =============================================================================
# Database Metrics
# =============================================================================

db_connections_active = Gauge(
    "db_connections_active",
    "Number of active database connections",
)

db_operations_total = Counter(
    "db_operations_total",
    "Total database operations by collection and operation type",
    ["collection", "operation"],
)

db_operation_duration_seconds = Histogram(
    "db_operation_duration_seconds",
    "Database operation duration in seconds",
    ["collection", "operation"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)

db_errors_total = Counter(
    "db_errors_total",
    "Total database errors by type",
    ["error_type"],
)

# Collection-specific metrics
db_projects_total = Gauge(
    "db_projects_total",
    "Total number of projects in database",
)

db_scans_total = Gauge(
    "db_scans_total",
    "Total number of scans in database",
)

db_users_total = Gauge(
    "db_users_total",
    "Total number of users in database",
)

db_findings_total = Gauge(
    "db_findings_total",
    "Total number of findings in database",
)

# =============================================================================
# Cache Metrics (Redis/DragonflyDB)
# =============================================================================

cache_hits_total = Counter(
    "cache_hits_total",
    "Total cache hits",
)

cache_misses_total = Counter(
    "cache_misses_total",
    "Total cache misses",
)

cache_operations_total = Counter(
    "cache_operations_total",
    "Total cache operations by type",
    ["operation"],
)

cache_operation_duration_seconds = Histogram(
    "cache_operation_duration_seconds",
    "Cache operation duration in seconds",
    ["operation"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1),
)

cache_size_bytes = Gauge(
    "cache_size_bytes",
    "Current cache memory usage in bytes",
)

cache_keys_total = Gauge(
    "cache_keys_total",
    "Total number of keys in cache",
)

cache_connected_clients = Gauge(
    "cache_connected_clients",
    "Number of clients connected to cache",
)

# =============================================================================
# Worker Queue Metrics
# =============================================================================

worker_queue_size = Gauge(
    "worker_queue_size",
    "Current number of jobs in the worker queue",
)

worker_active_count = Gauge(
    "worker_active_count",
    "Number of active workers",
)

worker_jobs_processed_total = Counter(
    "worker_jobs_processed_total",
    "Total number of jobs processed by workers",
    ["status"],
)

worker_job_duration_seconds = Histogram(
    "worker_job_duration_seconds",
    "Worker job processing duration in seconds",
    buckets=(1, 5, 10, 30, 60, 120, 300, 600, 1800),
)

# =============================================================================
# Analysis/Scanner Metrics
# =============================================================================

analysis_scans_total = Counter(
    "analysis_scans_total",
    "Total number of scans performed by analyzer type",
    ["analyzer"],
)

analysis_findings_total = Counter(
    "analysis_findings_total",
    "Total findings discovered by analyzer type and severity",
    ["analyzer", "severity"],
)

analysis_findings_by_type = Counter(
    "analysis_findings_by_type",
    "Total findings by finding type",
    ["type", "severity"],
)

analysis_duration_seconds = Histogram(
    "analysis_duration_seconds",
    "Analysis duration in seconds by analyzer type",
    ["analyzer"],
    buckets=(0.1, 0.5, 1, 2, 5, 10, 30, 60, 120),
)

analysis_errors_total = Counter(
    "analysis_errors_total",
    "Total analysis errors by analyzer type",
    ["analyzer"],
)

analysis_sbom_processed_total = Counter(
    "analysis_sbom_processed_total",
    "Total SBOMs processed by format",
    ["format"],
)

analysis_components_parsed_total = Counter(
    "analysis_components_parsed_total",
    "Total components parsed from SBOMs",
)

analysis_sbom_parse_errors_total = Counter(
    "analysis_sbom_parse_errors_total",
    "Total SBOM parsing errors",
)

analysis_gridfs_operations_total = Counter(
    "analysis_gridfs_operations_total",
    "Total GridFS operations for SBOM storage/retrieval",
    ["operation", "status"],
)

analysis_enrichment_total = Counter(
    "analysis_enrichment_total",
    "Total vulnerability enrichments by type",
    ["type"],
)

analysis_epss_scores = Histogram(
    "analysis_epss_scores",
    "Distribution of EPSS scores for vulnerabilities",
    buckets=(0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
)

analysis_kev_vulnerabilities_total = Counter(
    "analysis_kev_vulnerabilities_total",
    "Total vulnerabilities found in CISA KEV catalog",
)

analysis_reachable_vulnerabilities_total = Counter(
    "analysis_reachable_vulnerabilities_total",
    "Total reachable vulnerabilities identified",
    ["reachability_level"],
)

analysis_waivers_applied_total = Counter(
    "analysis_waivers_applied_total",
    "Total waivers applied to findings",
    ["type"],
)

analysis_race_conditions_total = Counter(
    "analysis_race_conditions_total",
    "Total race conditions detected during analysis",
)

analysis_rescan_operations_total = Counter(
    "analysis_rescan_operations_total",
    "Total rescan operations performed",
)

analysis_aggregation_duration_seconds = Histogram(
    "analysis_aggregation_duration_seconds",
    "Time spent aggregating analysis results",
    buckets=(0.5, 1, 2, 5, 10, 20, 30, 60, 120),
)

# =============================================================================
# External API Metrics
# =============================================================================

external_api_requests_total = Counter(
    "external_api_requests_total",
    "Total external API requests by service",
    ["service"],
)

external_api_errors_total = Counter(
    "external_api_errors_total",
    "Total external API errors by service",
    ["service"],
)

external_api_duration_seconds = Histogram(
    "external_api_duration_seconds",
    "External API request duration in seconds",
    ["service"],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0),
)

external_api_rate_limit_hits_total = Counter(
    "external_api_rate_limit_hits_total",
    "Total rate limit hits by service",
    ["service"],
)

# =============================================================================
# Notification Metrics
# =============================================================================

notifications_sent_total = Counter(
    "notifications_sent_total",
    "Total notifications sent by type",
    ["type"],
)

notifications_failed_total = Counter(
    "notifications_failed_total",
    "Total notification failures by type",
    ["type"],
)

# =============================================================================
# Authentication Metrics
# =============================================================================

auth_login_attempts_total = Counter(
    "auth_login_attempts_total",
    "Total login attempts by status",
    ["status"],
)

auth_token_validations_total = Counter(
    "auth_token_validations_total",
    "Total token validations by result",
    ["result"],
)

auth_2fa_verifications_total = Counter(
    "auth_2fa_verifications_total",
    "Total 2FA verification attempts by result",
    ["result"],
)

auth_oidc_logins_total = Counter(
    "auth_oidc_logins_total",
    "Total OIDC login attempts by status",
    ["status"],
)

auth_signups_total = Counter(
    "auth_signups_total",
    "Total user signups by status",
    ["status"],
)

auth_password_resets_total = Counter(
    "auth_password_resets_total",
    "Total password reset completions",
    ["status"],
)

# =============================================================================
# Webhook Metrics
# =============================================================================

webhooks_triggered_total = Counter(
    "webhooks_triggered_total",
    "Total webhooks triggered by event type",
    ["event_type"],
)

webhooks_failed_total = Counter(
    "webhooks_failed_total",
    "Total webhook failures by event type",
    ["event_type"],
)

# =============================================================================
# System Metrics
# =============================================================================

uptime_seconds = Gauge(
    "uptime_seconds",
    "Application uptime in seconds",
)

# Track startup time
startup_time = time.time()


def update_uptime():
    """Update the uptime metric."""
    uptime_seconds.set(time.time() - startup_time)


# =============================================================================
# Prometheus Metrics Endpoint
# =============================================================================


async def metrics_endpoint(request: Request) -> Response:
    """
    Prometheus metrics endpoint.

    This endpoint should only be accessible internally within the Kubernetes
    cluster, not through the Ingress. The ServiceMonitor will scrape this.
    """
    update_uptime()
    metrics_output = generate_latest(REGISTRY)
    return Response(content=metrics_output, media_type=CONTENT_TYPE_LATEST)


# =============================================================================
# Middleware for HTTP Metrics
# =============================================================================


class PrometheusMiddleware(BaseHTTPMiddleware):
    """
    Middleware to automatically collect HTTP request metrics.

    This middleware is designed to work correctly in a multi-pod environment
    where each pod maintains its own metrics that are scraped independently.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip metrics for the /metrics endpoint itself to avoid recursion
        if request.url.path == "/metrics":
            return await call_next(request)

        method = request.method
        # Normalize endpoint path (remove IDs for better grouping)
        endpoint = self._normalize_path(request.url.path)

        # Track request size
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                http_request_size_bytes.labels(
                    method=method, endpoint=endpoint
                ).observe(int(content_length))
            except ValueError:
                pass

        # Track in-progress requests
        http_requests_in_progress.labels(method=method, endpoint=endpoint).inc()

        # Measure request duration
        start_time = time.time()

        try:
            response = await call_next(request)
            status = response.status_code

            # Track response size
            if hasattr(response, "body"):
                http_response_size_bytes.labels(
                    method=method, endpoint=endpoint
                ).observe(len(response.body))

        except Exception as e:
            status = 500
            logger.error(f"Error in PrometheusMiddleware: {e}")
            raise
        finally:
            # Record metrics
            duration = time.time() - start_time
            http_request_duration_seconds.labels(
                method=method, endpoint=endpoint
            ).observe(duration)
            http_requests_total.labels(
                method=method, endpoint=endpoint, status=status
            ).inc()
            http_requests_in_progress.labels(method=method, endpoint=endpoint).dec()

        return response

    def _normalize_path(self, path: str) -> str:
        """
        Normalize URL paths to prevent cardinality explosion.

        Replaces UUIDs and numeric IDs with placeholders.
        Examples:
          /api/v1/projects/123 -> /api/v1/projects/{id}
          /api/v1/users/550e8400-e29b-41d4-a716-446655440000 -> /api/v1/users/{id}
        """
        # Replace UUIDs
        path = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{id}",
            path,
            flags=re.IGNORECASE,
        )

        # Replace numeric IDs
        path = re.sub(r"/\d+", "/{id}", path)

        # Replace MongoDB ObjectIds (24 hex chars)
        path = re.sub(r"/[0-9a-f]{24}", "/{id}", path, flags=re.IGNORECASE)

        return path


# =============================================================================
# Helper Functions for Application Code
# =============================================================================


def track_db_operation(collection: str, operation: str):
    """Context manager to track database operation metrics."""

    @contextmanager
    def _tracker():
        start_time = time.time()
        try:
            yield
            duration = time.time() - start_time
            db_operations_total.labels(collection=collection, operation=operation).inc()
            db_operation_duration_seconds.labels(
                collection=collection, operation=operation
            ).observe(duration)
        except Exception as e:
            error_type = type(e).__name__
            db_errors_total.labels(error_type=error_type).inc()
            raise

    return _tracker()


def track_cache_operation(operation: str):
    """Context manager to track cache operation metrics."""

    @contextmanager
    def _tracker():
        start_time = time.time()
        try:
            yield
            duration = time.time() - start_time
            cache_operations_total.labels(operation=operation).inc()
            cache_operation_duration_seconds.labels(operation=operation).observe(
                duration
            )
        except Exception:
            raise

    return _tracker()


def track_external_api(service: str):
    """Context manager to track external API call metrics."""

    @contextmanager
    def _tracker():
        start_time = time.time()
        try:
            yield
            duration = time.time() - start_time
            external_api_requests_total.labels(service=service).inc()
            external_api_duration_seconds.labels(service=service).observe(duration)
        except Exception:
            external_api_errors_total.labels(service=service).inc()
            raise

    return _tracker()
