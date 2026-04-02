#!/bin/sh
set -e

# Default values
HOST="${HOST:-0.0.0.0}"
HTTP_PORT="${HTTP_PORT:-8000}"
HTTPS_PORT="${HTTPS_PORT:-8443}"
WORKERS="${WORKER_COUNT:-1}"

# Vulnerability database setup
# ─────────────────────────────
# Trivy: If TRIVY_SERVER_URL is set, skip local DB download (server holds the DB).
# Grype: If GRYPE_DB_SHARED=true, skip download (shared volume holds the DB).
# Otherwise, pre-download DBs so parallel workers don't each download their own copy.

if [ -n "$TRIVY_SERVER_URL" ]; then
    echo "Trivy server mode: using remote server at $TRIVY_SERVER_URL (no local DB needed)"
else
    echo "Updating Trivy vulnerability database..."
    trivy image --download-db-only 2>&1 || echo "WARNING: Trivy DB update failed (will retry on next pod restart)"
fi
export TRIVY_SKIP_DB_UPDATE=true

if [ "$GRYPE_DB_SHARED" = "true" ]; then
    # Check if shared DB is available (GCSFuse mount)
    if find "${GRYPE_DB_CACHE_DIR:-/app/.cache/grype}" -name "vulnerability.db" 2>/dev/null | grep -q .; then
        echo "Grype shared DB mode: using pre-loaded DB from ${GRYPE_DB_CACHE_DIR:-/app/.cache/grype}"
    else
        echo "WARNING: Shared Grype DB not yet available. Falling back to local download..."
        export GRYPE_DB_CACHE_DIR=/app/.cache/grype-local
        mkdir -p "$GRYPE_DB_CACHE_DIR"
        grype db update 2>&1 || echo "WARNING: Grype DB update failed"
    fi
else
    echo "Updating Grype vulnerability database..."
    rm -rf "${GRYPE_DB_CACHE_DIR:-/app/.cache/grype}"/grype-db-download* /tmp/getter* 2>/dev/null || true
    grype db update 2>&1 || echo "WARNING: Grype DB update failed (will retry on next pod restart)"
    rm -rf "${GRYPE_DB_CACHE_DIR:-/app/.cache/grype}"/grype-db-download* /tmp/getter* 2>/dev/null || true
fi
export GRYPE_DB_AUTO_UPDATE=false

# Build uvicorn command based on TLS settings
if [ "$TLS_ENABLED" = "true" ]; then
    # Verify certificates exist
    if [ ! -f "$TLS_CERT_PATH" ]; then
        echo "ERROR: TLS certificate not found at $TLS_CERT_PATH" >&2
        exit 1
    fi
    if [ ! -f "$TLS_KEY_PATH" ]; then
        echo "ERROR: TLS key not found at $TLS_KEY_PATH" >&2
        exit 1
    fi

    echo "Starting uvicorn with HTTPS on port $HTTPS_PORT ($WORKERS workers)"
    exec uvicorn app.main:app \
        --host "$HOST" \
        --port "$HTTPS_PORT" \
        --workers "$WORKERS" \
        --ssl-certfile "$TLS_CERT_PATH" \
        --ssl-keyfile "$TLS_KEY_PATH" \
        --proxy-headers \
        --forwarded-allow-ips "${TRUSTED_PROXY_IPS:-*}"
else
    echo "Starting uvicorn with HTTP on port $HTTP_PORT ($WORKERS workers)"
    exec uvicorn app.main:app \
        --host "$HOST" \
        --port "$HTTP_PORT" \
        --workers "$WORKERS" \
        --proxy-headers \
        --forwarded-allow-ips "${TRUSTED_PROXY_IPS:-*}"
fi
