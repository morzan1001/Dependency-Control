#!/bin/sh
set -e

# Default values
HOST="${HOST:-0.0.0.0}"
HTTP_PORT="${HTTP_PORT:-8000}"
HTTPS_PORT="${HTTPS_PORT:-8443}"
WORKERS="${WORKER_COUNT:-1}"

# Pre-download vulnerability databases so parallel workers don't each download their own copy.
# Failures are non-fatal: the analyzers will simply report tool errors for that scan.
echo "Updating Grype vulnerability database..."
grype db update 2>&1 || echo "WARNING: Grype DB update failed (will retry on next pod restart)"
rm -rf "${GRYPE_DB_CACHE_DIR:-/app/.cache/grype}"/grype-db-download* /tmp/getter* 2>/dev/null || true

echo "Updating Trivy vulnerability database..."
trivy image --download-db-only 2>&1 || echo "WARNING: Trivy DB update failed (will retry on next pod restart)"

# Disable auto-updates during scans now that DBs are pre-loaded
export GRYPE_DB_AUTO_UPDATE=false
export TRIVY_SKIP_DB_UPDATE=true

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
