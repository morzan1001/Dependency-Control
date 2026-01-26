#!/bin/sh
set -e

# Default values
HOST="${HOST:-0.0.0.0}"
HTTP_PORT="${HTTP_PORT:-8000}"
HTTPS_PORT="${HTTPS_PORT:-8443}"
WORKERS="${WORKER_COUNT:-1}"

# Build uvicorn command based on TLS settings
if [ "$TLS_ENABLED" = "true" ]; then
    # Verify certificates exist
    if [ ! -f "$TLS_CERT_PATH" ]; then
        echo "ERROR: TLS certificate not found at $TLS_CERT_PATH"
        exit 1
    fi
    if [ ! -f "$TLS_KEY_PATH" ]; then
        echo "ERROR: TLS key not found at $TLS_KEY_PATH"
        exit 1
    fi

    echo "Starting uvicorn with HTTPS on port $HTTPS_PORT"
    exec uvicorn app.main:app \
        --host "$HOST" \
        --port "$HTTPS_PORT" \
        --ssl-certfile "$TLS_CERT_PATH" \
        --ssl-keyfile "$TLS_KEY_PATH" \
        --proxy-headers \
        --forwarded-allow-ips "*"
else
    echo "Starting uvicorn with HTTP on port $HTTP_PORT"
    exec uvicorn app.main:app \
        --host "$HOST" \
        --port "$HTTP_PORT" \
        --proxy-headers \
        --forwarded-allow-ips "*"
fi
