FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1

LABEL org.opencontainers.image.source="https://github.com/morzan1001/Dependency-Control"
LABEL org.opencontainers.image.description="Backend for Dependency Control System"
LABEL org.opencontainers.image.authors="Matthias Duve <morzan1001@gmail.com>"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install system dependencies, Trivy, and poetry
RUN apt-get update && apt-get install -y curl \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && pip install poetry

# Copy poetry files
COPY backend/pyproject.toml backend/poetry.lock* ./

# Configure poetry and install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root

# Copy application code
COPY backend/app ./app

# Copy CI/CD scripts (for serving via API)
COPY ci-cd/scripts ./ci-cd/scripts

# Install the project itself
RUN poetry install --no-interaction --no-ansi

# Copy entrypoint script
COPY backend/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Create a non-root user
RUN addgroup --system --gid 1000 appgroup && \
    adduser --system --uid 1000 --gid 1000 --no-create-home appuser

# Set environment variables for tools
ENV TRIVY_CACHE_DIR=/app/.cache/trivy
ENV GRYPE_DB_CACHE_DIR=/app/.cache/grype
ENV HOME=/app

# Create cache directories
RUN mkdir -p /app/.cache/trivy && \
    mkdir -p /app/.cache/grype

# Change ownership of the application directory
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose both ports (only one will be used at runtime based on TLS config)
EXPOSE 8000 8443

ENTRYPOINT ["/docker-entrypoint.sh"]
