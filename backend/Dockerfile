FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1

LABEL org.opencontainers.image.source="https://github.com/morzan1001/Dependency-Control"
LABEL org.opencontainers.image.description="Backend for Dependency Control System"
LABEL org.opencontainers.image.authors="Matthias Duve <morzan1001@gmail.com>"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install system dependencies and Trivy
RUN apt-get update && apt-get install -y curl \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN pip install poetry

# Copy poetry files
COPY pyproject.toml poetry.lock* ./

# Configure poetry to not create a virtual environment
RUN poetry config virtualenvs.create false

# Install dependencies
RUN poetry install --no-interaction --no-ansi --no-root

# Copy application code
COPY . .

# Install the project itself
RUN poetry install --no-interaction --no-ansi

# Create a non-root user
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --gid 1001 --no-create-home appuser

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

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
