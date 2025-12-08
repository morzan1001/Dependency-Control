FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1

LABEL org.opencontainers.image.source="https://github.com/morzan1001/Dependency-Control"
LABEL org.opencontainers.image.description="Backend for Dependency Control System"
LABEL org.opencontainers.image.authors="Matthias Duve <morzan1001@gmail.com>"

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

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
