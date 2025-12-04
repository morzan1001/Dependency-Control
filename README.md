# Dependency Control System

## Overview
This is a backend system for managing software dependencies, ingesting SBOMs, and performing analyses (e.g., End-of-Life checks).

## Tech Stack
- Python 3.11
- FastAPI
- MongoDB (Motor)
- Poetry
- Docker & Docker Compose

## Setup & Run

### Prerequisites
- Docker and Docker Compose installed.

### Running with Docker Compose
1. Build and start the services:
   ```bash
   docker-compose up --build
   ```
2. The API will be available at `http://localhost:8000`.
3. API Documentation (Swagger UI) at `http://localhost:8000/docs`.

## Usage

### 1. Create a User
Use the `/api/v1/signup` endpoint to create a user.

### 2. Login
Use the `/api/v1/login/access-token` endpoint to get a JWT token.

### 3. Create a Project
Use the `/api/v1/projects/` endpoint (authenticated) to create a project. This will return an `api_key`.

### 4. Ingest SBOM (CI Pipeline)
Use the `/api/v1/ingest` endpoint with the `x-api-key` header.
Payload example:
```json
{
  "project_name": "My Project",
  "branch": "main",
  "commit_hash": "abc1234",
  "sbom": {
    "components": [
      {"name": "python", "version": "3.6.0"},
      {"name": "django", "version": "1.11"}
    ]
  }
}
```
See `examples/ci-cd/` for GitLab CI and GitHub Actions configuration examples.

### 5. View Results
Use the `/api/v1/projects/{project_id}/scans` and `/api/v1/projects/scans/{scan_id}/results` endpoints to view analysis results.
