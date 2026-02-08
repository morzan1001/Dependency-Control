import asyncio
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from app.core.config import settings
from app.core.metrics import PrometheusMiddleware, metrics_endpoint
from app.db.mongodb import close_mongo_connection, connect_to_mongo
from app.api import health
from app.api.v1.endpoints import (
    analytics,
    auth,
    callgraph,
    gitlab_instances,
    ingest,
    integrations,
    invitations,
    notifications,
    projects,
    scripts,
    system,
    teams,
    users,
    waivers,
    webhooks,
)
from app.core.init_db import init_db
from app.core.worker import worker_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="""
Dependency Control API for managing software dependencies, analyzing SBOMs,
and tracking vulnerabilities.

## Features
* **Project & Team Management**: Organize projects and manage access with teams.
* **SBOM Ingestion**: Upload and analyze Software Bill of Materials.
* **Comprehensive Analysis**: Vulnerabilities (Trivy, Grype, OSV), Secrets,
  License Compliance, Malware, End-of-Life, and Typosquatting.
* **Risk Management**: Handle false positives with waivers.
* **Integrations**: Webhooks and Notifications (Email, Slack, Mattermost).
* **User Management**: Secure authentication with 2FA and email verification.

Source Code: [GitHub Repository](https://github.com/morzan1001/Dependency-Control)
    """,
    version="1.4.33",
    license_info={
        "name": "MIT License",
        "url": "https://github.com/morzan1001/Dependency-Control/blob/main/LICENSE",
    },
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
)

# Add GZip Middleware for response compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Add Prometheus Middleware for metrics collection
app.add_middleware(PrometheusMiddleware)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception handler caught: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal Server Error. Please check the logs for more details."
        },
    )


@app.on_event("startup")
async def startup_event():
    max_retries = 30
    retry_interval = 5

    for i in range(max_retries):
        try:
            await connect_to_mongo()
            await init_db()  # Creates indexes + initial admin user

            await worker_manager.start()
            logger.info("Application startup complete.")
            break
        except (ServerSelectionTimeoutError, ConnectionFailure) as e:
            logger.warning(
                f"Database connection failed (Attempt {i+1}/{max_retries}): {e}"
            )
            await close_mongo_connection()
            if i < max_retries - 1:
                logger.info(f"Retrying in {retry_interval} seconds...")
                await asyncio.sleep(retry_interval)
            else:
                logger.error("Could not connect to database after multiple attempts.")
                raise e
        except Exception as e:
            logger.error(f"Unexpected error during startup: {e}")
            raise e


@app.on_event("shutdown")
async def shutdown_event():
    await worker_manager.stop()
    await close_mongo_connection()


# Prometheus metrics endpoint (internal only, not exposed via Ingress)
app.get("/metrics", include_in_schema=False)(metrics_endpoint)

app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}", tags=["auth"])
app.include_router(ingest.router, prefix=f"{settings.API_V1_STR}", tags=["ingest"])
app.include_router(
    projects.router, prefix=f"{settings.API_V1_STR}/projects", tags=["projects"]
)
app.include_router(users.router, prefix=f"{settings.API_V1_STR}/users", tags=["users"])
app.include_router(teams.router, prefix=f"{settings.API_V1_STR}/teams", tags=["teams"])
app.include_router(
    waivers.router, prefix=f"{settings.API_V1_STR}/waivers", tags=["waivers"]
)
app.include_router(
    webhooks.router, prefix=f"{settings.API_V1_STR}/webhooks", tags=["webhooks"]
)
app.include_router(
    system.router, prefix=f"{settings.API_V1_STR}/system", tags=["system"]
)
app.include_router(
    gitlab_instances.router,
    prefix=f"{settings.API_V1_STR}/gitlab-instances",
    tags=["gitlab-instances"],
)
app.include_router(
    invitations.router,
    prefix=f"{settings.API_V1_STR}/invitations",
    tags=["invitations"],
)
app.include_router(
    integrations.router,
    prefix=f"{settings.API_V1_STR}/integrations",
    tags=["integrations"],
)
app.include_router(
    notifications.router,
    prefix=f"{settings.API_V1_STR}/notifications",
    tags=["notifications"],
)
app.include_router(
    analytics.router, prefix=f"{settings.API_V1_STR}/analytics", tags=["analytics"]
)
app.include_router(
    callgraph.router, prefix=f"{settings.API_V1_STR}/projects", tags=["callgraph"]
)
app.include_router(scripts.router, prefix=f"{settings.API_V1_STR}", tags=["scripts"])


@app.get("/")
async def root():
    return {"message": "Welcome to Dependency Control API"}
