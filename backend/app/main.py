from fastapi import FastAPI
from app.core.config import settings
from app.db.mongodb import connect_to_mongo, close_mongo_connection
from app.core.init_db import init_db
from app.core.worker import worker_manager
from app.api.v1.endpoints import auth, ingest, projects, users, teams, waivers, webhooks, search, system
from app.api import health

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="""
    Dependency Control API for managing software dependencies, analyzing SBOMs, and tracking vulnerabilities.
    
    ## Features
    * **Project & Team Management**: Organize projects and manage access with teams.
    * **SBOM Ingestion**: Upload and analyze Software Bill of Materials.
    * **Comprehensive Analysis**: Vulnerabilities (Trivy, Grype, OSV), Secrets (TruffleHog), License Compliance, Malware, End-of-Life, and Typosquatting.
    * **Risk Management**: Handle false positives with waivers.
    * **Integrations**: Webhooks and Notifications (Email, Slack, Mattermost).
    * **User Management**: Secure authentication with 2FA and email verification.

    """,
    version="0.1.8",
    license_info={
        "name": "MIT License",
        "url": "https://github.com/morzan1001/Dependency-Control/blob/main/LICENSE",
    },
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

@app.on_event("startup")
async def startup_event():
    await connect_to_mongo()
    await init_db()
    await worker_manager.start()

@app.on_event("shutdown")
async def shutdown_event():
    await worker_manager.stop()
    await close_mongo_connection()

app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}", tags=["auth"])
app.include_router(ingest.router, prefix=f"{settings.API_V1_STR}", tags=["ingest"])
app.include_router(projects.router, prefix=f"{settings.API_V1_STR}/projects", tags=["projects"])
app.include_router(users.router, prefix=f"{settings.API_V1_STR}/users", tags=["users"])
app.include_router(teams.router, prefix=f"{settings.API_V1_STR}/teams", tags=["teams"])
app.include_router(waivers.router, prefix=f"{settings.API_V1_STR}/waivers", tags=["waivers"])
app.include_router(webhooks.router, prefix=f"{settings.API_V1_STR}/webhooks", tags=["webhooks"])
app.include_router(search.router, prefix=f"{settings.API_V1_STR}/search", tags=["search"])
app.include_router(system.router, prefix=f"{settings.API_V1_STR}/system", tags=["system"])

@app.get("/")
async def root():
    return {"message": "Welcome to Dependency Control API"}
