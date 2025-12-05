from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.db.mongodb import connect_to_mongo, close_mongo_connection
from app.core.init_db import init_db
from app.core.worker import worker_manager
from app.api.v1.endpoints import auth, ingest, projects, users, teams

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="""
    Dependency Control API manages software dependencies, analyzes SBOMs, and tracks vulnerabilities.
    
    ## Features
    * **Projects**: Manage projects, API keys, and team members.
    * **Ingest**: Upload SBOMs (Software Bill of Materials) for analysis.
    * **Analysis**: Comprehensive scanning using multiple engines:
        * **Trivy & Grype**: Vulnerability scanning.
        * **OSV.dev**: Open Source Vulnerability database checks.
        * **Deps.dev**: OpenSSF Scorecard and project health.
        * **License Compliance**: Check for restricted licenses (e.g. GPL).
        * **Malware**: Detect known malicious packages.
        * **End-of-Life**: Identify outdated and unsupported components.
    * **Notifications**: Get alerted via Email or Slack when issues are found.
    """,
    version="0.1.0",
    contact={
        "name": "Dependency Control Team",
        "email": "info@dependencycontrol.com",
    },
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Set all CORS enabled origins
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
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

app.include_router(auth.router, prefix=f"{settings.API_V1_STR}", tags=["auth"])
app.include_router(ingest.router, prefix=f"{settings.API_V1_STR}", tags=["ingest"])
app.include_router(projects.router, prefix=f"{settings.API_V1_STR}/projects", tags=["projects"])
app.include_router(users.router, prefix=f"{settings.API_V1_STR}/users", tags=["users"])
app.include_router(teams.router, prefix=f"{settings.API_V1_STR}/teams", tags=["teams"])

@app.get("/")
async def root():
    return {"message": "Welcome to Dependency Control API"}
