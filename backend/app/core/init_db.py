import logging
import secrets
from typing import Any

import pymongo
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.permissions import ALL_PERMISSIONS
from app.core.security import get_password_hash
from app.core.metrics import update_db_stats
from app.db.mongodb import get_database
from app.models.user import User

logger = logging.getLogger(__name__)


async def create_indexes(database: AsyncIOMotorDatabase[Any]) -> None:
    """Creates indexes for all collections to ensure performance."""
    logger.info("Creating database indexes...")

    # Users
    await database["users"].create_index("username", unique=True)
    await database["users"].create_index("email", unique=True)

    # Projects
    await database["projects"].create_index("owner_id")
    await database["projects"].create_index("team_id")
    await database["projects"].create_index("name")
    await database["projects"].create_index("members.user_id")

    # Teams
    await database["teams"].create_index("members.user_id")

    # Scans
    await database["scans"].create_index("project_id")
    await database["scans"].create_index("pipeline_id")  # For CI/CD lookups
    await database["scans"].create_index("status")  # For worker queue
    await database["scans"].create_index([("created_at", pymongo.DESCENDING)])
    # Compound index for efficient retrieval of project scans sorted by date
    await database["scans"].create_index(
        [("project_id", pymongo.ASCENDING), ("created_at", pymongo.DESCENDING)]
    )

    # Analysis Results
    await database["analysis_results"].create_index("scan_id")
    await database["analysis_results"].create_index(
        [("scan_id", pymongo.ASCENDING), ("analyzer_name", pymongo.ASCENDING)]
    )

    # Waivers
    await database["waivers"].create_index("project_id")
    await database["waivers"].create_index("expiration_date")
    await database["waivers"].create_index(
        [("project_id", pymongo.ASCENDING), ("expiration_date", pymongo.DESCENDING)]
    )

    # Dependencies (New Normalized Collection)
    await database["dependencies"].create_index("project_id")
    await database["dependencies"].create_index("scan_id")
    await database["dependencies"].create_index("name")
    await database["dependencies"].create_index("purl")
    await database["dependencies"].create_index("version")
    await database["dependencies"].create_index("type")
    await database["dependencies"].create_index("direct")
    # Unique constraint to prevent duplicate dependencies in the same scan
    # This allows safe upsert operations and prevents race conditions during SBOM ingestion
    await database["dependencies"].create_index(
        [
            ("scan_id", pymongo.ASCENDING),
            ("name", pymongo.ASCENDING),
            ("version", pymongo.ASCENDING),
            ("purl", pymongo.ASCENDING),
        ],
        unique=True,
        sparse=True,  # Allow null purl values
    )
    # Compound index for fast search within a project
    await database["dependencies"].create_index(
        [("project_id", pymongo.ASCENDING), ("name", pymongo.ASCENDING)]
    )
    # Compound index for analytics queries
    await database["dependencies"].create_index(
        [("scan_id", pymongo.ASCENDING), ("name", pymongo.ASCENDING)]
    )
    await database["dependencies"].create_index(
        [("scan_id", pymongo.ASCENDING), ("direct", pymongo.ASCENDING)]
    )

    # Findings (New Normalized Collection)
    await database["findings"].create_index("project_id")
    await database["findings"].create_index("scan_id")
    await database["findings"].create_index("severity")
    await database["findings"].create_index("type")
    await database["findings"].create_index("finding_id")  # Logical ID (CVE)
    # Compound for fast retrieval of scan results
    await database["findings"].create_index(
        [("scan_id", pymongo.ASCENDING), ("severity", pymongo.DESCENDING)]
    )

    # Finding Records - Analytics indexes
    await database["finding_records"].create_index(
        [("project_id", pymongo.ASCENDING), ("finding.component", pymongo.ASCENDING)]
    )
    await database["finding_records"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("finding.component", pymongo.ASCENDING),
            ("finding.type", pymongo.ASCENDING),
        ]
    )
    await database["finding_records"].create_index(
        [("scan_id", pymongo.ASCENDING), ("finding.type", pymongo.ASCENDING)]
    )

    # Projects - Additional indexes
    await database["projects"].create_index("gitlab_project_id")
    await database["projects"].create_index("latest_scan_id")
    await database["projects"].create_index("retention_days")
    await database["projects"].create_index([("last_scan_at", pymongo.DESCENDING)])
    await database["projects"].create_index([("created_at", pymongo.DESCENDING)])

    # Scans - Additional compound indexes for common query patterns
    await database["scans"].create_index(
        [("project_id", pymongo.ASCENDING), ("pipeline_id", pymongo.ASCENDING)]
    )
    await database["scans"].create_index(
        [("project_id", pymongo.ASCENDING), ("status", pymongo.ASCENDING)]
    )
    await database["scans"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("status", pymongo.ASCENDING),
            ("created_at", pymongo.DESCENDING),
        ]
    )
    await database["scans"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("branch", pymongo.ASCENDING),
            ("created_at", pymongo.DESCENDING),
        ]
    )
    await database["scans"].create_index(
        [("status", pymongo.ASCENDING), ("analysis_started_at", pymongo.ASCENDING)]
    )
    await database["scans"].create_index("original_scan_id")
    await database["scans"].create_index("latest_rescan_id")  # For fast rescan history traversal

    # Findings - Additional indexes for analytics and stats
    await database["findings"].create_index("waived")
    await database["findings"].create_index("component")
    await database["findings"].create_index("version")
    await database["findings"].create_index([("created_at", pymongo.DESCENDING)])
    await database["findings"].create_index(
        [("scan_id", pymongo.ASCENDING), ("waived", pymongo.ASCENDING)]
    )
    await database["findings"].create_index(
        [("scan_id", pymongo.ASCENDING), ("type", pymongo.ASCENDING)]
    )
    await database["findings"].create_index(
        [
            ("scan_id", pymongo.ASCENDING),
            ("component", pymongo.ASCENDING),
            ("version", pymongo.ASCENDING),
        ]
    )
    await database["findings"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("component", pymongo.ASCENDING),
            ("type", pymongo.ASCENDING),
        ]
    )

    # Dependencies - Additional compound indexes
    await database["dependencies"].create_index(
        [
            ("scan_id", pymongo.ASCENDING),
            ("name", pymongo.ASCENDING),
            ("version", pymongo.ASCENDING),
        ]
    )
    await database["dependencies"].create_index("source_type")

    # Waivers - Additional indexes for finding/package lookups
    await database["waivers"].create_index("finding_id")
    await database["waivers"].create_index("package_name")

    # Webhooks - Extended with circuit breaker and performance indexes
    await database["webhooks"].create_index("project_id")
    await database["webhooks"].create_index(
        [("is_active", pymongo.ASCENDING), ("circuit_breaker_until", pymongo.ASCENDING)]
    )
    await database["webhooks"].create_index(
        [("project_id", pymongo.ASCENDING), ("is_active", pymongo.ASCENDING)]
    )
    await database["webhooks"].create_index("events")

    # Webhook Deliveries - Audit trail (NEW)
    await database["webhook_deliveries"].create_index(
        [("webhook_id", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)]
    )
    await database["webhook_deliveries"].create_index(
        [("success", pymongo.ASCENDING), ("webhook_id", pymongo.ASCENDING)]
    )
    # TTL Index: Auto-delete after 30 days
    await database["webhook_deliveries"].create_index(
        [("timestamp", pymongo.ASCENDING)], expireAfterSeconds=2592000
    )

    # Distributed Locks - Multi-pod coordination (NEW)
    # TTL Index: Auto-delete expired locks
    await database["distributed_locks"].create_index(
        [("expires_at", pymongo.ASCENDING)], expireAfterSeconds=0
    )

    # Token Blacklist - Logout invalidation (NEW)
    await database["token_blacklist"].create_index("jti", unique=True)
    # TTL Index: Auto-delete after token expiration
    await database["token_blacklist"].create_index(
        [("expires_at", pymongo.ASCENDING)], expireAfterSeconds=0
    )

    # Scans - Additional index for reachability pending
    await database["scans"].create_index(
        [("reachability_pending", pymongo.ASCENDING), ("project_id", pymongo.ASCENDING)]
    )

    # Dependencies - Source type filtering
    await database["dependencies"].create_index(
        [("scan_id", pymongo.ASCENDING), ("source_type", pymongo.ASCENDING)]
    )

    # Findings - Reachability analysis
    await database["findings"].create_index(
        [("scan_id", pymongo.ASCENDING), ("reachable", pymongo.ASCENDING)]
    )

    # System Invitations
    await database["system_invitations"].create_index("token", unique=True)
    await database["system_invitations"].create_index(
        [
            ("email", pymongo.ASCENDING),
            ("is_used", pymongo.ASCENDING),
            ("expires_at", pymongo.ASCENDING),
        ]
    )
    await database["system_invitations"].create_index(
        [("is_used", pymongo.ASCENDING), ("expires_at", pymongo.ASCENDING)]
    )

    # Dependency Enrichments (cached package metadata)
    await database["dependency_enrichments"].create_index("purl", unique=True)

    # Invitations
    await database["project_invitations"].create_index("token", unique=True)
    await database["project_invitations"].create_index("email")

    logger.info("Database indexes created successfully.")


async def init_db() -> None:
    """Initialize the database with indexes and initial admin user."""
    database = await get_database()

    # Create indexes
    await create_indexes(database)

    user_collection = database["users"]

    # Check if any user exists
    if await user_collection.count_documents({}) == 0:
        logger.info("No users found. Creating initial admin user.")

        # Generate a secure random password
        password = secrets.token_urlsafe(16)
        hashed_password = get_password_hash(password)

        # Create the initial user with all permissions
        user = User(
            username="admin",
            email="admin@example.com",
            hashed_password=hashed_password,
            permissions=list(ALL_PERMISSIONS),
        )

        # Insert into database
        await user_collection.insert_one(user.model_dump(by_alias=True))

        # Print credentials to stdout ONLY (not logs) - password shown once
        # SECURITY: Never log passwords to persistent log files
        print("\n" + "=" * 60)
        print("INITIAL ADMIN USER CREATED")
        print("-" * 60)
        print(f"Username: {user.username}")
        print(f"Email:    {user.email}")
        print(f"Password: {password}")
        print("-" * 60)
        print("PLEASE CHANGE THIS PASSWORD IMMEDIATELY AFTER LOGIN!")
        print("This password will not be shown again.")
        print("=" * 60 + "\n")

        logger.info("Initial admin user created. Credentials displayed on stdout.")
    else:
        logger.info("Users already exist. Skipping initial user creation.")

    # Update database statistics metrics
    await update_db_stats(database)
    logger.info("Database statistics metrics initialized.")
