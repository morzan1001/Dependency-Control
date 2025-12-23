import logging
import secrets

import pymongo

from app.core.security import get_password_hash
from app.db.mongodb import get_database
from app.models.user import User

logger = logging.getLogger(__name__)


async def create_indexes(db):
    """Creates indexes for all collections to ensure performance."""
    logger.info("Creating database indexes...")

    # Users
    await db["users"].create_index("username", unique=True)
    await db["users"].create_index("email", unique=True)

    # Projects
    await db["projects"].create_index("owner_id")
    await db["projects"].create_index("team_id")
    await db["projects"].create_index("name")
    await db["projects"].create_index("members.user_id")

    # Teams
    await db["teams"].create_index("members.user_id")

    # Scans
    await db["scans"].create_index("project_id")
    await db["scans"].create_index("pipeline_id")  # For CI/CD lookups
    await db["scans"].create_index("status")  # For worker queue
    await db["scans"].create_index([("created_at", pymongo.DESCENDING)])
    # Compound index for efficient retrieval of project scans sorted by date
    await db["scans"].create_index(
        [("project_id", pymongo.ASCENDING), ("created_at", pymongo.DESCENDING)]
    )

    # Analysis Results
    await db["analysis_results"].create_index("scan_id")
    await db["analysis_results"].create_index(
        [("scan_id", pymongo.ASCENDING), ("analyzer_name", pymongo.ASCENDING)]
    )

    # Waivers
    await db["waivers"].create_index("project_id")
    await db["waivers"].create_index("expiration_date")
    await db["waivers"].create_index(
        [("project_id", pymongo.ASCENDING), ("expiration_date", pymongo.DESCENDING)]
    )

    # Dependencies (New Normalized Collection)
    await db["dependencies"].create_index("project_id")
    await db["dependencies"].create_index("scan_id")
    await db["dependencies"].create_index("name")
    await db["dependencies"].create_index("purl")
    await db["dependencies"].create_index("version")
    await db["dependencies"].create_index("type")
    await db["dependencies"].create_index("direct")
    # Compound index for fast search within a project
    await db["dependencies"].create_index(
        [("project_id", pymongo.ASCENDING), ("name", pymongo.ASCENDING)]
    )
    # Compound index for analytics queries
    await db["dependencies"].create_index(
        [("scan_id", pymongo.ASCENDING), ("name", pymongo.ASCENDING)]
    )
    await db["dependencies"].create_index(
        [("scan_id", pymongo.ASCENDING), ("direct", pymongo.ASCENDING)]
    )

    # Findings (New Normalized Collection)
    await db["findings"].create_index("project_id")
    await db["findings"].create_index("scan_id")
    await db["findings"].create_index("severity")
    await db["findings"].create_index("type")
    await db["findings"].create_index("finding_id")  # Logical ID (CVE)
    # Compound for fast retrieval of scan results
    await db["findings"].create_index(
        [("scan_id", pymongo.ASCENDING), ("severity", pymongo.DESCENDING)]
    )

    # Finding Records - Analytics indexes
    await db["finding_records"].create_index(
        [("project_id", pymongo.ASCENDING), ("finding.component", pymongo.ASCENDING)]
    )
    await db["finding_records"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("finding.component", pymongo.ASCENDING),
            ("finding.type", pymongo.ASCENDING),
        ]
    )
    await db["finding_records"].create_index(
        [("scan_id", pymongo.ASCENDING), ("finding.type", pymongo.ASCENDING)]
    )

    # Projects - Additional indexes
    await db["projects"].create_index("gitlab_project_id")
    await db["projects"].create_index("latest_scan_id")
    await db["projects"].create_index("retention_days")
    await db["projects"].create_index([("last_scan_at", pymongo.DESCENDING)])
    await db["projects"].create_index([("created_at", pymongo.DESCENDING)])

    # Scans - Additional compound indexes for common query patterns
    await db["scans"].create_index(
        [("project_id", pymongo.ASCENDING), ("pipeline_id", pymongo.ASCENDING)]
    )
    await db["scans"].create_index(
        [("project_id", pymongo.ASCENDING), ("status", pymongo.ASCENDING)]
    )
    await db["scans"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("status", pymongo.ASCENDING),
            ("created_at", pymongo.DESCENDING),
        ]
    )
    await db["scans"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("branch", pymongo.ASCENDING),
            ("created_at", pymongo.DESCENDING),
        ]
    )
    await db["scans"].create_index(
        [("status", pymongo.ASCENDING), ("analysis_started_at", pymongo.ASCENDING)]
    )
    await db["scans"].create_index("original_scan_id")

    # Findings - Additional indexes for analytics and stats
    await db["findings"].create_index("waived")
    await db["findings"].create_index("component")
    await db["findings"].create_index("version")
    await db["findings"].create_index([("created_at", pymongo.DESCENDING)])
    await db["findings"].create_index(
        [("scan_id", pymongo.ASCENDING), ("waived", pymongo.ASCENDING)]
    )
    await db["findings"].create_index(
        [("scan_id", pymongo.ASCENDING), ("type", pymongo.ASCENDING)]
    )
    await db["findings"].create_index(
        [
            ("scan_id", pymongo.ASCENDING),
            ("component", pymongo.ASCENDING),
            ("version", pymongo.ASCENDING),
        ]
    )
    await db["findings"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("component", pymongo.ASCENDING),
            ("type", pymongo.ASCENDING),
        ]
    )

    # Dependencies - Additional compound indexes
    await db["dependencies"].create_index(
        [
            ("scan_id", pymongo.ASCENDING),
            ("name", pymongo.ASCENDING),
            ("version", pymongo.ASCENDING),
        ]
    )
    await db["dependencies"].create_index("source_type")

    # Waivers - Additional indexes for finding/package lookups
    await db["waivers"].create_index("finding_id")
    await db["waivers"].create_index("package_name")

    # Webhooks
    await db["webhooks"].create_index("project_id")

    # System Invitations
    await db["system_invitations"].create_index("token", unique=True)
    await db["system_invitations"].create_index(
        [
            ("email", pymongo.ASCENDING),
            ("is_used", pymongo.ASCENDING),
            ("expires_at", pymongo.ASCENDING),
        ]
    )
    await db["system_invitations"].create_index(
        [("is_used", pymongo.ASCENDING), ("expires_at", pymongo.ASCENDING)]
    )

    # Dependency Enrichments (cached package metadata)
    await db["dependency_enrichments"].create_index("purl", unique=True)

    # Invitations
    await db["project_invitations"].create_index("token", unique=True)
    await db["project_invitations"].create_index("email")

    logger.info("Database indexes created successfully.")


async def init_db():
    db = await get_database()

    # Create indexes
    await create_indexes(db)

    user_collection = db["users"]

    # Check if any user exists
    if await user_collection.count_documents({}) == 0:
        logger.info("No users found. Creating initial admin user.")

        # Generate a secure random password
        password = secrets.token_urlsafe(16)
        hashed_password = get_password_hash(password)

        # Create the admin user with all permissions
        user = User(
            username="admin",
            email="admin@example.com",
            hashed_password=hashed_password,
            permissions=["*"],
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
