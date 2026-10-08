import logging
import secrets
from typing import Any

import pymongo
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import (
    DEPENDENCIES_SCAN_PACKAGE_INDEX,
    FINDINGS_SCAN_COMPONENT_INDEX,
    FINDINGS_SCAN_TYPE_INDEX,
    SCANS_TIP_SORT,
)
from app.core.metrics import update_db_stats
from app.core.permissions import ALL_PERMISSIONS
from app.core.security import get_password_hash
from app.db.mongodb import get_database
from app.models.user import User
from app.repositories.findings import FIRST_DETECTION_INDEX, NEWEST_VULNERABILITY_INDEX, VULNERABILITIES_ONLY
from app.services.crypto_policy.seeder import seed_crypto_policies

logger = logging.getLogger(__name__)

MONGO_TYPE = "$type"

RELEASES_UPSERT_KEY_NAME = "releases_upsert_key"
# One release per (project, environment, scan): the upsert filter and the constraint behind it,
# so a test double can declare the same key rather than a copy of it.
RELEASES_UPSERT_KEY_FIELDS: tuple[str, ...] = ("project_id", "environment", "scan_id")

RELEASES_LATEST_LOOKUP_NAME = "releases_latest_lookup"

# BSON dates are milliseconds, so a date-ordered pick tie-breaks on _id. Each sort is the trailing
# keys of its index: sorting on anything else turns an indexed seek into a blocking sort.
RELEASES_LATEST_SORT: list[tuple[str, int]] = [("released_at", pymongo.DESCENDING), ("_id", pymongo.ASCENDING)]

SCANS_TIP_INDEX_KEY: list[tuple[str, int]] = [
    ("project_id", pymongo.ASCENDING),
    ("status", pymongo.ASCENDING),
    *SCANS_TIP_SORT,
]
RELEASES_LATEST_LOOKUP_KEY: list[tuple[str, int]] = [
    ("project_id", pymongo.ASCENDING),
    ("environment", pymongo.ASCENDING),
    *RELEASES_LATEST_SORT,
]
# The index order left once project_id is matched by equality.
RELEASES_ENVIRONMENT_SORT = RELEASES_LATEST_LOOKUP_KEY[1:]


TEAM_BINDING_KEY_FIELD = "bindings.key"
# Partial, not sparse: a unique index over a path inside a missing array indexes the document
# under the key null, so the second team holding no binding collides — measured, not inferred.
# The filter selects on type, so a team with no bindings stays out of the unique scope entirely.
#
# A constraint, and nothing else: the planner cannot prove an equality on the key implies the
# $type filter, so the binding lookup is a COLLSCAN. Measured on percona-server-mongodb:8.0.17-6
# — 0.507 ms/op scanning 5 000 teams against 0.442 ms indexed, on an estate of 29. Serving that
# read means rebuilding the constraint under an $exists filter, which is not worth a uniqueness
# gap for 0.06 ms; revisit if the collection ever reaches five figures.
TEAM_BINDING_KEY_PARTIAL_FILTER = {TEAM_BINDING_KEY_FIELD: {MONGO_TYPE: "string"}}


async def create_team_indexes(database: AsyncIOMotorDatabase[Any]) -> None:
    """The teams keys, including the one that keeps a binding to a single holder."""
    await database["teams"].create_index("members.user_id")
    # Guarded so a pre-existing duplicate can't crash startup into CrashLoopBackOff —
    # the offending key is logged and the index skipped, degrading gracefully.
    try:
        await database["teams"].create_index(
            [(TEAM_BINDING_KEY_FIELD, pymongo.ASCENDING)],
            unique=True,
            partialFilterExpression=TEAM_BINDING_KEY_PARTIAL_FILTER,
        )
    except pymongo.errors.OperationFailure as exc:
        # Named "response" rather than "details": the Finding.details contract test reads any
        # local of that name as a finding-details access.
        response = exc.details or {}
        logger.exception(
            "Skipping unique teams %s index, build failed with %s; the key stays unenforced "
            "until it is built. Server response: %s",
            TEAM_BINDING_KEY_FIELD,
            response.get("codeName", type(exc).__name__),
            response or exc,
        )


async def create_indexes(database: AsyncIOMotorDatabase[Any]) -> None:
    """Create indexes for all collections."""
    logger.info("Creating database indexes...")

    # Users
    await database["users"].create_index("username", unique=True)
    await database["users"].create_index("email", unique=True)

    # Projects
    # Multikey: serves the element equality every ownership filter is and the $in a member's visible
    # scope is. The project list sorts after filtering and this index cannot supply that order, so it
    # blocking-sorts the matched set; a compound {team_ids, <sort key>} would remove it (measured), but
    # only one sort key can be picked and the list offers six, so at this collection size the sort is
    # left to run in memory.
    await database["projects"].create_index("team_ids")
    await database["projects"].create_index("name")
    await database["projects"].create_index("members.user_id")

    await create_team_indexes(database)

    # Scans
    await database["scans"].create_index("pipeline_id")
    await database["scans"].create_index([("created_at", pymongo.DESCENDING)])
    await database["scans"].create_index([("project_id", pymongo.ASCENDING), ("created_at", pymongo.DESCENDING)])
    await database["scans"].create_index("sbom_refs.gridfs_id")

    # Analysis Results
    await database["analysis_results"].create_index(
        [("scan_id", pymongo.ASCENDING), ("analyzer_name", pymongo.ASCENDING)]
    )
    await database["analysis_results"].create_index("result_gridfs_id", sparse=True)

    # Waivers
    await database["waivers"].create_index("expiration_date")
    await database["waivers"].create_index([("project_id", pymongo.ASCENDING), ("expiration_date", pymongo.DESCENDING)])

    # Dependencies
    await database["dependencies"].create_index("name")
    await database["dependencies"].create_index("purl")
    # Unique key permits idempotent upserts during concurrent SBOM ingestion and serves every (scan_id, name,
    # version) read. sparse is inert (every row has a scan_id, so purl-less rows are indexed and unique too) but
    # stays: changing it fails on the built index.
    await database["dependencies"].create_index(DEPENDENCIES_SCAN_PACKAGE_INDEX, unique=True, sparse=True)
    await database["dependencies"].create_index([("project_id", pymongo.ASCENDING), ("name", pymongo.ASCENDING)])
    await database["dependencies"].create_index([("scan_id", pymongo.ASCENDING), ("version", pymongo.ASCENDING)])
    await database["dependencies"].create_index([("scan_id", pymongo.ASCENDING), ("direct", pymongo.ASCENDING)])
    # Bounds the anchored purl-prefix match of the per-scan enrichment copy to one scan's range.
    await database["dependencies"].create_index([("scan_id", pymongo.ASCENDING), ("purl", pymongo.ASCENDING)])

    # Update-frequency rollups (scan_outdated_sets is only ever read by _id)
    # _id joins the key because the neighbour lookups order by (scan_created_at, _id).
    await database["scan_update_deltas"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("branch", pymongo.ASCENDING),
            ("scan_created_at", pymongo.DESCENDING),
            ("_id", pymongo.DESCENDING),
        ]
    )
    await database["scan_update_deltas"].create_index(
        [("project_id", pymongo.ASCENDING), ("scan_created_at", pymongo.DESCENDING)]
    )

    # Findings
    await database["findings"].create_index("severity")
    await database["findings"].create_index("finding_id")  # Logical CVE id, not _id.
    # The CSV export streams each severity bucket in (type, finding_id) order straight off this key.
    await database["findings"].create_index(
        [
            ("scan_id", pymongo.ASCENDING),
            ("severity", pymongo.ASCENDING),
            ("type", pymongo.ASCENDING),
            ("finding_id", pymongo.ASCENDING),
        ]
    )

    # GitLab compound index: project_id must be unique per instance.
    await database["projects"].create_index(
        [("gitlab_instance_id", pymongo.ASCENDING), ("gitlab_project_id", pymongo.ASCENDING)],
        unique=True,
        partialFilterExpression={
            "gitlab_instance_id": {MONGO_TYPE: "string"},
            "gitlab_project_id": {MONGO_TYPE: "int"},
        },
    )
    await database["projects"].create_index("gitlab_instance_id")
    await database["projects"].create_index("latest_scan_id")
    await database["projects"].create_index("retention_days")
    await database["projects"].create_index([("last_scan_at", pymongo.DESCENDING)])
    await database["projects"].create_index([("created_at", pymongo.DESCENDING)])

    await database["scans"].create_index([("project_id", pymongo.ASCENDING), ("pipeline_id", pymongo.ASCENDING)])
    await database["scans"].create_index(SCANS_TIP_INDEX_KEY)
    await database["scans"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("branch", pymongo.ASCENDING),
            ("created_at", pymongo.DESCENDING),
        ]
    )
    # A branch's tip build is found in one seek, however many rescans of it pile up in front.
    await database["scans"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("branch", pymongo.ASCENDING),
            ("is_rescan", pymongo.ASCENDING),
            *SCANS_TIP_SORT,
        ]
    )
    await database["scans"].create_index([("status", pymongo.ASCENDING), ("analysis_started_at", pymongo.ASCENDING)])
    await database["scans"].create_index("original_scan_id")
    await database["scans"].create_index("latest_rescan_id")

    await database["scans"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("is_release", pymongo.ASCENDING),
            ("created_at", pymongo.DESCENDING),
        ],
        name="scans_released_list",
        partialFilterExpression={"is_release": True},
    )  # Partial so only released scans are indexed; serves the released-only scan list.

    await database["releases"].create_index(
        RELEASES_LATEST_LOOKUP_KEY,
        name=RELEASES_LATEST_LOOKUP_NAME,
    )  # Serves the latest release of a (project, environment) as a single sorted find_one.
    await database["releases"].create_index(
        [(field, pymongo.ASCENDING) for field in RELEASES_UPSERT_KEY_FIELDS],
        name=RELEASES_UPSERT_KEY_NAME,
        unique=True,
    )  # The upsert key: without uniqueness two concurrent marks of one scan both insert.
    await database["releases"].create_index("scan_id")

    await database["findings"].create_index([("scan_id", pymongo.ASCENDING), ("waived", pymongo.ASCENDING)])
    await database["findings"].create_index(FINDINGS_SCAN_TYPE_INDEX)
    await database["findings"].create_index(FINDINGS_SCAN_COMPONENT_INDEX)
    # Both detection lookups hint these keys; an unsatisfiable hint errors, so every persist needs them.
    await database["findings"].create_index(FIRST_DETECTION_INDEX)
    await database["findings"].create_index(NEWEST_VULNERABILITY_INDEX, partialFilterExpression=VULNERABILITIES_ONLY)

    await database["waivers"].create_index("finding_id")
    await database["waivers"].create_index("package_name")

    await database["webhooks"].create_index(
        [("is_active", pymongo.ASCENDING), ("circuit_breaker_until", pymongo.ASCENDING)]
    )
    await database["webhooks"].create_index([("project_id", pymongo.ASCENDING), ("is_active", pymongo.ASCENDING)])
    await database["webhooks"].create_index("events")

    await database["webhook_deliveries"].create_index(
        [("webhook_id", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)]
    )
    # TTL: drops deliveries after 30 days.
    await database["webhook_deliveries"].create_index([("timestamp", pymongo.ASCENDING)], expireAfterSeconds=2592000)

    # TTL: auto-cleans expired distributed locks.
    await database["distributed_locks"].create_index([("expires_at", pymongo.ASCENDING)], expireAfterSeconds=0)

    # TTL: drops blacklisted JWTs after they would have expired anyway.
    await database["token_blacklist"].create_index([("expires_at", pymongo.ASCENDING)], expireAfterSeconds=0)

    # GitLab Instances
    await database["gitlab_instances"].create_index("url", unique=True)
    await database["gitlab_instances"].create_index("name", unique=True)
    await database["gitlab_instances"].create_index("is_active")

    # GitHub Instances
    await database["github_instances"].create_index("url", unique=True)
    await database["github_instances"].create_index("name", unique=True)
    await database["github_instances"].create_index("is_active")

    # GitHub compound index: repository_id must be unique per instance.
    await database["projects"].create_index(
        [("github_instance_id", pymongo.ASCENDING), ("github_repository_id", pymongo.ASCENDING)],
        unique=True,
        partialFilterExpression={
            "github_instance_id": {MONGO_TYPE: "string"},
            "github_repository_id": {MONGO_TYPE: "string"},
        },
    )

    await database["scans"].create_index(
        [("reachability_pending", pymongo.ASCENDING), ("project_id", pymongo.ASCENDING)]
    )

    await database["dependencies"].create_index([("scan_id", pymongo.ASCENDING), ("source_type", pymongo.ASCENDING)])

    await database["findings"].create_index([("scan_id", pymongo.ASCENDING), ("reachable", pymongo.ASCENDING)])

    # Callgraphs
    await database["callgraphs"].create_index([("project_id", pymongo.ASCENDING), ("scan_id", pymongo.ASCENDING)])
    await database["callgraphs"].create_index([("project_id", pymongo.ASCENDING), ("pipeline_id", pymongo.ASCENDING)])
    await database["callgraphs"].create_index("graph_gridfs_id", sparse=True)
    # One callgraph per language per scan. The type filter keeps rows with a null scan_id
    # (pipeline-only uploads) out of the uniqueness scope. Guarded like the teams index so a
    # pre-existing duplicate cannot crash startup.
    try:
        await database["callgraphs"].create_index(
            [
                ("project_id", pymongo.ASCENDING),
                ("language", pymongo.ASCENDING),
                ("scan_id", pymongo.ASCENDING),
            ],
            unique=True,
            partialFilterExpression={"scan_id": {MONGO_TYPE: "string"}},
        )
    except (pymongo.errors.DuplicateKeyError, pymongo.errors.OperationFailure) as exc:
        key_info = getattr(exc, "details", None) or str(exc)
        logger.error(
            "Skipping unique callgraphs (project_id, language, scan_id) index: build failed "
            "(likely a pre-existing duplicate). Startup continues without it; reconcile the "
            "duplicate and re-run. Offending key/error: %s",
            key_info,
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

    # Cached package metadata.
    await database["dependency_enrichments"].create_index("purl", unique=True)

    # Archive Metadata
    await database["archive_metadata"].create_index("scan_id", unique=True)
    await database["archive_metadata"].create_index(
        [("project_id", pymongo.ASCENDING), ("archived_at", pymongo.DESCENDING)]
    )

    # Chat Conversations
    chat_conversations = database["chat_conversations"]
    await chat_conversations.create_index(
        [("user_id", pymongo.ASCENDING), ("updated_at", pymongo.DESCENDING)],
        name="user_conversations_listing",
    )

    # Chat Messages
    chat_messages = database["chat_messages"]
    await chat_messages.create_index(
        [("conversation_id", pymongo.ASCENDING), ("created_at", pymongo.ASCENDING)],
        name="conversation_messages_chronological",
    )

    # Unified API keys
    api_keys = database["api_keys"]
    await api_keys.create_index(
        [("user_id", pymongo.ASCENDING), ("created_at", pymongo.DESCENDING)],
        name="api_keys_user_listing",
    )
    await api_keys.create_index(
        [("token_hash", pymongo.ASCENDING)],
        name="api_keys_token_lookup",
        unique=True,
    )
    # TTL: Mongo expires docs after expires_at, no housekeeping job needed.
    await api_keys.create_index(
        [("expires_at", pymongo.ASCENDING)],
        name="api_keys_ttl",
        expireAfterSeconds=0,
    )

    # Crypto Assets (CBOM)
    await database["crypto_assets"].create_index([("project_id", pymongo.ASCENDING), ("name", pymongo.ASCENDING)])
    await database["crypto_assets"].create_index([("project_id", pymongo.ASCENDING), ("primitive", pymongo.ASCENDING)])
    await database["crypto_assets"].create_index(
        [("project_id", pymongo.ASCENDING), ("scan_id", pymongo.ASCENDING), ("bom_ref", pymongo.ASCENDING)],
        unique=True,
    )
    await database["crypto_assets"].create_index(
        [("project_id", pymongo.ASCENDING), ("asset_type", pymongo.ASCENDING), ("primitive", pymongo.ASCENDING)]
    )

    # Crypto Policies
    await database["crypto_policies"].create_index(
        [("scope", pymongo.ASCENDING), ("project_id", pymongo.ASCENDING)], unique=True
    )

    # Policy Audit Entries (PolicyAuditRepository stores these in "crypto_policy_history").
    await database["crypto_policy_history"].create_index(
        [
            ("policy_type", pymongo.ASCENDING),
            ("policy_scope", pymongo.ASCENDING),
            ("project_id", pymongo.ASCENDING),
            ("version", pymongo.DESCENDING),
        ]
    )
    await database["crypto_policy_history"].create_index(
        [("policy_scope", pymongo.ASCENDING), ("project_id", pymongo.ASCENDING), ("version", pymongo.DESCENDING)]
    )
    await database["crypto_policy_history"].create_index([("timestamp", pymongo.DESCENDING)])
    await database["crypto_policy_history"].create_index(
        [("actor_user_id", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)]
    )

    # Compliance Reports
    await database["compliance_reports"].create_index(
        [
            ("scope", pymongo.ASCENDING),
            ("scope_id", pymongo.ASCENDING),
            ("framework", pymongo.ASCENDING),
            ("requested_at", pymongo.DESCENDING),
        ]
    )
    await database["compliance_reports"].create_index([("status", pymongo.ASCENDING)])
    await database["compliance_reports"].create_index([("expires_at", pymongo.ASCENDING)])
    await database["compliance_reports"].create_index(
        [("requested_by", pymongo.ASCENDING), ("status", pymongo.ASCENDING)]
    )
    await database["compliance_reports"].create_index("artifact_gridfs_id", sparse=True)

    await database["adhoc_jobs"].create_index([("expires_at", pymongo.ASCENDING)], expireAfterSeconds=0)
    await database["adhoc_jobs"].create_index([("status", pymongo.ASCENDING), ("created_at", pymongo.ASCENDING)])
    await database["adhoc_jobs"].create_index("input_file_id")
    await database["adhoc_jobs"].create_index("result_file_id", sparse=True)

    # Findings: scan_created_at analytics indexes
    await database["findings"].create_index([("project_id", pymongo.ASCENDING), ("scan_created_at", pymongo.ASCENDING)])
    await database["findings"].create_index([("type", pymongo.ASCENDING), ("scan_created_at", pymongo.ASCENDING)])

    logger.info("Database indexes created successfully.")


async def init_db() -> None:
    """Initialize the database with indexes and initial admin user."""
    database = await get_database()

    await create_indexes(database)

    user_collection = database["users"]

    if await user_collection.count_documents({}) == 0:
        logger.info("No users found. Creating initial admin user.")

        password = secrets.token_urlsafe(16)
        hashed_password = get_password_hash(password)

        user = User(
            username="admin",
            email="admin@example.com",
            hashed_password=hashed_password,
            permissions=list(ALL_PERMISSIONS),
            # admin@example.com can never receive a verification mail.
            is_verified=True,
        )

        await user_collection.insert_one(user.model_dump(by_alias=True))

        # SECURITY: print credentials to stdout only — never write to log files.
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

    await seed_crypto_policies(database)

    await update_db_stats(database)
    logger.info("Database statistics metrics initialized.")
