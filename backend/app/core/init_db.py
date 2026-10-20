import logging
import secrets
from typing import Any

import pymongo
from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase

from app.core.constants import (
    DEPENDENCIES_SCAN_PACKAGE_INDEX,
    DEPENDENCIES_SCAN_VERSION_INDEX,
    FINDINGS_SCAN_COMPONENT_INDEX,
    FINDINGS_SCAN_TYPE_INDEX,
    SCANS_TIP_SORT,
    TEAM_SOURCE_GITLAB,
    team_source,
)
from app.core.metrics import update_db_stats
from app.core.permissions import ALL_PERMISSIONS
from app.core.security import get_password_hash
from app.db.mongodb import get_database
from app.models.user import User
from app.repositories.findings import FIRST_DETECTION_INDEX, NEWEST_VULNERABILITY_INDEX, VULNERABILITIES_ONLY
from app.repositories.scans import RESTORED_SCAN_MATCH, TAG_BUILD_MATCH
from app.services.crypto_policy.seeder import seed_crypto_policies

logger = logging.getLogger(__name__)

MONGO_TYPE = "$type"

RELEASES_UPSERT_KEY_NAME = "releases_upsert_key"
# One release per (project, environment, scan), shared by the upsert filter and the unique index behind it.
RELEASES_UPSERT_KEY_FIELDS: tuple[str, ...] = ("project_id", "environment", "scan_id")

RELEASES_LATEST_LOOKUP_NAME = "releases_latest_lookup"

GITLAB_PROJECT_KEY_NAME = "projects_gitlab_key"

# BSON dates are milliseconds, so ties break on _id; each sort is its index's trailing keys, keeping the seek indexed.
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


async def _backfill_member_and_team_provenance(database: AsyncIOMotorDatabase[Any]) -> None:
    """Skips a team bound to several GitLab instances, as the wrong one's next ingest would delete the owner."""
    teams = database["teams"]
    projects = database["projects"]

    cursor = teams.find(
        {"bindings": {"$elemMatch": {"provider": TEAM_SOURCE_GITLAB}}},
        {"_id": 1, "bindings": 1},
    )
    synced_teams = await cursor.to_list(None)

    projects_stamped = 0
    unattributable = 0
    failed = 0
    for team in synced_teams:
        team_id = team.get("_id")
        # Isolated per team: this runs before index creation, so one raise would crash startup for every other team.
        try:
            instances = {
                binding.get("instance_id")
                for binding in team.get("bindings") or []
                if binding.get("provider") == TEAM_SOURCE_GITLAB
            }
            if len(instances) != 1:
                unattributable += 1
                continue
            (instance_id,) = tuple(instances)

            # Per owner: only this entry is known to be GitLab's; unstamped, a transferred project ends up owned twice.
            provenance = f"team_sources.{team_id}"
            # Only absent or null, as overwriting a stored source would move an owner between instances on startup.
            result = await projects.update_many(
                {"team_ids": team_id, provenance: {"$in": [None]}},
                {"$set": {provenance: team_source(TEAM_SOURCE_GITLAB, instance_id)}},
            )
            projects_stamped += getattr(result, "modified_count", 0) or 0
        except Exception:
            failed += 1
            logger.exception(
                "Provenance backfill: failed to process synced team %s; skipping it and "
                "continuing. It can be reconciled on the next live sync.",
                team_id,
            )
            continue

    if synced_teams:
        logger.info(
            "Provenance backfill complete: %d project(s) stamped an owner with its GitLab instance "
            "across %d synced team(s), %d team(s) named no single instance and were left unstamped, "
            "%d team(s) failed and skipped. "
            "(Members intentionally left unstamped so manually-added members survive merges.)",
            projects_stamped,
            len(synced_teams),
            unattributable,
            failed,
        )


TEAM_BINDING_KEY_FIELD = "bindings.key"
# Partial, as a sparse unique index keys teams without bindings as null; lookups COLLSCAN, fine below five figures.
TEAM_BINDING_KEY_PARTIAL_FILTER = {TEAM_BINDING_KEY_FIELD: {MONGO_TYPE: "string"}}


async def _create_unique_index(
    collection: AsyncIOMotorCollection[Any], keys: list[tuple[str, int]], label: str, **options: Any
) -> None:
    """Logged and skipped on failure, so a pre-existing duplicate can't crash startup into CrashLoopBackOff."""
    try:
        await collection.create_index(keys, unique=True, **options)
    except pymongo.errors.OperationFailure as exc:
        # Not named "details": the Finding.details contract test reads any local of that name as a details access.
        response = exc.details or {}
        logger.exception(
            "Skipping unique %s index, build failed with %s; the key stays unenforced "
            "until it is built. Server response: %s",
            label,
            response.get("codeName", type(exc).__name__),
            response or exc,
        )


async def create_team_indexes(database: AsyncIOMotorDatabase[Any]) -> None:
    await database["teams"].create_index("members.user_id")
    await _create_unique_index(
        database["teams"],
        [(TEAM_BINDING_KEY_FIELD, pymongo.ASCENDING)],
        f"teams {TEAM_BINDING_KEY_FIELD}",
        partialFilterExpression=TEAM_BINDING_KEY_PARTIAL_FILTER,
    )


async def create_indexes(database: AsyncIOMotorDatabase[Any]) -> None:
    logger.info("Creating database indexes...")

    await _backfill_member_and_team_provenance(database)

    await database["users"].create_index("username", unique=True)
    await database["users"].create_index("email", unique=True)

    # Serves ownership filters; the list then sorts in memory, as its six sort keys rule out one compound index.
    await database["projects"].create_index("team_ids")
    await database["projects"].create_index("name")
    await database["projects"].create_index("members.user_id")

    await create_team_indexes(database)

    await database["scans"].create_index("pipeline_id")
    await database["scans"].create_index([("created_at", pymongo.DESCENDING)])
    await database["scans"].create_index([("project_id", pymongo.ASCENDING), ("created_at", pymongo.DESCENDING)])
    await database["scans"].create_index("sbom_refs.gridfs_id")

    await database["analysis_results"].create_index(
        [("scan_id", pymongo.ASCENDING), ("analyzer_name", pymongo.ASCENDING)]
    )
    await database["analysis_results"].create_index("result_gridfs_id", sparse=True)

    await database["waivers"].create_index("expiration_date")
    await database["waivers"].create_index([("project_id", pymongo.ASCENDING), ("expiration_date", pymongo.DESCENDING)])

    # Unique for idempotent concurrent upserts; sparse is inert but stays, as changing it fails on the built index.
    await database["dependencies"].create_index(DEPENDENCIES_SCAN_PACKAGE_INDEX, unique=True, sparse=True)
    await database["dependencies"].create_index(DEPENDENCIES_SCAN_VERSION_INDEX)
    await database["dependencies"].create_index([("scan_id", pymongo.ASCENDING), ("direct", pymongo.ASCENDING)])
    # Bounds the anchored purl-prefix match of the per-scan enrichment copy to one scan's range.
    await database["dependencies"].create_index([("scan_id", pymongo.ASCENDING), ("purl", pymongo.ASCENDING)])

    # scan_outdated_sets is read by _id only; _id is in this key as neighbour lookups order by (scan_created_at, _id).
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

    # The CSV export streams each severity bucket in (type, finding_id) order straight off this key.
    await database["findings"].create_index(
        [
            ("scan_id", pymongo.ASCENDING),
            ("severity", pymongo.ASCENDING),
            ("type", pymongo.ASCENDING),
            ("finding_id", pymongo.ASCENDING),
        ]
    )

    # A $type of "int" would match int32 alone.
    await _create_unique_index(
        database["projects"],
        [("gitlab_instance_id", pymongo.ASCENDING), ("gitlab_project_id", pymongo.ASCENDING)],
        GITLAB_PROJECT_KEY_NAME,
        name=GITLAB_PROJECT_KEY_NAME,
        partialFilterExpression={
            "gitlab_instance_id": {MONGO_TYPE: "string"},
            "gitlab_project_id": {MONGO_TYPE: "number"},
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
    )  # Serves the released-only scan list.
    await database["scans"].create_index(
        [("project_id", pymongo.ASCENDING), *SCANS_TIP_SORT],
        name="scans_tag_builds",
        partialFilterExpression=TAG_BUILD_MATCH,
    )
    await database["scans"].create_index(
        "restored_at", name="scans_restored", partialFilterExpression=RESTORED_SCAN_MATCH
    )

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

    await database["distributed_locks"].create_index([("expires_at", pymongo.ASCENDING)], expireAfterSeconds=0)

    # TTL: drops blacklisted JWTs after they would have expired anyway.
    await database["token_blacklist"].create_index([("expires_at", pymongo.ASCENDING)], expireAfterSeconds=0)

    await database["gitlab_instances"].create_index("url", unique=True)
    await database["gitlab_instances"].create_index("name", unique=True)
    await database["gitlab_instances"].create_index("is_active")

    await database["github_instances"].create_index("url", unique=True)
    await database["github_instances"].create_index("name", unique=True)
    await database["github_instances"].create_index("is_active")

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

    await database["callgraphs"].create_index([("project_id", pymongo.ASCENDING), ("scan_id", pymongo.ASCENDING)])
    await database["callgraphs"].create_index([("project_id", pymongo.ASCENDING), ("pipeline_id", pymongo.ASCENDING)])
    await database["callgraphs"].create_index("graph_gridfs_id", sparse=True)
    # The type filter keeps pipeline-only uploads, whose scan_id is null, out of the uniqueness scope.
    await _create_unique_index(
        database["callgraphs"],
        [
            ("project_id", pymongo.ASCENDING),
            ("language", pymongo.ASCENDING),
            ("scan_id", pymongo.ASCENDING),
        ],
        "callgraphs (project_id, language, scan_id)",
        partialFilterExpression={"scan_id": {MONGO_TYPE: "string"}},
    )

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

    await database["dependency_enrichments"].create_index("purl", unique=True)

    await database["archive_metadata"].create_index("scan_id", unique=True)
    await database["archive_metadata"].create_index(
        [("project_id", pymongo.ASCENDING), ("archived_at", pymongo.DESCENDING)]
    )
    await database["archive_metadata"].create_index(
        [("project_id", pymongo.ASCENDING), ("branch", pymongo.ASCENDING), ("archived_at", pymongo.DESCENDING)]
    )
    await database["archive_metadata"].create_index([("archived_at", pymongo.DESCENDING)])

    chat_conversations = database["chat_conversations"]
    await chat_conversations.create_index(
        [("user_id", pymongo.ASCENDING), ("updated_at", pymongo.DESCENDING)],
        name="user_conversations_listing",
    )

    chat_messages = database["chat_messages"]
    await chat_messages.create_index(
        [("conversation_id", pymongo.ASCENDING), ("created_at", pymongo.ASCENDING)],
        name="conversation_messages_chronological",
    )

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
    await api_keys.create_index(
        [("expires_at", pymongo.ASCENDING)],
        name="api_keys_ttl",
        expireAfterSeconds=0,
    )

    await database["crypto_assets"].create_index([("project_id", pymongo.ASCENDING), ("name", pymongo.ASCENDING)])
    await database["crypto_assets"].create_index([("project_id", pymongo.ASCENDING), ("primitive", pymongo.ASCENDING)])
    await database["crypto_assets"].create_index(
        [("project_id", pymongo.ASCENDING), ("scan_id", pymongo.ASCENDING), ("bom_ref", pymongo.ASCENDING)],
        unique=True,
    )
    await database["crypto_assets"].create_index(
        [("project_id", pymongo.ASCENDING), ("asset_type", pymongo.ASCENDING), ("primitive", pymongo.ASCENDING)]
    )

    await database["crypto_policies"].create_index(
        [("scope", pymongo.ASCENDING), ("project_id", pymongo.ASCENDING)], unique=True
    )

    # PolicyAuditRepository's entries live in crypto_policy_history.
    await database["crypto_policy_history"].create_index(
        [
            ("policy_type", pymongo.ASCENDING),
            ("policy_scope", pymongo.ASCENDING),
            ("project_id", pymongo.ASCENDING),
            ("version", pymongo.DESCENDING),
        ]
    )
    await database["crypto_policy_history"].create_index([("timestamp", pymongo.DESCENDING)])

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

    # Crypto trends read findings by type and scan date across projects; no other index bounds that read.
    await database["findings"].create_index([("type", pymongo.ASCENDING), ("scan_created_at", pymongo.ASCENDING)])

    logger.info("Database indexes created successfully.")


async def init_db() -> None:
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
