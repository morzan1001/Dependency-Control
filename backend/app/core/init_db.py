import logging
import secrets
from typing import Any

import pymongo
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.metrics import update_db_stats
from app.core.permissions import ALL_PERMISSIONS
from app.core.security import get_password_hash
from app.db.mongodb import get_database
from app.models.user import User
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
SCANS_TIP_SORT: list[tuple[str, int]] = [("created_at", pymongo.DESCENDING), ("_id", pymongo.ASCENDING)]
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
_TIE_BREAK_INDEXES: tuple[tuple[str, list[tuple[str, int]]], ...] = (
    ("scans", SCANS_TIP_INDEX_KEY),
    ("releases", RELEASES_LATEST_LOOKUP_KEY),
)


async def _migrate_tie_break_indexes(database: AsyncIOMotorDatabase[Any]) -> None:
    """Drop the date-only ancestor of each tie-break index.

    Mongo rejects a key change under an existing index name, and an ancestor left behind is a
    second index every write to the collection has to maintain for no additional plan.
    """
    for collection_name, key in _TIE_BREAK_INDEXES:
        collection = database[collection_name]
        ancestor = [(field, direction) for field, direction in key if field != "_id"]
        for idx_name, idx_info in (await collection.index_information()).items():
            if [tuple(pair) for pair in idx_info.get("key", [])] == ancestor:
                logger.info(f"Dropping index superseded by the {collection_name} tie-break key: {idx_name}")
                await collection.drop_index(idx_name)


async def _migrate_project_indexes(database: AsyncIOMotorDatabase[Any]) -> None:
    """Drop old sparse GitLab/GitHub project indexes; sparse compound indexes still collide on
    explicit null (Pydantic serializes None), so they are rebuilt with partialFilterExpression."""
    projects_collection = database["projects"]
    existing_indexes = await projects_collection.index_information()

    for idx_name, idx_info in existing_indexes.items():
        key = idx_info.get("key", [])
        is_sparse = idx_info.get("sparse", False)

        if key == [("gitlab_instance_id", 1), ("gitlab_project_id", 1)] and is_sparse:
            logger.info(f"Dropping old sparse GitLab index: {idx_name}")
            await projects_collection.drop_index(idx_name)

        if key == [("github_instance_id", 1), ("github_repository_id", 1)] and is_sparse:
            logger.info(f"Dropping old sparse GitHub index: {idx_name}")
            await projects_collection.drop_index(idx_name)


_SYNCED_TEAM_NAME_PREFIX = "GitLab Group: "


async def _backfill_synced_team_gitlab_ids(database: AsyncIOMotorDatabase[Any]) -> None:
    """Idempotent backfill of gitlab_instance_id onto legacy synced teams that predate the
    (gitlab_instance_id, gitlab_group_id) composite key, so the next sync re-matches them
    instead of orphaning them.

    Only stamps gitlab_instance_id, and only when the team's linked projects resolve to
    exactly one non-null GitLab instance (otherwise ambiguous — left untouched). The numeric
    gitlab_group_id isn't stored locally and is left for the next live sync to fill.
    """
    teams = database["teams"]
    projects = database["projects"]

    cursor = teams.find(
        {"name": {"$regex": f"^{_SYNCED_TEAM_NAME_PREFIX}"}},
        {"_id": 1, "name": 1, "gitlab_instance_id": 1, "gitlab_group_id": 1},
    )
    legacy_teams = await cursor.to_list(None)

    stamped = 0
    skipped = 0
    failed = 0
    for team in legacy_teams:
        team_id = team.get("_id")
        # Isolate per-team failures: this runs before index creation, so an unhandled
        # raise here would crash startup for every other team.
        try:
            # Idempotency: anything already tagged with an instance is left alone.
            if team.get("gitlab_instance_id"):
                continue

            linked = await projects.find({"team_id": team_id}, {"gitlab_instance_id": 1}).to_list(None)
            instance_ids = {p.get("gitlab_instance_id") for p in linked if p.get("gitlab_instance_id")}

            if len(instance_ids) != 1:
                skipped += 1
                logger.warning(
                    "Backfill: legacy synced team %s (%r) is ambiguous — linked projects "
                    "resolve to %d distinct GitLab instances (%s). Leaving it untouched; it "
                    "will be re-tagged on the next live sync or must be reconciled manually.",
                    team_id,
                    team.get("name"),
                    len(instance_ids),
                    sorted(instance_ids) or "none",
                )
                continue

            (instance_id,) = tuple(instance_ids)
            await teams.update_one({"_id": team_id}, {"$set": {"gitlab_instance_id": instance_id}})
            stamped += 1
            logger.info(
                "Backfill: stamped gitlab_instance_id=%s onto legacy synced team %s (%r). "
                "gitlab_group_id remains unset and will be filled by the next live sync.",
                instance_id,
                team_id,
                team.get("name"),
            )
        except Exception:
            failed += 1
            logger.exception(
                "Backfill: failed to process legacy synced team %s; skipping it and "
                "continuing with the rest. It can be reconciled on the next live sync.",
                team_id,
            )
            continue

    if legacy_teams:
        logger.info(
            "Backfill complete: %d legacy synced team(s) stamped with an instance id, "
            "%d left for live re-sync, %d failed and skipped.",
            stamped,
            skipped,
            failed,
        )


async def _backfill_member_and_team_provenance(database: AsyncIOMotorDatabase[Any]) -> None:
    """Idempotent provenance backfill: stamp team_source="gitlab" on projects linked to a
    gitlab-synced team, but only where team_source is unset (never overwrite "manual").

    Members are intentionally left unstamped: stamping existing members "gitlab" would put
    manually-added members inside the gitlab subset the next sync's merge replaces, silently
    removing them. Unstamped members default to "manual" on read, which the merge preserves.
    """
    teams = database["teams"]
    projects = database["projects"]

    # A synced team is identified by a non-null gitlab_group_id. $ne null excludes
    # both manual teams (field absent) and teams with an explicit null.
    cursor = teams.find(
        {"gitlab_group_id": {"$ne": None}},
        {"_id": 1, "gitlab_group_id": 1},
    )
    synced_teams = await cursor.to_list(None)

    projects_stamped = 0
    failed = 0
    for team in synced_teams:
        team_id = team.get("_id")
        # Per-team isolation: this runs before index creation, so an unhandled raise
        # would crash startup for every other team/project.
        try:
            if not team.get("gitlab_group_id"):
                continue

            # $nin matches both missing fields and null, so already-stamped projects
            # ("manual" or "gitlab") are left untouched.
            result = await projects.update_many(
                {"team_id": team_id, "team_source": {"$nin": ["manual", "gitlab"]}},
                {"$set": {"team_source": "gitlab"}},
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
            "Provenance backfill complete: %d project(s) stamped team_source=gitlab "
            "across %d synced team(s), %d team(s) failed and skipped. "
            "(Members intentionally left unstamped so manually-added members survive merges.)",
            projects_stamped,
            len(synced_teams),
            failed,
        )


async def create_indexes(database: AsyncIOMotorDatabase[Any]) -> None:
    """Create indexes for all collections."""
    logger.info("Creating database indexes...")

    await _migrate_project_indexes(database)
    await _migrate_tie_break_indexes(database)
    # Reconcile legacy synced teams BEFORE creating the unique team index, so the
    # index build does not trip over partially-tagged data.
    await _backfill_synced_team_gitlab_ids(database)
    # Runs after the instance-id backfill so teams that just gained their instance id are included.
    await _backfill_member_and_team_provenance(database)

    # Users
    await database["users"].create_index("username", unique=True)
    await database["users"].create_index("email", unique=True)

    # Projects
    await database["projects"].create_index("owner_id")
    await database["projects"].create_index("team_id")
    await database["projects"].create_index("team_ids")
    await database["projects"].create_index("name")
    await database["projects"].create_index("members.user_id")

    # Teams
    await database["teams"].create_index("members.user_id")
    # Uniqueness scoped to teams carrying BOTH fields via partialFilterExpression:
    # MongoDB sparse compound indexes still collide on explicit null, so the type
    # filter is required to exclude manual teams (both fields null/absent).
    # Guarded so a pre-existing duplicate can't crash startup into CrashLoopBackOff —
    # the offending key is logged and the index skipped, degrading gracefully.
    try:
        await database["teams"].create_index(
            [("gitlab_instance_id", pymongo.ASCENDING), ("gitlab_group_id", pymongo.ASCENDING)],
            unique=True,
            partialFilterExpression={
                "gitlab_instance_id": {MONGO_TYPE: "string"},
                "gitlab_group_id": {MONGO_TYPE: "int"},
            },
        )
    except (pymongo.errors.DuplicateKeyError, pymongo.errors.OperationFailure) as exc:
        key_info = getattr(exc, "details", None) or str(exc)
        logger.error(
            "Skipping unique teams (gitlab_instance_id, gitlab_group_id) index: build "
            "failed (likely a pre-existing duplicate). Startup continues without it; "
            "reconcile the duplicate and re-run. Offending key/error: %s",
            key_info,
        )

    # Same $type filter as the GitLab index above: teams carrying an explicit null in both
    # fields must stay out of the unique scope, or the second manual team is a duplicate key.
    # "number", not "int": pymongo encodes an id >= 2**31 as BSON long, which "int" exempts.
    try:
        await database["teams"].create_index(
            [("github_instance_id", pymongo.ASCENDING), ("github_team_id", pymongo.ASCENDING)],
            unique=True,
            partialFilterExpression={
                "github_instance_id": {MONGO_TYPE: "string"},
                "github_team_id": {MONGO_TYPE: "number"},
            },
        )
    except pymongo.errors.OperationFailure as exc:
        # Named "response" rather than "details": the Finding.details contract test reads any
        # local of that name as a finding-details access.
        response = exc.details or {}
        logger.error(
            "Skipping unique teams (github_instance_id, github_team_id) index, build failed "
            "with %s; the key stays unenforced until it is built. Server response: %s",
            response.get("codeName", type(exc).__name__),
            response or exc,
        )

    # Scans
    await database["scans"].create_index("pipeline_id")
    await database["scans"].create_index([("created_at", pymongo.DESCENDING)])
    await database["scans"].create_index([("project_id", pymongo.ASCENDING), ("created_at", pymongo.DESCENDING)])

    # Analysis Results
    await database["analysis_results"].create_index("scan_id")
    await database["analysis_results"].create_index(
        [("scan_id", pymongo.ASCENDING), ("analyzer_name", pymongo.ASCENDING)]
    )

    # Waivers
    await database["waivers"].create_index("project_id")
    await database["waivers"].create_index("expiration_date")
    await database["waivers"].create_index([("project_id", pymongo.ASCENDING), ("expiration_date", pymongo.DESCENDING)])

    # Dependencies
    await database["dependencies"].create_index("name")
    await database["dependencies"].create_index("purl")
    # Unique key permits idempotent upserts during concurrent SBOM ingestion.
    await database["dependencies"].create_index(
        [
            ("scan_id", pymongo.ASCENDING),
            ("name", pymongo.ASCENDING),
            ("version", pymongo.ASCENDING),
            ("purl", pymongo.ASCENDING),
        ],
        unique=True,
        sparse=True,  # null purl is permitted, won't conflict on uniqueness
    )
    await database["dependencies"].create_index([("project_id", pymongo.ASCENDING), ("name", pymongo.ASCENDING)])
    await database["dependencies"].create_index([("scan_id", pymongo.ASCENDING), ("name", pymongo.ASCENDING)])
    await database["dependencies"].create_index([("scan_id", pymongo.ASCENDING), ("direct", pymongo.ASCENDING)])

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
    await database["findings"].create_index("type")
    await database["findings"].create_index("finding_id")  # Logical CVE id, not _id.
    await database["findings"].create_index([("scan_id", pymongo.ASCENDING), ("severity", pymongo.DESCENDING)])

    # Finding Records
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
    await database["scans"].create_index([("project_id", pymongo.ASCENDING), ("status", pymongo.ASCENDING)])
    await database["scans"].create_index(SCANS_TIP_INDEX_KEY)
    await database["scans"].create_index(
        [
            ("project_id", pymongo.ASCENDING),
            ("branch", pymongo.ASCENDING),
            ("created_at", pymongo.DESCENDING),
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

    await database["findings"].create_index([("created_at", pymongo.DESCENDING)])
    await database["findings"].create_index([("scan_id", pymongo.ASCENDING), ("waived", pymongo.ASCENDING)])
    # _STATS_CURSOR_HINT hints this exact key pattern; an unsatisfiable hint errors, so without
    # this index every stats read fails rather than falling back to a scan.
    await database["findings"].create_index([("scan_id", pymongo.ASCENDING), ("type", pymongo.ASCENDING)])
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

    await database["dependencies"].create_index(
        [
            ("scan_id", pymongo.ASCENDING),
            ("name", pymongo.ASCENDING),
            ("version", pymongo.ASCENDING),
        ]
    )

    await database["waivers"].create_index("finding_id")
    await database["waivers"].create_index("package_name")

    await database["webhooks"].create_index("project_id")
    await database["webhooks"].create_index(
        [("is_active", pymongo.ASCENDING), ("circuit_breaker_until", pymongo.ASCENDING)]
    )
    await database["webhooks"].create_index([("project_id", pymongo.ASCENDING), ("is_active", pymongo.ASCENDING)])
    await database["webhooks"].create_index("events")

    await database["webhook_deliveries"].create_index(
        [("webhook_id", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)]
    )
    await database["webhook_deliveries"].create_index(
        [("success", pymongo.ASCENDING), ("webhook_id", pymongo.ASCENDING)]
    )
    # TTL: drops deliveries after 30 days.
    await database["webhook_deliveries"].create_index([("timestamp", pymongo.ASCENDING)], expireAfterSeconds=2592000)

    # TTL: auto-cleans expired distributed locks.
    await database["distributed_locks"].create_index([("expires_at", pymongo.ASCENDING)], expireAfterSeconds=0)

    await database["token_blacklist"].create_index("jti", unique=True)
    # TTL: drops blacklisted JWTs after they would have expired anyway.
    await database["token_blacklist"].create_index([("expires_at", pymongo.ASCENDING)], expireAfterSeconds=0)

    # GitLab Instances
    await database["gitlab_instances"].create_index("url", unique=True)
    await database["gitlab_instances"].create_index("name", unique=True)
    await database["gitlab_instances"].create_index("is_active")
    await database["gitlab_instances"].create_index("is_default")

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

    # Invitations (InvitationRepository stores project invitations in "invitations").
    await database["invitations"].create_index("token", unique=True)
    await database["invitations"].create_index("email")

    # Archive Metadata
    await database["archive_metadata"].create_index("project_id")
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
    await chat_messages.create_index(
        [("conversation_id", pymongo.ASCENDING)],
        name="conversation_cascade_delete",
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
    await database["crypto_assets"].create_index([("project_id", pymongo.ASCENDING), ("scan_id", pymongo.ASCENDING)])
    await database["crypto_assets"].create_index([("project_id", pymongo.ASCENDING), ("asset_type", pymongo.ASCENDING)])
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

    # Findings: scan_created_at analytics indexes
    await database["findings"].create_index([("project_id", pymongo.ASCENDING), ("scan_created_at", pymongo.ASCENDING)])
    await database["findings"].create_index([("type", pymongo.ASCENDING), ("scan_created_at", pymongo.ASCENDING)])

    # Serves historical_first_seen (days_known): (component, version, type) prefix locates a vuln's
    # rows, trailing scan_created_at lets $group take the earliest with an index min ($first).
    await database["findings"].create_index(
        [
            ("component", pymongo.ASCENDING),
            ("version", pymongo.ASCENDING),
            ("type", pymongo.ASCENDING),
            ("scan_created_at", pymongo.ASCENDING),
        ]
    )

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
