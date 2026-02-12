#!/usr/bin/env python3
"""
Migration script: Single GitLab Instance → Multi-Instance Support

Migrates existing single-instance GitLab configuration to multi-instance architecture.

Steps:
1. Read current GitLab configuration from SystemSettings
2. Create a default GitLabInstance from existing settings
3. Update all projects with gitlab_project_id to reference the new instance
4. Create database indexes
5. Optionally clean up old SystemSettings fields

Usage:
    python scripts/migrate_to_multi_instance.py [--dry-run] [--cleanup-settings]
"""

import asyncio
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from motor.motor_asyncio import AsyncIOMotorClient
import pymongo

from app.core.config import settings
from app.models.gitlab_instance import GitLabInstance

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


async def create_gitlab_indexes(db):
    """Create indexes for gitlab_instances and update projects indexes."""
    logger.info("Creating database indexes...")

    # GitLab Instances indexes
    await db.gitlab_instances.create_index("url", unique=True)
    await db.gitlab_instances.create_index("name", unique=True)
    await db.gitlab_instances.create_index("is_active")
    await db.gitlab_instances.create_index("is_default")
    logger.info("✓ Created gitlab_instances indexes")

    # Projects: Compound index for (gitlab_instance_id, gitlab_project_id)
    await db.projects.create_index(
        [("gitlab_instance_id", pymongo.ASCENDING), ("gitlab_project_id", pymongo.ASCENDING)],
        unique=True,
        sparse=True  # Allow null values (projects without GitLab integration)
    )
    await db.projects.create_index("gitlab_instance_id")
    logger.info("✓ Created projects compound indexes")


async def migrate_to_multi_instance(dry_run: bool = False, cleanup_settings: bool = False):
    """
    Main migration function.

    Args:
        dry_run: If True, only simulate the migration without making changes
        cleanup_settings: If True, remove old GitLab fields from SystemSettings
    """
    logger.info("=" * 80)
    logger.info("GitLab Multi-Instance Migration")
    logger.info("=" * 80)

    if dry_run:
        logger.warning("DRY RUN MODE - No changes will be made to the database")

    # Connect to MongoDB
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGODB_DB_NAME]

    try:
        # Test connection
        await client.admin.command('ping')
        logger.info(f"✓ Connected to MongoDB: {settings.MONGODB_DB_NAME}")
    except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
        logger.error(f"✗ Failed to connect to MongoDB: {e}")
        return False

    # Step 1: Load current SystemSettings
    logger.info("\n[1/6] Loading current SystemSettings...")
    system_settings = await db.system_settings.find_one({"_id": "current"})

    if not system_settings:
        logger.error("✗ SystemSettings not found in database")
        return False

    gitlab_enabled = system_settings.get("gitlab_integration_enabled", False)
    gitlab_url = system_settings.get("gitlab_url", "https://gitlab.com")
    gitlab_token = system_settings.get("gitlab_access_token")
    gitlab_oidc_audience = system_settings.get("gitlab_oidc_audience")
    gitlab_auto_create = system_settings.get("gitlab_auto_create_projects", False)
    gitlab_sync_teams = system_settings.get("gitlab_sync_teams", False)

    logger.info(f"  GitLab Integration Enabled: {gitlab_enabled}")
    logger.info(f"  GitLab URL: {gitlab_url}")
    logger.info(f"  Access Token Configured: {bool(gitlab_token)}")
    logger.info(f"  Auto-Create Projects: {gitlab_auto_create}")
    logger.info(f"  Sync Teams: {gitlab_sync_teams}")

    if not gitlab_enabled:
        logger.warning("⚠ GitLab integration is not enabled - migration will still create default instance")

    # Step 2: Check if migration already done
    logger.info("\n[2/6] Checking if migration already performed...")
    existing_instances = await db.gitlab_instances.count_documents({})

    if existing_instances > 0:
        logger.warning(f"⚠ Found {existing_instances} existing GitLab instances")
        logger.info("Migration may have already been performed. Checking projects...")

        projects_with_instance_id = await db.projects.count_documents({
            "gitlab_instance_id": {"$ne": None}
        })
        projects_with_project_id = await db.projects.count_documents({
            "gitlab_project_id": {"$ne": None}
        })
        orphaned = projects_with_project_id - projects_with_instance_id

        if orphaned == 0:
            logger.info("✓ All projects already have gitlab_instance_id")
            logger.info("Migration appears complete. Use --force to re-run if needed.")
            return True

        logger.warning(f"⚠ Found {orphaned} orphaned projects (gitlab_project_id but no gitlab_instance_id)")
        logger.info("Will continue migration to fix orphaned projects...")

    # Step 3: Create default GitLab instance
    logger.info("\n[3/6] Creating default GitLab instance...")

    instance_id = str(uuid.uuid4())
    default_instance = {
        "_id": instance_id,
        "name": "Default GitLab",
        "url": gitlab_url.rstrip("/"),
        "description": "Migrated from single-instance configuration",
        "access_token": gitlab_token,
        "oidc_audience": gitlab_oidc_audience,
        "auto_create_projects": gitlab_auto_create,
        "sync_teams": gitlab_sync_teams,
        "is_active": gitlab_enabled,
        "is_default": True,
        "created_by": "migration",
        "created_at": datetime.now(timezone.utc),
        "last_modified_at": None,
    }

    if not dry_run:
        # Check if instance with this URL already exists
        existing = await db.gitlab_instances.find_one({"url": default_instance["url"]})
        if existing:
            logger.warning(f"⚠ Instance with URL '{default_instance['url']}' already exists")
            instance_id = str(existing["_id"])
            logger.info(f"  Using existing instance ID: {instance_id}")
        else:
            await db.gitlab_instances.insert_one(default_instance)
            logger.info(f"✓ Created default GitLab instance: {instance_id}")
    else:
        logger.info(f"[DRY RUN] Would create instance: {default_instance['name']} ({default_instance['url']})")

    # Step 4: Update projects with gitlab_project_id
    logger.info("\n[4/6] Updating projects with gitlab_instance_id...")

    projects_to_update = await db.projects.count_documents({
        "gitlab_project_id": {"$ne": None},
        "gitlab_instance_id": None
    })

    logger.info(f"  Found {projects_to_update} projects to update")

    if projects_to_update > 0:
        if not dry_run:
            result = await db.projects.update_many(
                {"gitlab_project_id": {"$ne": None}, "gitlab_instance_id": None},
                {"$set": {"gitlab_instance_id": instance_id}}
            )
            logger.info(f"✓ Updated {result.modified_count} projects")

            if result.modified_count != projects_to_update:
                logger.warning(f"⚠ Expected to update {projects_to_update} but only updated {result.modified_count}")
        else:
            logger.info(f"[DRY RUN] Would update {projects_to_update} projects")
    else:
        logger.info("  No projects to update")

    # Step 5: Create indexes
    logger.info("\n[5/6] Creating database indexes...")

    if not dry_run:
        try:
            await create_gitlab_indexes(db)
            logger.info("✓ Indexes created successfully")
        except pymongo.errors.OperationFailure as e:
            logger.warning(f"⚠ Error creating indexes (may already exist): {e}")
    else:
        logger.info("[DRY RUN] Would create database indexes")

    # Step 6: Validate migration
    logger.info("\n[6/6] Validating migration...")

    # Check for orphaned projects
    orphaned_projects = await db.projects.count_documents({
        "gitlab_project_id": {"$ne": None},
        "gitlab_instance_id": None
    })

    if orphaned_projects > 0:
        logger.error(f"✗ Migration incomplete: {orphaned_projects} orphaned projects remain")
        return False

    # Check instance count
    total_instances = await db.gitlab_instances.count_documents({})
    logger.info(f"  Total GitLab instances: {total_instances}")

    # Check project counts
    total_projects = await db.projects.count_documents({})
    gitlab_projects = await db.projects.count_documents({"gitlab_project_id": {"$ne": None}})
    logger.info(f"  Total projects: {total_projects}")
    logger.info(f"  GitLab-linked projects: {gitlab_projects}")

    # Optional: Clean up old SystemSettings fields
    if cleanup_settings:
        logger.info("\n[Cleanup] Removing old GitLab fields from SystemSettings...")

        if not dry_run:
            result = await db.system_settings.update_one(
                {"_id": "current"},
                {
                    "$unset": {
                        "gitlab_url": "",
                        "gitlab_access_token": "",
                        "gitlab_oidc_audience": "",
                        "gitlab_auto_create_projects": "",
                        "gitlab_sync_teams": "",
                    }
                }
            )
            if result.modified_count > 0:
                logger.info("✓ Removed old GitLab fields from SystemSettings")
            else:
                logger.warning("⚠ SystemSettings not modified (fields may not exist)")
        else:
            logger.info("[DRY RUN] Would remove old GitLab fields from SystemSettings")

        logger.warning("⚠ Note: gitlab_integration_enabled flag is kept for global toggle")

    logger.info("\n" + "=" * 80)
    logger.info("✓ Migration completed successfully!")
    logger.info("=" * 80)

    # Summary
    logger.info("\nSummary:")
    logger.info(f"  - GitLab instances: {total_instances}")
    logger.info(f"  - Projects migrated: {gitlab_projects}")
    logger.info(f"  - Orphaned projects: {orphaned_projects}")

    if not dry_run:
        logger.info("\n⚠ IMPORTANT: Restart your application to apply changes")
    else:
        logger.info("\n⚠ This was a DRY RUN - no changes were made")
        logger.info("   Run without --dry-run to perform actual migration")

    await client.close()
    return True


async def rollback_migration():
    """
    Rollback migration (emergency use only).

    WARNING: This will remove all GitLabInstance data and unset gitlab_instance_id from projects.
    """
    logger.warning("=" * 80)
    logger.warning("ROLLBACK MIGRATION - USE WITH CAUTION")
    logger.warning("=" * 80)

    response = input("Are you sure you want to rollback? This will remove all GitLab instances. (yes/no): ")
    if response.lower() != "yes":
        logger.info("Rollback cancelled")
        return

    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGODB_DB_NAME]

    logger.info("Removing gitlab_instance_id from projects...")
    result = await db.projects.update_many(
        {},
        {"$unset": {"gitlab_instance_id": ""}}
    )
    logger.info(f"✓ Updated {result.modified_count} projects")

    logger.info("Deleting all GitLab instances...")
    result = await db.gitlab_instances.delete_many({})
    logger.info(f"✓ Deleted {result.deleted_count} instances")

    logger.info("✓ Rollback complete")

    await client.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Migrate to multi-GitLab-instance support")
    parser.add_argument("--dry-run", action="store_true", help="Simulate migration without making changes")
    parser.add_argument("--cleanup-settings", action="store_true", help="Remove old GitLab fields from SystemSettings")
    parser.add_argument("--rollback", action="store_true", help="Rollback migration (DANGEROUS)")

    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback_migration())
    else:
        success = asyncio.run(migrate_to_multi_instance(
            dry_run=args.dry_run,
            cleanup_settings=args.cleanup_settings
        ))
        sys.exit(0 if success else 1)
