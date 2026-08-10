"""Aggregated head-tile numbers for the inventory page."""

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.project import Project, Scan
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.dependencies import DependencyRepository
from app.schemas.inventory import InventoryScanContext, InventoryStatsResponse


def scan_context(scan: Scan) -> InventoryScanContext:
    return InventoryScanContext(
        scan_id=scan.id, branch=scan.branch, created_at=scan.created_at, commit_hash=scan.commit_hash
    )


async def build_inventory_stats(
    db: AsyncIOMotorDatabase, project: Project, scan: Scan
) -> InventoryStatsResponse:
    deps = DependencyRepository(db)
    total = await deps.count({"scan_id": scan.id})
    direct = await deps.count({"scan_id": scan.id, "direct": True})
    licenses = await deps.collection.distinct("license", {"scan_id": scan.id})
    ecosystems = await deps.collection.distinct("type", {"scan_id": scan.id})
    crypto_count = await CryptoAssetRepository(db).count_by_scan(project.id, scan.id)
    return InventoryStatsResponse(
        scan=scan_context(scan),
        components_total=total,
        direct_count=direct,
        transitive_count=total - direct,
        license_count=len([lic for lic in licenses if lic]),
        ecosystem_count=len([e for e in ecosystems if e]),
        crypto_asset_count=crypto_count,
    )
