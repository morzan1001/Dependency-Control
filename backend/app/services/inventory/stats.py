from collections import Counter

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.sorting import case_insensitive_key
from app.models.project import Project, Scan
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.dependencies import DependencyRepository
from app.schemas.inventory import InventoryScanContext, InventoryStatsResponse
from app.services.inventory.licenses import license_ids


def scan_context(scan: Scan) -> InventoryScanContext:
    return InventoryScanContext(
        scan_id=scan.id, branch=scan.branch, created_at=scan.created_at, commit_hash=scan.commit_hash
    )


async def build_inventory_stats(db: AsyncIOMotorDatabase, project: Project, scan: Scan) -> InventoryStatsResponse:
    deps = DependencyRepository(db)
    total = await deps.count({"scan_id": scan.id})
    direct = await deps.count({"scan_id": scan.id, "direct": True})
    licenses = await deps.collection.distinct("license", {"scan_id": scan.id})
    by_ecosystem: Counter[str] = Counter()
    for row in await deps.aggregate([{"$match": {"scan_id": scan.id}}, {"$group": {"_id": "$type", "n": {"$sum": 1}}}]):
        by_ecosystem[row["_id"] or "unknown"] += row["n"]
    ecosystems = sorted(by_ecosystem, key=lambda e: (-by_ecosystem[e], case_insensitive_key(e)))
    crypto_assets = CryptoAssetRepository(db)
    crypto_count = await crypto_assets.count_by_scan(project.id, scan.id)
    return InventoryStatsResponse(
        scan=scan_context(scan),
        components_total=total,
        direct_count=direct,
        transitive_count=total - direct,
        license_count=len({t for lic in licenses for t in license_ids(lic)}),
        ecosystem_count=len(ecosystems),
        ecosystems=ecosystems,
        crypto_asset_count=crypto_count,
        cbom_evaluated=scan.id in await crypto_assets.evaluated_scan_ids([project.id], [scan.id]),
    )
