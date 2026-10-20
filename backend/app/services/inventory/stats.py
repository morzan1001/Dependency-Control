import asyncio
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
    crypto_assets = CryptoAssetRepository(db)
    by_type, crypto_count, evaluated = await asyncio.gather(
        DependencyRepository(db).aggregate(
            [
                {"$match": {"scan_id": scan.id}},
                {
                    "$group": {
                        "_id": "$type",
                        "count": {"$sum": 1},
                        "direct": {"$sum": {"$cond": [{"$eq": ["$direct", True]}, 1, 0]}},
                        "licenses": {"$addToSet": "$license"},
                    }
                },
            ]
        ),
        crypto_assets.count_by_scan(project.id, scan.id),
        crypto_assets.evaluated_scan_ids([project.id], [scan.id]),
    )
    by_ecosystem: Counter[str] = Counter()
    for row in by_type:
        by_ecosystem[row["_id"] or "unknown"] += row["count"]
    ecosystems = sorted(by_ecosystem, key=lambda e: (-by_ecosystem[e], e == "unknown", case_insensitive_key(e)))
    total = by_ecosystem.total()
    direct = sum(row["direct"] for row in by_type)
    return InventoryStatsResponse(
        scan=scan_context(scan),
        components_total=total,
        direct_count=direct,
        transitive_count=total - direct,
        license_count=len({t for row in by_type for lic in row["licenses"] for t in license_ids(lic)}),
        ecosystem_count=len(ecosystems),
        ecosystems=ecosystems,
        crypto_asset_count=crypto_count,
        cbom_evaluated=scan.id in evaluated,
    )
