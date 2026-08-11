"""License aggregation over a scan's dependencies."""

from collections.abc import AsyncIterator
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.project import Scan
from app.repositories.dependencies import DependencyRepository
from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.schemas.inventory import LicenseItem

LICENSE_COLUMNS = ["license", "category", "risks", "component_count", "components"]

UNKNOWN_LICENSE = "unknown"
# Category/risks are identical for every package under the same SPDX id;
# a handful of sample purls per license is enough for the enrichment lookup.
_SAMPLE_PURLS_PER_LICENSE = 5


async def build_license_rows(db: AsyncIOMotorDatabase, scan: Scan) -> list[LicenseItem]:
    groups: dict[str, dict[str, Any]] = {}
    cursor = DependencyRepository(db).collection.find(
        {"scan_id": scan.id}, {"name": 1, "version": 1, "license": 1, "purl": 1}
    )
    async for doc in cursor:
        license_id = doc.get("license") or UNKNOWN_LICENSE
        group = groups.setdefault(license_id, {"components": [], "purls": []})
        group["components"].append(f"{doc.get('name')}@{doc.get('version')}")
        if doc.get("purl") and len(group["purls"]) < _SAMPLE_PURLS_PER_LICENSE:
            group["purls"].append(doc["purl"])

    sample_purls = [p for g in groups.values() for p in g["purls"]]
    enrichment = await DependencyEnrichmentRepository(db).get_many_by_purls(sample_purls)

    items: list[LicenseItem] = []
    for license_id, group in groups.items():
        category = None
        risks: list[str] = []
        for purl in group["purls"]:
            doc = enrichment.get(purl)
            if not doc:
                continue
            category = category or doc.get("license_category")
            for risk in doc.get("license_risks") or []:
                if risk not in risks:
                    risks.append(risk)
        items.append(
            LicenseItem(
                license=license_id,
                category=category,
                risks=risks,
                component_count=len(group["components"]),
                components=sorted(group["components"]),
            )
        )
    items.sort(key=lambda item: (-item.component_count, item.license))
    return items


async def iter_license_rows(db: AsyncIOMotorDatabase, scan: Scan) -> AsyncIterator[dict[str, Any]]:
    for item in await build_license_rows(db, scan):
        yield item.model_dump()
