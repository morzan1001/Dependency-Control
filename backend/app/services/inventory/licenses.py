"""License aggregation over a scan's dependencies."""

from collections import defaultdict
from collections.abc import AsyncIterator
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.project import Scan
from app.repositories.dependencies import DependencyRepository
from app.schemas.inventory import LicenseItem
from app.services.analyzers.license_compliance.analyzer import classify_license
from app.services.analyzers.license_compliance.normalizer import tokenize_license_string

LICENSE_COLUMNS = ["license", "category", "risks", "component_count", "components"]

UNKNOWN_LICENSE = "unknown"


def license_ids(raw: str | None) -> list[str]:
    """The license rows a component is listed under; one without a license is listed as unknown."""
    return tokenize_license_string(raw or "") or [UNKNOWN_LICENSE]


async def build_license_rows(db: AsyncIOMotorDatabase, scan: Scan) -> list[LicenseItem]:
    components: defaultdict[str, set[str]] = defaultdict(set)
    docs = DependencyRepository(db).iterate_raw({"scan_id": scan.id}, {"name": 1, "version": 1, "license": 1})
    async for doc in docs:
        for license_id in license_ids(doc.get("license")):
            components[license_id].add(f"{doc.get('name')}@{doc.get('version')}")

    items: list[LicenseItem] = []
    for license_id, names in components.items():
        info = classify_license(license_id)
        items.append(
            LicenseItem(
                license=license_id,
                category=info.category.value if info else None,
                risks=info.risks if info else [],
                component_count=len(names),
                components=sorted(names),
            )
        )
    items.sort(key=lambda item: (-item.component_count, item.license))
    return items


async def iter_license_rows(db: AsyncIOMotorDatabase, scan: Scan) -> AsyncIterator[dict[str, Any]]:
    for item in await build_license_rows(db, scan):
        yield item.model_dump()
