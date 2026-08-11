"""License aggregation over a scan's dependencies."""

from collections.abc import AsyncIterator
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.project import Scan
from app.repositories.dependencies import DependencyRepository
from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.schemas.inventory import LicenseItem
from app.services.analyzers.license_compliance.normalizer import tokenize_license_string

LICENSE_COLUMNS = ["license", "category", "risks", "component_count", "components"]

UNKNOWN_LICENSE = "unknown"
# Category/risks are identical for every package under the same SPDX id;
# a handful of sample purls per license is enough for the enrichment lookup.
_SAMPLE_PURLS_PER_LICENSE = 5


def _add_to_group(
    groups: dict[str, dict[str, Any]],
    license_id: str,
    component: str,
    purl: str | None,
    category: str | None,
    risks: list[str] | None,
    single_token: bool,
) -> None:
    group = groups.setdefault(
        license_id, {"components": [], "component_names": set(), "purls": [], "category": None, "risks": []}
    )
    if component not in group["component_names"]:
        group["component_names"].add(component)
        group["components"].append(component)
    # A composite expression's purl reflects the worst-member license, not any single token,
    # so it must not seed the enrichment lookup for its constituent groups.
    if single_token and purl and len(group["purls"]) < _SAMPLE_PURLS_PER_LICENSE:
        group["purls"].append(purl)
    group["category"] = group["category"] or category
    for risk in risks or []:
        if risk not in group["risks"]:
            group["risks"].append(risk)


def _aggregate_category_risks(group: dict[str, Any], enrichment: dict[str, Any]) -> tuple[str | None, list[str]]:
    category = group["category"]
    risks: list[str] = list(group["risks"])
    if category and risks:
        return category, risks
    for purl in group["purls"]:
        doc = enrichment.get(purl)
        if not doc:
            continue
        category = category or doc.get("license_category")
        for risk in doc.get("license_risks") or []:
            if risk not in risks:
                risks.append(risk)
    return category, risks


async def build_license_rows(db: AsyncIOMotorDatabase, scan: Scan) -> list[LicenseItem]:
    groups: dict[str, dict[str, Any]] = {}
    cursor = DependencyRepository(db).collection.find(
        {"scan_id": scan.id},
        {"name": 1, "version": 1, "license": 1, "purl": 1, "license_category": 1, "license_risks": 1},
    )
    async for doc in cursor:
        tokens = tokenize_license_string(doc.get("license") or "") or [UNKNOWN_LICENSE]
        component = f"{doc.get('name')}@{doc.get('version')}"
        single_token = len(tokens) == 1
        for license_id in tokens:
            _add_to_group(
                groups,
                license_id,
                component,
                doc.get("purl"),
                doc.get("license_category"),
                doc.get("license_risks"),
                single_token,
            )

    # Skip the enrichment lookup entirely for groups the dependency docs already fully cover.
    sample_purls = [p for g in groups.values() if not g["category"] or not g["risks"] for p in g["purls"]]
    enrichment = await DependencyEnrichmentRepository(db).get_many_by_purls(sample_purls)

    items: list[LicenseItem] = []
    for license_id, group in groups.items():
        category, risks = _aggregate_category_risks(group, enrichment)
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
