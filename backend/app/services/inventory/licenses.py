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
# Category and risks are identical for every package under the same SPDX id, so the first
# enrichment document found answers the whole group. The sample only decides how many purls
# one round trip tries before the walk falls back to the rest of them.
_FIRST_PASS_PURLS_PER_LICENSE = 5
# Bounds the width of one $in, not how far the walk goes.
_ENRICHMENT_LOOKUP_CHUNK = 500


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
        license_id,
        {
            "components": [],
            "component_names": set(),
            "purls": [],
            "purl_names": set(),
            "category": None,
            "risks": [],
        },
    )
    if component not in group["component_names"]:
        group["component_names"].add(component)
        group["components"].append(component)
    # A composite expression's purl reflects the worst-member license, not any single token,
    # so it must not seed the enrichment lookup for its constituent groups.
    if single_token and purl and purl not in group["purl_names"]:
        group["purl_names"].add(purl)
        group["purls"].append(purl)
    group["category"] = group["category"] or category
    for risk in risks or []:
        if risk not in group["risks"]:
            group["risks"].append(risk)


def _answered(group: dict[str, Any], enrichment: dict[str, dict[str, Any]]) -> bool:
    return any(purl in enrichment for purl in group["purls"])


async def _load_enrichment(
    repo: DependencyEnrichmentRepository,
    groups: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Enrichment documents for the groups the dependency rows left uncategorised.

    A first pass samples every such group in one round trip; only a license whose sample
    carries no enrichment at all walks the rest of its purls, so an uncategorised row means
    the estate has no answer rather than that the lookup stopped early.
    """
    pending = [group for group in groups.values() if not group["category"] or not group["risks"]]
    if not pending:
        return {}

    sample = [purl for group in pending for purl in group["purls"][:_FIRST_PASS_PURLS_PER_LICENSE]]
    enrichment = await repo.get_many_by_purls(sample)

    for group in pending:
        if _answered(group, enrichment):
            continue
        rest = group["purls"][_FIRST_PASS_PURLS_PER_LICENSE:]
        for start in range(0, len(rest), _ENRICHMENT_LOOKUP_CHUNK):
            found = await repo.get_many_by_purls(rest[start : start + _ENRICHMENT_LOOKUP_CHUNK])
            if found:
                enrichment.update(found)
                break

    return enrichment


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

    enrichment = await _load_enrichment(DependencyEnrichmentRepository(db), groups)

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
