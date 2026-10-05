"""Row builder for the multi-branch findings CSV export."""

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any, NamedTuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import DETAILS_KEY_IN_KEV
from app.core.cve import canonical_cves, display_vulnerability_id
from app.models.finding import FindingType, Severity
from app.repositories.dependencies import DependencyRepository
from app.repositories.findings import FindingRepository
from app.services.component_identity import build_component_index, lookup_component


class ExportedScan(NamedTuple):
    id: str
    branch: str
    created_at: datetime | None
    commit_hash: str | None


FINDINGS_COLUMNS = [
    "branch",
    "scan_date",
    "commit",
    "finding_id",
    "type",
    "severity",
    "title",
    "component",
    "version",
    "purl",
    "direct",
    "locations",
    "epss_score",
    "epss_percentile",
    "kev",
    "reachable",
    "exploit_maturity",
    "fixed_version",
    "recommendation",
    "license",
    "license_category",
    "scanners",
    "waived",
    "waiver_reason",
    "cves",
]

# Findings carry no top-level purl/direct; those come from the dependencies join below.
# `details.purl` is the license normalizer's nesting spot, used as a fallback.
_PROJECTION = {
    "finding_id": 1,
    "type": 1,
    "severity": 1,
    "description": 1,
    "component": 1,
    "version": 1,
    "found_in": 1,
    "scanners": 1,
    "waived": 1,
    "waiver_reason": 1,
    "details.epss_score": 1,
    "details.epss_percentile": 1,
    f"details.{DETAILS_KEY_IN_KEV}": 1,
    "details.exploit_maturity": 1,
    "details.reachability.is_reachable": 1,
    "details.fixed_version": 1,
    "details.recommendation": 1,
    "details.license": 1,
    "details.category": 1,
    "details.purl": 1,
    "details.vulnerabilities.id": 1,
    "details.vulnerabilities.aliases": 1,
    "details.vulnerabilities.resolved_cve": 1,
}

_DEP_PROJECTION = {"name": 1, "version": 1, "purl": 1, "direct": 1}

# version -> component index of (purl, direct); see build_component_index for the name rule
_DepLookup = dict[str, dict[str, tuple[str | None, bool | None]]]


def _row(scan: ExportedScan, doc: dict[str, Any], dep_lookup: _DepLookup) -> dict[str, Any]:
    details = doc.get("details") or {}
    is_vuln = doc.get("type") == FindingType.VULNERABILITY.value
    is_license = doc.get("type") == FindingType.LICENSE.value
    by_component = dep_lookup.get(str(doc.get("version")), {})
    dep_purl, direct = lookup_component(by_component, str(doc.get("component")), (None, None)) or (None, None)
    return {
        "branch": scan.branch,
        "scan_date": scan.created_at,
        "commit": scan.commit_hash,
        "finding_id": doc.get("finding_id"),
        "type": doc.get("type"),
        "severity": doc.get("severity"),
        "title": doc.get("description") or display_vulnerability_id(details),
        "component": doc.get("component"),
        "version": doc.get("version"),
        "purl": dep_purl or details.get("purl"),
        "direct": direct,
        "locations": doc.get("found_in") or [],
        "epss_score": details.get("epss_score") if is_vuln else None,
        "epss_percentile": details.get("epss_percentile") if is_vuln else None,
        "kev": bool(details.get(DETAILS_KEY_IN_KEV, False)) if is_vuln else None,
        "reachable": (details.get("reachability") or {}).get("is_reachable") if is_vuln else None,
        "exploit_maturity": details.get("exploit_maturity") if is_vuln else None,
        "fixed_version": details.get("fixed_version"),
        "recommendation": details.get("recommendation"),
        "license": details.get("license") if is_license else None,
        "license_category": details.get("category") if is_license else None,
        "scanners": doc.get("scanners") or [],
        "waived": doc.get("waived", False),
        "waiver_reason": doc.get("waiver_reason"),
        "cves": canonical_cves([details]),
    }


async def _dependency_lookup(db: AsyncIOMotorDatabase, scan: ExportedScan) -> _DepLookup:
    by_version: dict[str, dict[str, tuple[str | None, bool | None]]] = {}
    async for dep in DependencyRepository(db).iterate_raw({"scan_id": scan.id}, _DEP_PROJECTION):
        by_name = by_version.setdefault(str(dep.get("version")), {})
        name = str(dep.get("name"))
        # A name@version can hold several docs (purl-qualifier variants); on 60 sampled
        # multi-SBOM scans 1,635 such groups disagree on `direct`, so keeping whichever
        # the cursor yielded last made the exported column arbitrary. Direct wins.
        kept = by_name.get(name)
        if kept is not None and (kept[1] or not dep.get("direct")):
            continue
        by_name[name] = (dep.get("purl"), dep.get("direct"))
    return {version: build_component_index(names) for version, names in by_version.items()}


async def iter_findings_rows(db: AsyncIOMotorDatabase, scans: list[ExportedScan]) -> AsyncIterator[dict[str, Any]]:
    findings = FindingRepository(db)
    for scan in scans:
        dep_lookup = await _dependency_lookup(db, scan)
        # One query per severity, most severe first; the (scan_id, severity, type, finding_id) index
        # hands each bucket over in streaming order.
        for severity in Severity:
            query = {"scan_id": scan.id, "severity": severity.value}
            async for doc in findings.iterate_raw(query, _PROJECTION, [("type", 1), ("finding_id", 1)]):
                yield _row(scan, doc, dep_lookup)
