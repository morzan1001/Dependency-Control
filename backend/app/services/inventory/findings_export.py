"""Row builder for the multi-branch findings CSV export."""

from collections.abc import AsyncIterator
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import DETAILS_KEY_IN_KEV
from app.models.finding import FindingType, Severity
from app.models.project import Scan
from app.repositories.findings import FindingRepository

FINDINGS_COLUMNS = [
    "branch", "scan_date", "commit",
    "finding_id", "type", "severity", "title",
    "component", "version", "purl", "direct", "locations",
    "epss_score", "epss_percentile", "kev", "reachable", "exploit_maturity",
    "fixed_version", "recommendation", "license", "license_category",
    "scanners", "waived", "waiver_reason", "cve_aliases",
]

_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
    Severity.NEGLIGIBLE, Severity.INFO, Severity.UNKNOWN,
]

_PROJECTION = {
    "finding_id": 1, "type": 1, "severity": 1, "description": 1,
    "component": 1, "version": 1, "purl": 1, "direct": 1,
    "found_in": 1, "locations": 1, "scanners": 1, "aliases": 1,
    "waived": 1, "waiver_reason": 1,
    "details.epss_score": 1, "details.epss_percentile": 1,
    f"details.{DETAILS_KEY_IN_KEV}": 1, "details.exploit_maturity": 1,
    "details.reachability.reachable": 1, "details.fixed_version": 1,
    "details.recommendation": 1, "details.license": 1, "details.category": 1,
}


def _row(scan: Scan, doc: dict[str, Any]) -> dict[str, Any]:
    details = doc.get("details") or {}
    is_vuln = doc.get("type") == FindingType.VULNERABILITY.value
    is_license = doc.get("type") == FindingType.LICENSE.value
    return {
        "branch": scan.branch,
        "scan_date": scan.created_at,
        "commit": scan.commit_hash,
        "finding_id": doc.get("finding_id"),
        "type": doc.get("type"),
        "severity": doc.get("severity"),
        "title": doc.get("description"),
        "component": doc.get("component"),
        "version": doc.get("version"),
        "purl": doc.get("purl"),
        "direct": doc.get("direct"),
        "locations": doc.get("found_in") or doc.get("locations") or [],
        "epss_score": details.get("epss_score") if is_vuln else None,
        "epss_percentile": details.get("epss_percentile") if is_vuln else None,
        "kev": bool(details.get(DETAILS_KEY_IN_KEV, False)) if is_vuln else None,
        "reachable": (details.get("reachability") or {}).get("reachable") if is_vuln else None,
        "exploit_maturity": details.get("exploit_maturity") if is_vuln else None,
        "fixed_version": details.get("fixed_version"),
        "recommendation": details.get("recommendation"),
        "license": details.get("license") if is_license else None,
        "license_category": details.get("category") if is_license else None,
        "scanners": doc.get("scanners") or [],
        "waived": doc.get("waived", False),
        "waiver_reason": doc.get("waiver_reason"),
        "cve_aliases": doc.get("aliases") or [],
    }


async def iter_findings_rows(db: AsyncIOMotorDatabase, scans: list[Scan]) -> AsyncIterator[dict[str, Any]]:
    collection = FindingRepository(db).collection
    for scan in scans:
        # One query per severity bucket keeps streaming order without an in-memory sort.
        for severity in _SEVERITY_ORDER:
            cursor = collection.find(
                {"scan_id": scan.id, "severity": severity.value}, _PROJECTION
            ).sort([("type", 1), ("finding_id", 1)])
            async for doc in cursor:
                yield _row(scan, doc)
