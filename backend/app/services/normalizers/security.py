from typing import Any, Dict, Optional, TYPE_CHECKING

from app.models.finding import Finding, FindingType, Severity
from app.services.normalizers.utils import build_finding_id, safe_get

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator


def normalize_malware(aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None):
    """
    Normalize malware findings from the OpenSourceMalware.com API (os_malware scanner).
    Note: OpenSSF malware data comes through OSV scanner and is handled by _normalize_osv_malware.
    """
    for item in result.get("malware_issues") or []:
        malware_info = item.get("malware_info") or {}
        threats = malware_info.get("threats") or []
        component = safe_get(item, "component", "unknown")
        version = item.get("version")

        description = "Potential malware detected"
        if isinstance(threats, list) and threats:
            if isinstance(threats[0], str):
                threat_list = threats[:5]
                description = f"Malware detected: {', '.join(threat_list)}"
                if len(threats) > 5:
                    description += f" (+{len(threats) - 5} more)"
        elif malware_info.get("description"):
            description = f"Malware detected: {malware_info.get('description')}"

        aggregator.add_finding(
            Finding(
                id=build_finding_id("MALWARE", component),
                type=FindingType.MALWARE,
                severity=Severity.CRITICAL,
                component=component,
                version=version,
                description=description,
                scanners=["os_malware"],
                details={
                    "info": malware_info,
                    "threats": threats,
                    "reference": malware_info.get("reference"),
                    "source": "opensourcemalware",
                },
            ),
            source=source,
        )


def normalize_hash_verification(aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None):
    """Normalize hash verification results into findings."""
    for item in result.get("hash_issues") or []:
        component = safe_get(item, "component", "unknown")
        algorithm = safe_get(item, "algorithm", "unknown")
        version = item.get("version")

        aggregator.add_finding(
            Finding(
                id=build_finding_id("HASH", component, algorithm),
                type=FindingType.MALWARE,  # Hash mismatch is a serious supply chain issue
                severity=Severity.CRITICAL,
                component=component,
                version=version,
                description=f"Package integrity check failed! {item.get('message') or 'Hash mismatch detected'}",
                scanners=["hash_verification"],
                details={
                    "registry": item.get("registry"),
                    "algorithm": algorithm,
                    "sbom_hash": item.get("sbom_hash"),
                    "expected_hashes": item.get("expected_hashes") or [],
                    "verification_failed": True,
                },
            ),
            source=source,
        )
