from typing import Any, Dict, Optional, TYPE_CHECKING
from app.models.finding import Finding, FindingType, Severity

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator


def normalize_malware(
    aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None
):
    """
    Normalize malware findings from the OpenSourceMalware.com API (os_malware scanner).
    Note: OpenSSF malware data comes through OSV scanner and is handled by _normalize_osv_malware.
    """
    for item in result.get("malware_issues", []):
        malware_info = item.get("malware_info", {})
        threats = malware_info.get("threats", [])

        description = "Potential malware detected"
        if isinstance(threats, list) and threats:
            if isinstance(threats[0], str):
                description = f"Malware detected: {', '.join(threats[:5])}"
                if len(threats) > 5:
                    description += f" (+{len(threats) - 5} more)"
        elif malware_info.get("description"):
            description = f"Malware detected: {malware_info.get('description')}"

        aggregator.add_finding(
            Finding(
                id=f"MALWARE-{item['component']}",
                type=FindingType.MALWARE,
                severity=Severity.CRITICAL,
                component=item.get("component"),
                version=item.get("version"),
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


def normalize_hash_verification(
    aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None
):
    """Normalize hash verification results into findings."""
    for item in result.get("hash_issues", []):
        aggregator.add_finding(
            Finding(
                id=f"HASH-{item['component']}-{item['algorithm']}",
                type=FindingType.MALWARE,  # Hash mismatch is a serious supply chain issue
                severity=Severity.CRITICAL,
                component=item.get("component"),
                version=item.get("version"),
                description=f"Package integrity check failed! {item.get('message', 'Hash mismatch detected')}",
                scanners=["hash_verification"],
                details={
                    "registry": item.get("registry"),
                    "algorithm": item.get("algorithm"),
                    "sbom_hash": item.get("sbom_hash"),
                    "expected_hashes": item.get("expected_hashes", []),
                    "verification_failed": True,
                },
            ),
            source=source,
        )
