"""
Ingest Helper Functions

Helper functions for ingest endpoints, extracted for better
code organization and reusability.
"""

from typing import Any, Dict

from app.services.aggregator import ResultAggregator
from app.services.scan_manager import ScanManager


async def process_findings_ingest(
    manager: ScanManager,
    analyzer_name: str,
    result_dict: Dict[str, Any],
    scan_id: str,
) -> Dict[str, Any]:
    """
    Common processing for findings-based ingests (TruffleHog, OpenGrep, KICS, Bearer).

    1. Normalize findings via aggregator
    2. Apply waivers
    3. Store results
    4. Compute stats
    5. Register result (does NOT trigger aggregation - waits for all scanners)
    6. Update project timestamp

    Returns response dict with scan_id, findings_count, and stats.

    Note: Unlike SBOM ingestion, findings-based scanners do NOT trigger
    the aggregation immediately. This prevents race conditions where a fast
    scanner (e.g., SAST) completes before slower scanners (e.g., SBOM),
    causing the scan to be marked as 'completed' prematurely.

    The aggregation is triggered either:
    - By the SBOM scanner (which typically runs last and is the "main" analysis)
    - By the housekeeping job if no new results arrive for a configured period
    """
    # Normalize findings
    aggregator = ResultAggregator()
    aggregator.aggregate(analyzer_name, result_dict)
    findings = aggregator.get_findings()

    # Apply waivers
    final_findings, waived_count = await manager.apply_waivers(findings)

    # Store results
    await manager.store_results(analyzer_name, result_dict, scan_id)

    # Compute stats
    stats = ScanManager.compute_stats(final_findings)

    # Register result WITHOUT triggering aggregation
    # This updates last_result_at and received_results, and resets status
    # to 'pending' if it was 'completed' (for late arrivals)
    await manager.register_result(scan_id, analyzer_name, trigger_analysis=False)

    # Update project timestamp
    await manager.update_project_last_scan()

    return {
        "scan_id": scan_id,
        "findings_count": len(final_findings),
        "waived_count": waived_count,
        "stats": stats.model_dump(),
    }
