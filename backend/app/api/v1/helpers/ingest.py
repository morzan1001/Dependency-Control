"""Helper functions for ingest endpoints."""

from typing import Any, Dict

from app.services.aggregation import ResultAggregator
from app.services.scan_manager import ScanManager


async def process_findings_ingest(
    manager: ScanManager,
    analyzer_name: str,
    result_dict: Dict[str, Any],
    scan_id: str,
) -> Dict[str, Any]:
    """Common processing for findings-based ingests (TruffleHog, OpenGrep, KICS, Bearer).

    Does NOT trigger aggregation, so a fast scanner can't mark the scan
    'completed' before slower scanners (e.g. SBOM) finish; aggregation is kicked
    off later by the SBOM scanner or the housekeeping job.
    """
    aggregator = ResultAggregator()
    aggregator.aggregate(analyzer_name, result_dict)
    findings = aggregator.get_findings()

    final_findings, waived_count = await manager.apply_waivers(findings)

    await manager.store_results(analyzer_name, result_dict, scan_id)

    stats = ScanManager.compute_stats(final_findings)

    await manager.register_result(scan_id, analyzer_name, trigger_analysis=False)

    await manager.update_project_last_scan()

    return {
        "scan_id": scan_id,
        "findings_count": len(final_findings),
        "waived_count": waived_count,
        "stats": stats.model_dump(),
    }
