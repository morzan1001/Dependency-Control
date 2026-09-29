"""Helper functions for ingest endpoints."""

from typing import Any

from app.api.v1.helpers.body_limit import refuse_oversized_document
from app.repositories.analysis_results import AnalysisResultRepository
from app.services.aggregation import ResultAggregator
from app.services.analysis.stats import compute_stats
from app.services.scan_manager import ScanManager


async def process_findings_ingest(
    manager: ScanManager,
    analyzer_name: str,
    result_dict: dict[str, Any],
    scan_id: str,
) -> dict[str, Any]:
    """Common processing for findings-based ingests (TruffleHog, OpenGrep, KICS, Bearer).

    Does NOT trigger aggregation, so a fast scanner can't mark the scan
    'completed' before slower scanners (e.g. SBOM) finish; aggregation is kicked
    off later by the SBOM scanner or the housekeeping job.
    """
    # Stored first so an oversized result is refused before the aggregation and waiver work.
    with refuse_oversized_document(f"The {analyzer_name} result"):
        await AnalysisResultRepository(manager.db).save_result(scan_id, analyzer_name, result_dict)

    aggregator = ResultAggregator()
    aggregator.aggregate(analyzer_name, result_dict)
    findings = aggregator.get_findings()

    final_findings, waived_count = await manager.apply_waivers(findings)

    stats = compute_stats((f.model_dump() for f in final_findings), {})

    await manager.register_result(scan_id, analyzer_name, trigger_analysis=False)

    return {
        "scan_id": scan_id,
        "findings_count": len(final_findings),
        "waived_count": waived_count,
        "stats": stats.model_dump(),
    }
