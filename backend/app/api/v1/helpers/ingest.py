"""Helper functions for ingest endpoints."""

from typing import Any

from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.scans import ScanRepository
from app.schemas.ingest import BaseIngest
from app.services.aggregation import ResultAggregator
from app.services.analysis.stats import StatsAccumulator, compute_stats
from app.services.scan_manager import ScanManager

_STATS_FIELDS = {path.split(".", 1)[0] for path in StatsAccumulator.REQUIRED_PATHS}


async def process_findings_ingest(manager: ScanManager, analyzer_name: str, data: BaseIngest) -> dict[str, Any]:
    """Common processing for findings-based ingests (TruffleHog, OpenGrep, KICS, Bearer).

    Does NOT trigger aggregation, so a fast scanner can't mark the scan
    'completed' before slower scanners (e.g. SBOM) finish; aggregation is kicked
    off later by the SBOM scanner or the housekeeping job.
    """
    scan_id = manager.run_scan_id(data)
    result_dict = data.model_dump(exclude=set(BaseIngest.model_fields))
    await ScanRepository(manager.db).touch(scan_id)
    await AnalysisResultRepository(manager.db).save_result(scan_id, analyzer_name, result_dict)
    await manager.find_or_create_scan(data, scan_id)

    aggregator = ResultAggregator()
    aggregator.aggregate(analyzer_name, result_dict)
    findings = aggregator.get_findings()

    final_findings, waived_count = await manager.apply_waivers(findings)

    stats = compute_stats((f.model_dump(include=_STATS_FIELDS) for f in final_findings), {})

    await manager.register_result(scan_id, analyzer_name, trigger_analysis=False)

    return {
        "scan_id": scan_id,
        "findings_count": len(final_findings),
        "waived_count": waived_count,
        "stats": stats.model_dump(),
    }
