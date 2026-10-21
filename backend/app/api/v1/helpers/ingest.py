import asyncio
from typing import Any

from app.models.finding import Finding
from app.models.stats import Stats
from app.models.waiver import Waiver
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.scans import ScanRepository
from app.repositories.waivers import WaiverRepository
from app.schemas.ingest import FindingsIngestResponse, IngestEnvelope, PipelineIngest, ScanStatsResponse
from app.services.aggregation import ResultAggregator
from app.services.analysis.stats import StatsAccumulator, compute_stats
from app.services.scan_manager import ScanManager, apply_waivers

_STATS_FIELDS = {path.split(".", 1)[0] for path in StatsAccumulator.REQUIRED_PATHS} & Finding.model_fields.keys()


async def process_findings_ingest(
    manager: ScanManager, analyzer_name: str, data: PipelineIngest
) -> FindingsIngestResponse:
    """Triggers no analysis, so a fast scanner cannot complete the scan before slower ones such as the SBOM finish."""
    scan_id = manager.run_scan_id(data)
    result_dict = data.model_dump(exclude=set(IngestEnvelope.model_fields))
    await ScanRepository(manager.db).touch(scan_id)
    await AnalysisResultRepository(manager.db).save_result(scan_id, analyzer_name, result_dict, source=data.job_name)
    await manager.find_or_create_scan(data, scan_id)

    waivers = await WaiverRepository(manager.db).find_active_for_project(str(manager.project.id))
    findings_count, waived_count, stats = await asyncio.to_thread(_summarize, analyzer_name, result_dict, waivers)

    await manager.register_result(scan_id, analyzer_name, trigger_analysis=False)

    return FindingsIngestResponse(
        scan_id=scan_id,
        findings_count=findings_count,
        waived_count=waived_count,
        stats=ScanStatsResponse(**stats.model_dump()),
    )


def _summarize(analyzer_name: str, result: dict[str, Any], waivers: list[Waiver]) -> tuple[int, int, Stats]:
    """Off the event loop: a large upload takes hundreds of milliseconds to aggregate, match and count."""
    aggregator = ResultAggregator()
    aggregator.aggregate(analyzer_name, result)
    kept, waived_count = apply_waivers(aggregator.get_findings(), waivers)
    records = ({field: getattr(f, field) for field in _STATS_FIELDS} for f in kept)
    return len(kept), waived_count, compute_stats(records, {})
