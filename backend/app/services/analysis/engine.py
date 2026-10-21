import asyncio
import contextlib
import json
import logging
import os
import re
import tempfile
import time
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from functools import partial
from itertools import batched
from pathlib import Path
from typing import Any

import bson
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pymongo import UpdateMany
from pymongo.errors import DocumentTooLarge

from app.core.constants import (
    ANALYSIS_MAX_RETRIES,
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_COMPLETED_WITH_ERRORS,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
    SCAN_TYPE_CBOM,
    ScanStatus,
    SCAN_USABLE_STATUSES,
)
from app.core.cve import advisory_ids
from app.core.metrics import (
    analysis_aggregation_duration_seconds,
    analysis_components_parsed_total,
    analysis_duration_seconds,
    analysis_enrichment_total,
    analysis_epss_scores,
    analysis_errors_total,
    analysis_findings_by_type_total,
    analysis_findings_total,
    analysis_gridfs_operations_total,
    analysis_kev_vulnerabilities_total,
    analysis_race_conditions_total,
    analysis_rescan_operations_total,
    analysis_sbom_parse_errors_total,
    analysis_sbom_processed_total,
    analysis_scans_total,
    analysis_waivers_applied_total,
)
from app.core.purl import CopyKey, dependency_copy_key
from app.models.crypto_asset import CryptoAsset
from app.models.finding import Finding, FindingType
from app.models.project import Scan
from app.models.stats import Stats
from app.repositories.analysis_results import RESULT_PROJECTION, AnalysisResultRepository
from app.repositories.crypto_asset import CryptoAssetRepository, scan_query
from app.repositories.dependencies import DependencyRepository
from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.repositories.findings import FindingRepository, finding_identity
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.repositories.waivers import WaiverRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.schemas.cbom import CryptoAssetType
from app.schemas.sbom import ParsedSBOM, SBOMFormat
from app.services.aggregation import ResultAggregator, is_error_result
from app.services.aggregation.cross_link import refresh_vulnerability_info
from app.services.analysis.integrations import decorate_github_pr, decorate_gitlab_mr
from app.services.analysis.notifications import notify_analysis_failed, send_scan_notifications
from app.services.analysis.registry import (
    CRYPTO_ANALYZERS,
    POST_PROCESSOR_ANALYZERS,
    RAW_SBOM_ANALYZERS,
    VULNERABILITY_ANALYZERS,
    analyzer_factories,
    crypto_evaluators,
)
from app.services.analysis.runner import (
    AnalyzerInput,
    AnalyzerOutcome,
    OutcomeStatus,
    build_settings_resolver,
    record_result,
    run_analyzer,
    sbom_name,
)
from app.services.analysis.stats import build_epss_kev_summary, calculate_comprehensive_stats
from app.services.analysis.types import Database
from app.services.analyzers.cli_base import TEMP_SBOM_PREFIX
from app.services.analyzers.crypto.catalogs.loader import CipherSuiteEntry, load_iana_catalog
from app.services.crypto_policy.resolver import CryptoPolicyResolver, EffectivePolicy
from app.services.dependency_store import store_scan_dependencies
from app.services.enrichment.service import vulnerability_enrichment_service
from app.services.github import installation_github_token
from app.services.gridfs_maintenance import gridfs_ref_id, read_gridfs_file
from app.services.reachability_enrichment import (
    ComponentLanguages,
    apply_reachability,
    fetch_callgraphs,
    run_pending_reachability_for_scan,
)
from app.services.sbom_parser import parse_sbom, sbom_parser
from app.services.update_frequency_rollup import record_scan_update_delta
from app.services.waivers.apply import restamp_waivers, waiver_fingerprint
from app.services.waivers.matching import route_waiver

logger = logging.getLogger(__name__)

_BULK_CHUNK_SIZE = 500
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_SLIMMED_ADVISORY_FIELDS = frozenset({"description", "references", "details"})
# What an alert shows of a finding; the advisory text can reach hundreds of MB on a large scan.
_ANNOUNCED_ADVISORY_FIELDS = ("id", "aliases", "resolved_cve", "severity", "waived", "epss_score", "kev_due_date")
_ANNOUNCED_FINDING_PROJECTION = {
    **dict.fromkeys(("type", "component", "version"), 1),
    **{
        f"details.vulnerabilities.{field}": 1
        for field in (*_ANNOUNCED_ADVISORY_FIELDS, DETAILS_KEY_IN_KEV, DETAILS_KEY_KEV_RANSOMWARE)
    },
}

_ENGINE_RESULT_NAMES = frozenset(analyzer_factories) | POST_PROCESSOR_ANALYZERS | CRYPTO_ANALYZERS

# Crypto findings span the whole scan, so none is credited to one SBOM.
_CRYPTO_SOURCE = "CBOM"


@dataclass(frozen=True)
class _RunContext:
    scan: Scan
    db: Database
    worker_id: str
    # The claimed document's, which every final write is guarded on; ``scan`` may already carry a newer one.
    sbom_generation: int | None
    active_analyzers: list[str]
    github_token: str | None
    settings_for: Callable[[str], dict[str, Any]]

    @property
    def scan_id(self) -> str:
        return self.scan.id

    @property
    def project_id(self) -> str:
        return self.scan.project_id


@dataclass(frozen=True)
class _Verdict:
    status: ScanStatus
    error: str | None
    stats: Stats
    findings_count: int
    ignored_count: int
    outcomes: list[AnalyzerOutcome]
    failed_analyzers: list[str]
    enrichment_failures: list[str]


async def _run_context(scan: Scan, db: Database, worker_id: str, sbom_generation: int | None) -> _RunContext | None:
    project = await ProjectRepository(db).get_by_id(scan.project_id)
    if project is None:
        return None
    system_settings = await SystemSettingsRepository(db).get()
    github_token = await installation_github_token(db, system_settings.github_token)
    settings_for = build_settings_resolver(system_settings, project.analyzer_settings, github_token)
    return _RunContext(scan, db, worker_id, sbom_generation, project.active_analyzers, github_token, settings_for)


async def _carry_over_external_results(scan_id: str, scan_doc: Scan, db: Database) -> None:
    if not (scan_doc.is_rescan and scan_doc.original_scan_id):
        return

    original_scan_id = scan_doc.original_scan_id
    logger.info(f"Rescan detected. Carrying over external results from {original_scan_id} to {scan_id}")

    try:
        await AnalysisResultRepository(db).carry_over(original_scan_id, scan_id, list(_ENGINE_RESULT_NAMES))
    except Exception as e:
        logger.exception("Failed to carry over external results: %s", e)


async def _carry_over_crypto_assets(scan_id: str, scan_doc: Scan, db: Database) -> None:
    """A CBOM posted to /ingest/cbom is not in GridFS, so a rescan cannot re-derive its assets."""
    if scan_doc.is_rescan and scan_doc.original_scan_id:
        await CryptoAssetRepository(db).carry_over_to_scan(scan_doc.project_id, scan_doc.original_scan_id, scan_id)


async def _keep_result(
    ctx: _RunContext,
    aggregator: ResultAggregator,
    analyzer_name: str,
    result: Any,
    source: str,
    row_source: str | None = None,
) -> None:
    aggregator.aggregate(analyzer_name, result, source=source)
    await AnalysisResultRepository(ctx.db).save_result(ctx.scan_id, analyzer_name, result, source=row_source)


def _account(ctx: _RunContext, aggregator: ResultAggregator, outcome: AnalyzerOutcome) -> AnalyzerOutcome:
    name, reason = outcome.name, outcome.reason
    if outcome.error is not None:
        logger.error("Analysis %s failed: %s", name, outcome.error, exc_info=outcome.error)
        analysis_errors_total.labels(analyzer=name).inc()
        aggregator.add_scan_error(name, reason, source=f"System: {name}")
        outcome = replace(outcome, error=None)
    elif outcome.status is OutcomeStatus.FAILED:
        # CLI analyzers report timeouts/exit-codes/bad JSON as error dicts, which aggregate into a finding.
        analysis_errors_total.labels(analyzer=name).inc()
        logger.warning(f"Analysis {name} returned an error result for {ctx.scan_id}: {reason}")
    elif outcome.status is OutcomeStatus.PARTIAL:
        aggregator.add_scan_error(name, reason, partial=True, source=f"System: {name}")
        logger.warning(f"Analysis {name} returned a partial result for {ctx.scan_id}: {reason}")
    else:
        logger.info(f"Analysis {name} completed for {ctx.scan_id}")
    return outcome


async def process_analyzer(
    ctx: _RunContext, aggregator: ResultAggregator, analyzer_name: str, sbom: AnalyzerInput
) -> AnalyzerOutcome:
    started = time.time()
    analysis_scans_total.labels(analyzer=analyzer_name).inc()

    async def keep(result: Any) -> None:
        analysis_duration_seconds.labels(analyzer=analyzer_name).observe(time.time() - started)
        # Rows are keyed on the SBOM's position: root names repeat within a scan (multi-arch images).
        await _keep_result(ctx, aggregator, analyzer_name, result, sbom.source, row_source=sbom.label)

    outcome = await run_analyzer(analyzer_name, sbom, ctx.settings_for(analyzer_name), keep)
    return _account(ctx, aggregator, outcome)


def _evaluate_crypto(
    docs: list[dict[str, Any]], policy: EffectivePolicy, catalog: dict[str, CipherSuiteEntry]
) -> dict[str, dict[str, Any] | Exception]:
    assets = [CryptoAsset.model_validate(d) for d in docs]
    results: dict[str, dict[str, Any] | Exception] = {}
    for name, evaluate in crypto_evaluators(catalog).items():
        started = time.time()
        analysis_scans_total.labels(analyzer=name).inc()
        try:
            results[name] = evaluate(assets, policy)
        except Exception as e:
            results[name] = e
        analysis_duration_seconds.labels(analyzer=name).observe(time.time() - started)
    return results


def _crypto_analyzers_failed(ctx: _RunContext, aggregator: ResultAggregator, error: Exception) -> list[AnalyzerOutcome]:
    return [_account(ctx, aggregator, AnalyzerOutcome.from_error(name, error)) for name in sorted(CRYPTO_ANALYZERS)]


async def _run_crypto_analyzers(ctx: _RunContext, aggregator: ResultAggregator) -> list[AnalyzerOutcome]:
    """Must run after every SBOM's embedded crypto assets are persisted."""
    try:
        docs = await CryptoAssetRepository(ctx.db).find_all_raw(scan_query(ctx.project_id, ctx.scan_id))
        policy = await CryptoPolicyResolver(ctx.db).resolve(ctx.project_id)
        has_protocols = any(d.get("asset_type") == CryptoAssetType.PROTOCOL for d in docs)
        catalog = await load_iana_catalog() if has_protocols else {}
        results = await asyncio.to_thread(_evaluate_crypto, docs, policy, catalog)
    except Exception as e:
        return _crypto_analyzers_failed(ctx, aggregator, e)

    outcomes: list[AnalyzerOutcome] = []
    for name, result in results.items():
        if isinstance(result, Exception):
            outcome = AnalyzerOutcome.from_error(name, result)
        else:
            keep = partial(_keep_result, ctx, aggregator, name, source=_CRYPTO_SOURCE)
            outcome = await record_result(name, result, keep)
        outcomes.append(_account(ctx, aggregator, outcome))
    return outcomes


_SBOM_GRIDFS_LOAD_ERROR = "Failed to load SBOM from GridFS"


def _worst_outcomes(outcomes: list[AnalyzerOutcome]) -> list[AnalyzerOutcome]:
    """An analyzer reports once per SBOM."""
    worst: dict[str, AnalyzerOutcome] = {}
    for outcome in outcomes:
        if outcome.name not in worst or outcome.status > worst[outcome.name].status:
            worst[outcome.name] = outcome
    return list(worst.values())


def _failed_analyzer_names(outcomes: list[AnalyzerOutcome]) -> tuple[list[str], list[str]]:
    """Enrichments are listed apart: a failed enrichment loses metadata, not findings."""
    failed = sorted(outcome.name for outcome in outcomes if outcome.status is not OutcomeStatus.SUCCESS)
    return (
        [name for name in failed if name not in POST_PROCESSOR_ANALYZERS],
        [name for name in failed if name in POST_PROCESSOR_ANALYZERS],
    )


def _sbom_load_failed(aggregator: ResultAggregator, reason: object) -> None:
    analysis_gridfs_operations_total.labels(operation="download", status="error").inc()
    aggregator.add_scan_error("system", f"{_SBOM_GRIDFS_LOAD_ERROR}: {reason}")


async def _stored_sbom_ids(
    fs: AsyncIOMotorGridFSBucket, sboms: list[Any], aggregator: ResultAggregator
) -> list[str | None]:
    gridfs_ids = [gridfs_ref_id(item) for item in sboms]
    wanted = [bson.ObjectId(gid) for gid in gridfs_ids if gid and bson.ObjectId.is_valid(gid)]
    stored = {str(file._id) async for file in fs.find({"_id": {"$in": wanted}})} if wanted else set()
    for gid in gridfs_ids:
        if gid not in stored:
            logger.error("%s: %s is not stored", _SBOM_GRIDFS_LOAD_ERROR, gid)
            _sbom_load_failed(aggregator, f"{gid} is not stored")
    return [gid if gid in stored else None for gid in gridfs_ids]


async def _load_sbom(
    fs: AsyncIOMotorGridFSBucket, gridfs_id: str, position: int, write_file: bool
) -> tuple[ParsedSBOM | None, AnalyzerInput]:
    analysis_gridfs_operations_total.labels(operation="download", status="attempt").inc()
    data = await read_gridfs_file(fs, bson.ObjectId(gridfs_id))
    path = None
    try:
        if write_file:
            fd, path = tempfile.mkstemp(prefix=TEMP_SBOM_PREFIX, suffix=".json")
            os.close(fd)
            await asyncio.to_thread(Path(path).write_bytes, data)
        document = await asyncio.to_thread(json.loads, data)
        del data
        analysis_gridfs_operations_total.labels(operation="download", status="success").inc()
        return await asyncio.to_thread(_parse_and_track_sbom, document, position, path)
    except BaseException:
        if path:
            os.remove(path)
        raise


def _parse_and_track_sbom(
    document: Any, position: int = 1, path: str | None = None
) -> tuple[ParsedSBOM | None, AnalyzerInput]:
    parsed_components: list[dict[str, Any]] = []
    parsed_sbom = None
    name, sbom_format = None, SBOMFormat.UNKNOWN
    try:
        name, sbom_format = sbom_name(document), sbom_parser.detect_format(document)
        parsed_sbom = parse_sbom(document)
        parsed_components = [dep.model_dump() for dep in parsed_sbom.dependencies]
        logger.info(
            f"Parsed SBOM: format={parsed_sbom.format.value}, components={len(parsed_components)}, "
            f"skipped={parsed_sbom.skipped_components}, merged={parsed_sbom.merged_components}, "
            f"skipped_reasons={parsed_sbom.skipped_reasons}"
        )
        analysis_sbom_processed_total.labels(format=parsed_sbom.format.value).inc()
        analysis_components_parsed_total.inc(len(parsed_components))
    except Exception as parse_err:
        logger.warning(f"Failed to pre-parse SBOM: {parse_err} - only the raw-document scanners will run")
        analysis_sbom_parse_errors_total.inc()
    return parsed_sbom, AnalyzerInput(position, parsed_components, name=name, path=path, format=sbom_format)


async def _persist_embedded_crypto_assets(parsed_sbom: Any, project_id: str, scan_id: str, db: Database) -> None:
    crypto_assets = [
        CryptoAsset(project_id=project_id, scan_id=scan_id, **a.model_dump()) for a in parsed_sbom.crypto_assets
    ]
    persisted = await CryptoAssetRepository(db).bulk_upsert(project_id, scan_id, crypto_assets)
    logger.info("engine: persisted %d crypto assets from embedded CBOM (scan=%s)", persisted, scan_id)


def _resolve_effective_analyzers(
    active_analyzers: list[str], parsed_sbom: ParsedSBOM | None, parsed_components: list[dict[str, Any]]
) -> list[str]:
    if parsed_sbom is None:
        return sorted(n for n in active_analyzers if n in RAW_SBOM_ANALYZERS)
    if parsed_sbom.crypto_assets and not parsed_components:
        return sorted(n for n in active_analyzers if n not in VULNERABILITY_ANALYZERS)
    return sorted(active_analyzers)


async def _process_sbom(
    ctx: _RunContext, aggregator: ResultAggregator, parsed_sbom: ParsedSBOM | None, sbom: AnalyzerInput
) -> list[AnalyzerOutcome]:
    outcomes: list[AnalyzerOutcome] = []
    if parsed_sbom is not None and parsed_sbom.crypto_assets:
        try:
            await _persist_embedded_crypto_assets(parsed_sbom, ctx.project_id, ctx.scan_id, ctx.db)
        except Exception as e:
            outcomes = _crypto_analyzers_failed(ctx, aggregator, e)
    names = _resolve_effective_analyzers(ctx.active_analyzers, parsed_sbom, sbom.components)
    tasks = [process_analyzer(ctx, aggregator, name, sbom) for name in names if name in analyzer_factories]
    return [*outcomes, *await asyncio.gather(*tasks)]


async def _analyse_sboms(
    ctx: _RunContext, fs: AsyncIOMotorGridFSBucket, stored_ids: list[str | None], aggregator: ResultAggregator
) -> tuple[list[ParsedSBOM | None], int, list[AnalyzerOutcome]]:
    write_file = bool(RAW_SBOM_ANALYZERS & set(ctx.active_analyzers))
    # Collected rather than stored per SBOM: the inventory is replaced once per payload.
    payload: list[ParsedSBOM | None] = []
    load_failures = stored_ids.count(None)
    outcomes: list[AnalyzerOutcome] = []
    for position, gridfs_id in enumerate(stored_ids, start=1):
        if gridfs_id is None:
            payload.append(None)
            continue
        try:
            parsed_sbom, sbom = await _load_sbom(fs, gridfs_id, position, write_file)
        except Exception as load_err:
            logger.exception("Failed to load SBOM from GridFS %s", gridfs_id)
            _sbom_load_failed(aggregator, load_err)
            load_failures += 1
            payload.append(None)
            continue
        payload.append(parsed_sbom)
        try:
            outcomes.extend(await _process_sbom(ctx, aggregator, parsed_sbom, sbom))
        finally:
            if sbom.path:
                os.remove(sbom.path)
        aggregator.fold_vulnerability_entries()
        # The component dicts must not stay alive while the next SBOM loads.
        del sbom

    if load_failures:
        logger.warning(
            "Scan %s: %d/%d SBOMs failed to load; skipping dependency persistence to keep stored dependencies",
            ctx.scan_id,
            load_failures,
            len(stored_ids),
        )
    return payload, load_failures, outcomes


def _track_findings_metrics(aggregated_findings: list[Finding]) -> None:
    by_type = Counter((finding.type, finding.severity) for finding in aggregated_findings)
    by_scanner = Counter((name, finding.severity) for finding in aggregated_findings for name in finding.scanners)
    for (finding_type, severity), count in by_type.items():
        analysis_findings_by_type_total.labels(type=finding_type, severity=severity).inc(count)
    for (scanner_name, severity), count in by_scanner.items():
        analysis_findings_total.labels(analyzer=scanner_name, severity=severity).inc(count)


_DEP_ENRICHMENT_COPY_KEYS = ("license", "license_expression", "license_category", "license_risks")


def _dependency_copies(enrichment_entries: list[dict[str, Any]]) -> dict[CopyKey, dict[str, Any]]:
    copies: dict[CopyKey, dict[str, Any]] = {}
    for entry in enrichment_entries:
        if copied := {key: entry["data"][key] for key in _DEP_ENRICHMENT_COPY_KEYS if key in entry["data"]}:
            copies[dependency_copy_key(entry["purl"], entry["name"], entry["version"])] = copied
    return copies


def _dependency_update(scan_id: str, copy_key: CopyKey, copied: dict[str, Any]) -> UpdateMany:
    if isinstance(copy_key, str):
        # Prefix match keeps qualifier variants; a lookahead, unlike an alternation, keeps the index range tight.
        dep_filter: dict[str, Any] = {"scan_id": scan_id, "purl": {"$regex": f"^{re.escape(copy_key)}(?![^?#])"}}
    else:
        name, version = copy_key
        # Purl-less docs only, so it cannot stamp a same-named package of another ecosystem with its licence.
        dep_filter = {"scan_id": scan_id, "name": name, "version": version, "purl": {"$in": [None, ""]}}
    fields: dict[str, Any] = {key: {"$literal": value} for key, value in copied.items()}
    if "license" in fields:
        # The SBOM-declared license is authoritative; enrichment only fills docs that lack one.
        declared = {"$ifNull": ["$license", ""]}
        fields["license"] = {"$cond": [{"$eq": [declared, ""]}, fields["license"], "$license"]}
    return UpdateMany(dep_filter, [{"$set": fields}])


async def _store_dependencies(
    payload: list[ParsedSBOM | None],
    project_id: str,
    scan_id: str,
    db: Database,
    enrichment_entries: list[dict[str, Any]],
) -> None:
    copies = _dependency_copies(enrichment_entries)
    stored = await store_scan_dependencies(payload, project_id, scan_id, DependencyRepository(db), copies)
    if stored is not None:
        logger.info(f"Stored {stored} dependencies for scan {scan_id}")
    else:
        # The inventory an earlier write left in place takes the copies as updates.
        ops = (_dependency_update(scan_id, copy_key, copied) for copy_key, copied in copies.items())
        for chunk in batched(ops, _BULK_CHUNK_SIZE, strict=False):
            try:
                await db.dependencies.bulk_write(list(chunk), ordered=False)
            except Exception as e:
                logger.exception("Failed to bulk update dependencies: %s", e)
    persisted = await DependencyEnrichmentRepository(db).upsert_many(enrichment_entries)
    logger.info(f"Upserted {persisted} dependency enrichments.")


async def _run_epss_kev_enrichment(
    ctx: _RunContext, vulnerability_findings: list[dict[str, Any]], outcomes: list[AnalyzerOutcome]
) -> None:
    try:
        enrichments, unavailable = await vulnerability_enrichment_service.enrich_findings(
            vulnerability_findings, github_token=ctx.github_token
        )
        epss_kev_summary = build_epss_kev_summary(vulnerability_findings, enrichments)
        await AnalysisResultRepository(ctx.db).save_result(ctx.scan_id, "epss_kev", epss_kev_summary)
        status = OutcomeStatus.PARTIAL if unavailable else OutcomeStatus.SUCCESS
        outcomes.append(
            AnalyzerOutcome("epss_kev", status, unavailable or "", f"{len(vulnerability_findings)} enriched")
        )
        logger.info(f"[epss_kev] Enriched {len(vulnerability_findings)} vulnerability findings with EPSS/KEV data")

        analysis_enrichment_total.labels(type="epss_kev").inc(len(vulnerability_findings))

        for vf in vulnerability_findings:
            details = vf.get("details", {})
            epss_score = details.get("epss_score")
            if epss_score is not None:
                with contextlib.suppress(ValueError, TypeError):
                    analysis_epss_scores.observe(float(epss_score))
            if details.get(DETAILS_KEY_IN_KEV):
                analysis_kev_vulnerabilities_total.inc()

    except Exception as e:
        outcomes.append(AnalyzerOutcome("epss_kev", OutcomeStatus.FAILED))
        logger.warning(f"[epss_kev] Failed to enrich findings: {e}")


async def _run_reachability_enrichment(
    ctx: _RunContext, vulnerability_findings: list[dict[str, Any]], outcomes: list[AnalyzerOutcome]
) -> ComponentLanguages | None:
    callgraphs = await fetch_callgraphs(ctx.project_id, ctx.scan_id, ctx.db)
    if not callgraphs:
        await ScanRepository(ctx.db).update_raw(ctx.scan_id, {"$set": {"reachability_pending": True}})
        logger.info(f"[reachability] No callgraph available for scan {ctx.scan_id}. Marked as pending.")
        return None

    try:
        component_languages, enriched_count = await apply_reachability(
            ctx.db, ctx.scan_id, vulnerability_findings, callgraphs
        )
    except Exception as e:
        outcomes.append(AnalyzerOutcome("reachability", OutcomeStatus.FAILED))
        logger.warning(f"[reachability] Failed to enrich findings: {e}")
        return None
    outcomes.append(AnalyzerOutcome("reachability", OutcomeStatus.SUCCESS, detail=f"{enriched_count} enriched"))
    return component_languages


async def _aggregate_external_results(
    aggregator: ResultAggregator, result_repo: AnalysisResultRepository, scan_id: str
) -> list[AnalyzerOutcome]:
    outcomes: list[AnalyzerOutcome] = []
    query = {"scan_id": scan_id, "analyzer_name": {"$nin": list(_ENGINE_RESULT_NAMES)}}
    async for row in result_repo.iterate_raw(query, RESULT_PROJECTION):
        analyzer_name = row["analyzer_name"]
        try:
            result = await result_repo.load_result(row)
            aggregator.aggregate(analyzer_name, result)
            # Error-shaped rows aggregate into a SCAN-ERROR finding without raising.
            status = OutcomeStatus.FAILED if is_error_result(result) else OutcomeStatus.SUCCESS
            outcomes.append(AnalyzerOutcome(analyzer_name, status))
        except Exception as exc:
            logger.warning(
                "_aggregate_external_results: skipping malformed result for analyzer=%s scan=%s: %s",
                analyzer_name,
                scan_id,
                exc,
            )
            aggregator.add_scan_error(
                analyzer_name, f"external result could not be aggregated: {exc}", error_details=str(exc)
            )
            outcomes.append(AnalyzerOutcome(analyzer_name, OutcomeStatus.FAILED))
    return outcomes


def _prepare_finding_records(
    aggregated_findings: list[Any],
    scan_id: str,
    project_id: str,
    scan_created_at: datetime,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """A deterministic _id per (scan, finding identity) makes a re-analysis or raced double-persist overwrite."""
    findings_to_insert: list[dict[str, Any]] = []
    vulnerability_findings: list[dict[str, Any]] = []
    seen_identities: dict[str, int] = {}
    for f in aggregated_findings:
        record: dict[str, Any] = f.model_dump()
        record["scan_id"] = scan_id
        record["project_id"] = project_id
        record["finding_id"] = f.id
        identity = f"{scan_id}:{record.get('type')}:{record.get('component')}:{record.get('version')}:{f.id}"
        occurrence = seen_identities.get(identity, 0)
        seen_identities[identity] = occurrence + 1
        if occurrence:
            identity = f"{identity}:{occurrence}"
        record["_id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, identity))
        record["scan_created_at"] = scan_created_at
        findings_to_insert.append(record)
        if record.get("type") == "vulnerability":
            vulnerability_findings.append(record)
    return findings_to_insert, vulnerability_findings


async def _run_vuln_enrichments(
    ctx: _RunContext, vulnerability_findings: list[dict[str, Any]], outcomes: list[AnalyzerOutcome]
) -> ComponentLanguages | None:
    if "epss_kev" in ctx.active_analyzers and vulnerability_findings:
        await _run_epss_kev_enrichment(ctx, vulnerability_findings, outcomes)

    if "reachability" in ctx.active_analyzers and vulnerability_findings:
        return await _run_reachability_enrichment(ctx, vulnerability_findings, outcomes)
    return None


async def _stamp_first_seen(records: list[dict[str, Any]], project_id: str, finding_repo: FindingRepository) -> None:
    """Carried forward because retention deletes the scans that first saw a finding."""
    vulnerabilities = [r for r in records if r["type"] == FindingType.VULNERABILITY.value]
    others = [r for r in records if r["type"] != FindingType.VULNERABILITY.value]
    earliest, advisories = await asyncio.gather(
        finding_repo.earliest_detections(project_id, others),
        finding_repo.advisory_detections(project_id, vulnerabilities),
    )
    for record in others:
        detections = (earliest.get(finding_identity(record)), record["scan_created_at"])
        record["first_seen_at"] = min(d for d in detections if d is not None)
    for record in vulnerabilities:
        entries = record["details"]["vulnerabilities"]
        for entry in entries:
            known = [advisories.get((record["component"], advisory_id)) for advisory_id in advisory_ids(entry)]
            entry["first_seen_at"] = min(d for d in (*known, record["scan_created_at"]) if d is not None)
        record["first_seen_at"] = min(entry["first_seen_at"] for entry in entries)


def _fit_finding(record: dict[str, Any]) -> dict[str, Any]:
    size = len(bson.encode(record))
    if size <= _MAX_DOCUMENT_BYTES:
        return record
    if record["type"] == "vulnerability":
        details = record["details"]
        advisories = [
            {k: v for k, v in e.items() if k not in _SLIMMED_ADVISORY_FIELDS} for e in details["vulnerabilities"]
        ]
        slim = {**record, "details": {**details, "vulnerabilities": advisories}}
        if len(bson.encode(slim)) <= _MAX_DOCUMENT_BYTES:
            logger.warning(
                "Finding %s exceeds 16 MiB (%d bytes); stored with slim advisories", record["finding_id"], size
            )
            return slim
    raise DocumentTooLarge(f"Finding {record['finding_id']} is {size} bytes, over the 16 MiB document limit")


async def _persist_findings_and_waivers(
    findings_to_insert: list[dict[str, Any]], scan_id: str, project_id: str, db: Database
) -> int:
    finding_repo = FindingRepository(db)
    # Before the write, so re-analysing a scan still sees the dates its own copies inherited.
    await _stamp_first_seen(findings_to_insert, project_id, finding_repo)
    written_at = datetime.now(timezone.utc)
    for record in findings_to_insert:
        record["created_at"] = written_at
    # Fitted before the first write: the server drops a document just over 16 MiB from the batch without failing it.
    fitted = [_fit_finding(record) for record in findings_to_insert]
    fresh = not await finding_repo.exists({"scan_id": scan_id})
    persisted_count = 0
    for i in range(0, len(fitted), _BULK_CHUNK_SIZE):
        persisted_count += await finding_repo.replace_many_raw(fitted[i : i + _BULK_CHUNK_SIZE], fresh)
    # Only after every chunk is written, so a persist that raises leaves the previous findings in place.
    await finding_repo.delete_older_writes({"scan_id": scan_id}, written_at)

    waivers = await WaiverRepository(db).find_active_for_project(project_id)
    matches = await restamp_waivers(finding_repo, None, scan_id, waivers)
    await ScanRepository(db).update_raw(scan_id, {"$set": {"waiver_fingerprint": waiver_fingerprint(waivers)}})
    for waiver in waivers:
        if matches[waiver.id]:
            analysis_waivers_applied_total.labels(type=route_waiver(waiver)).inc()
    return persisted_count


async def _apply_handed_over_callgraphs(scan_id: str, project_id: str, db: Database) -> None:
    # A callgraph uploaded during the run only flagged the scan, since the findings it would enrich were being replaced.
    try:
        state = await ScanRepository(db).get_minimal_by_id(scan_id)
        if state and state.reachability_pending:
            await run_pending_reachability_for_scan(scan_id, project_id, db)
    except Exception:
        # A failed pass stays flagged for the next upload; the final scan is still announced.
        logger.exception("Scan %s: applying the callgraphs uploaded during the analysis failed", scan_id)


async def _write_final_state(
    ctx: _RunContext, status: ScanStatus, update: dict[str, Any], external_load_start: datetime
) -> ScanStatus | None:
    """Returns status, PENDING when new input arrived mid-run (rescheduled), or None when another run took the claim."""
    # Otherwise a replaced SBOM or a scanner result arriving mid-load would be finalized over, never analysed.
    guard: dict[str, Any] = {
        "_id": ctx.scan_id,
        "status": SCAN_STATUS_PROCESSING,
        "worker_id": ctx.worker_id,
        "sbom_generation": ctx.sbom_generation,
        "$or": [
            {"last_result_at": None},
            {"last_result_at": {"$lt": external_load_start}},
        ],
    }
    scan_repo = ScanRepository(ctx.db)
    if await scan_repo.collection.find_one_and_update(guard, update) is not None:
        return status
    if not await scan_repo.requeue(ctx.scan_id, ctx.worker_id, counter="retry_count"):
        logger.warning("Scan %s: the claim moved to another run; leaving the scan to it.", ctx.scan_id)
        return None
    logger.warning("Scan %s: new input arrived during analysis; rescheduled instead of finalizing.", ctx.scan_id)
    analysis_race_conditions_total.inc()
    return SCAN_STATUS_PENDING


async def _finalize_scan_and_project(
    ctx: _RunContext, verdict: _Verdict, external_load_start: datetime
) -> ScanStatus | None:
    scan, scan_id, status = ctx.scan, ctx.scan_id, verdict.status
    completed_at = datetime.now(timezone.utc)
    stats = verdict.stats.model_dump()
    latest_run = {
        "scan_id": scan_id,
        "status": status,
        "findings_count": verdict.findings_count,
        "stats": stats,
        "completed_at": completed_at,
    }
    set_fields: dict[str, Any] = {
        "status": status,
        "findings_count": verdict.findings_count,
        "ignored_count": verdict.ignored_count,
        "stats": stats,
        "completed_at": completed_at,
        "latest_run": latest_run,
        "failed_analyzers": verdict.failed_analyzers or None,
        "enrichment_failures": verdict.enrichment_failures or None,
    }
    unset_fields = {"received_results": "", "last_result_at": ""}
    if verdict.error:
        set_fields["error"] = verdict.error
    else:
        unset_fields["error"] = ""
    if status in SCAN_USABLE_STATUSES and not scan.is_rescan:
        # This analysis post-dates every rescan of the build, which may still hold a replaced SBOM.
        unset_fields["latest_rescan_id"] = ""

    outcome = await _write_final_state(ctx, status, {"$set": set_fields, "$unset": unset_fields}, external_load_start)
    if outcome != status:
        return outcome

    scan_repo = ScanRepository(ctx.db)
    if scan.is_rescan and scan.original_scan_id:
        # latest_run reports every run, while the lineage moves only onto an analysis head may report.
        root_fields: dict[str, Any] = {"latest_run": latest_run}
        if status in SCAN_USABLE_STATUSES:
            root_fields["latest_rescan_id"] = scan_id
        await scan_repo.report_rescan_run(scan.original_scan_id, scan.sbom_generation, root_fields)

    if status != SCAN_STATUS_FAILED and await scan_repo.sync_project_head(ctx.project_id) == scan_id:
        # Only head records waiver outcomes, and head is known once sync_project_head derived it.
        try:
            waiver_repo = WaiverRepository(ctx.db)
            waivers = await waiver_repo.find_active_for_project(ctx.project_id)
            await restamp_waivers(FindingRepository(ctx.db), waiver_repo, scan_id, waivers)
        except Exception:
            # Best effort like the announcement: the scan is already final.
            logger.exception("Scan %s: recording the waiver outcomes on head failed", scan_id)
    return status


async def _unwaived_findings(scan_id: str, db: Database) -> list[dict[str, Any]]:
    """Read back from the DB because waivers are applied only there."""
    query = {"scan_id": scan_id, "waived": {"$ne": True}}
    return [doc async for doc in FindingRepository(db).iterate_raw(query, _ANNOUNCED_FINDING_PROJECTION)]


async def _send_integrations_and_notifications(
    ctx: _RunContext, verdict: _Verdict, findings: list[dict[str, Any]]
) -> None:
    project = await ProjectRepository(ctx.db).get_by_id(ctx.project_id)
    if not project:
        return
    for decorate in (decorate_gitlab_mr, decorate_github_pr):
        await decorate(ctx.scan_id, verdict.stats, verdict.status, verdict.error, ctx.scan, project, ctx.db)
    await send_scan_notifications(
        ctx.scan_id,
        project,
        findings,
        verdict.stats,
        verdict.status,
        verdict.failed_analyzers,
        verdict.outcomes,
        db=ctx.db,
    )


def _partial_run_reasons(
    failed_analyzers: list[str],
    sbom_load_failures: int,
    sbom_parse_failures: int,
    sboms_expected: int,
    persisted_findings_count: int,
    total_findings_count: int,
) -> list[str]:
    reasons: list[str] = []
    if failed_analyzers:
        reasons.append(f"analyzers failed or returned partial results: {', '.join(failed_analyzers)}")
    if sbom_load_failures:
        reasons.append(f"{sbom_load_failures} of {sboms_expected} SBOMs failed to load")
    if sbom_parse_failures:
        reasons.append(
            f"{sbom_parse_failures} of {sboms_expected} SBOMs failed to parse; dependency inventory left unchanged"
        )
    if persisted_findings_count < total_findings_count:
        reasons.append(f"only {persisted_findings_count} of {total_findings_count} findings were persisted")
    return reasons


def _final_scan_status(scan_id: str, partial_reasons: list[str]) -> tuple[ScanStatus, str | None]:
    if partial_reasons:
        error = "; ".join(partial_reasons)
        logger.warning("Scan %s completed with errors: %s", scan_id, error)
        return SCAN_STATUS_COMPLETED_WITH_ERRORS, error
    return SCAN_STATUS_COMPLETED, None


async def _announce_outcome(ctx: _RunContext, verdict: _Verdict) -> None:
    """Best effort: the scan is already final, so a failure here is logged and never changes it."""
    try:
        await _apply_handed_over_callgraphs(ctx.scan_id, ctx.project_id, ctx.db)
        if verdict.status == SCAN_STATUS_FAILED:
            await notify_analysis_failed(ctx.db, ctx.scan_id, ctx.project_id, verdict.error or verdict.status)
            return
        await _send_integrations_and_notifications(ctx, verdict, await _unwaived_findings(ctx.scan_id, ctx.db))
    except Exception:
        logger.exception("Scan %s: announcing the finished analysis failed", ctx.scan_id)


async def _keep_previous_analysis(ctx: _RunContext, load_start: datetime) -> ScanStatus | None:
    scan_repo = ScanRepository(ctx.db)
    # Retried while the worker still re-queues, so the input that reopened the scan gets analysed.
    if ctx.scan.retry_count + 1 < ANALYSIS_MAX_RETRIES:
        logger.warning("Scan %s: an SBOM failed to load or parse; retrying the re-analysis", ctx.scan_id)
        requeued = await scan_repo.requeue(ctx.scan_id, ctx.worker_id, counter="retry_count")
        return SCAN_STATUS_PENDING if requeued else None
    logger.warning(
        "Scan %s: an SBOM failed to load or parse on the last attempt; keeping the previous analysis", ctx.scan_id
    )
    error = "SBOM could not be loaded or parsed for re-analysis; findings are from the previous analysis"
    outcome = await _write_final_state(
        ctx,
        SCAN_STATUS_COMPLETED_WITH_ERRORS,
        {"$set": {"status": SCAN_STATUS_COMPLETED_WITH_ERRORS, "error": error}},
        load_start,
    )
    if outcome == SCAN_STATUS_COMPLETED_WITH_ERRORS:
        await scan_repo.sync_project_head(ctx.project_id)
        await _apply_handed_over_callgraphs(ctx.scan_id, ctx.project_id, ctx.db)
    return outcome


async def _conclude(
    ctx: _RunContext, verdict: _Verdict, external_load_start: datetime, started: float
) -> ScanStatus | None:
    analysis_aggregation_duration_seconds.observe(time.time() - started)
    outcome = await _finalize_scan_and_project(ctx, verdict, external_load_start)
    if outcome != verdict.status:
        return outcome
    await _announce_outcome(ctx, verdict)
    # Runs on the released findings: the rollup holds two dependency maps of its own.
    await record_scan_update_delta(ctx.db, ctx.scan_id)
    return outcome


async def _still_claimed(ctx: _RunContext) -> bool:
    if await ScanRepository(ctx.db).renew_claim(ctx.scan_id, ctx.worker_id):
        return True
    logger.warning("Scan %s: the claim moved to another run; stopping before writing results.", ctx.scan_id)
    return False


async def run_analysis(
    scan_id: str,
    sboms: list[dict[str, Any]],
    db: Database,
    *,
    worker_id: str,
    sbom_generation: int | None = None,
) -> ScanStatus | None:
    """sboms and sbom_generation must come from the same claimed scan document."""
    logger.info(f"Starting analysis for scan {scan_id}")
    aggregation_start_time = time.time()

    scan_repo = ScanRepository(db)
    scan_doc = await scan_repo.get_by_id(scan_id)
    if not scan_doc:
        logger.error(f"Scan {scan_id} not found")
        return None
    ctx = await _run_context(scan_doc, db, worker_id, sbom_generation)
    if ctx is None:
        logger.error(f"Project for scan {scan_id} not found")
        # No failure notice: it is addressed through the project, which is gone.
        failed = await scan_repo.mark_failed(scan_id, "Project not found", worker_id=worker_id)
        return SCAN_STATUS_FAILED if failed else None

    aggregator = ResultAggregator()
    fs = AsyncIOMotorGridFSBucket(db)
    load_start = datetime.now(timezone.utc)
    # Checked before any write, so an SBOM that is gone leaves the stored analysis intact.
    stored_ids = await _stored_sbom_ids(fs, sboms, aggregator)
    if None in stored_ids and scan_doc.completed_at is not None:
        return await _keep_previous_analysis(ctx, load_start)

    if scan_doc.is_rescan:
        analysis_rescan_operations_total.inc()

    # Before the SBOM loop: an embedded CBOM re-persists over the carried copy of the same asset.
    await _carry_over_external_results(scan_id, scan_doc, db)
    carry_over_error: Exception | None = None
    try:
        await _carry_over_crypto_assets(scan_id, scan_doc, db)
    except Exception as e:
        carry_over_error = e

    payload, sbom_load_failures, outcomes = await _analyse_sboms(ctx, fs, stored_ids, aggregator)
    sbom_parse_failures = payload.count(None) - sbom_load_failures

    # A rescan has no stored inventory to fall back on, so a partial payload would leave it without one.
    if (scan_doc.is_rescan and sbom_load_failures + sbom_parse_failures > 0) or (
        sbom_load_failures > 0 and sbom_load_failures == len(stored_ids)
    ):
        del payload, aggregator
        logger.error(
            "Scan %s: %d/%d SBOMs failed to load and %d failed to parse; storing no findings or dependencies",
            scan_id,
            sbom_load_failures,
            len(stored_ids),
            sbom_parse_failures,
        )
        if scan_doc.completed_at is not None:
            return await _keep_previous_analysis(ctx, load_start)
        analyzer_outcomes = _worst_outcomes(outcomes)
        verdict = _Verdict(
            SCAN_STATUS_FAILED,
            "SBOM could not be loaded or parsed for analysis",
            Stats(),
            0,
            0,
            analyzer_outcomes,
            *_failed_analyzer_names(analyzer_outcomes),
        )
        return await _conclude(ctx, verdict, load_start, aggregation_start_time)

    result_repo = AnalysisResultRepository(db)
    # Deferred past the unusable check so a kept analysis keeps its rows; this run's rows postdate load_start.
    await result_repo.delete_older_writes(
        {"scan_id": scan_id, "analyzer_name": {"$in": list(_ENGINE_RESULT_NAMES)}}, load_start
    )

    if scan_doc.scan_type == SCAN_TYPE_CBOM or any(p is not None and p.crypto_assets for p in payload):
        outcomes.extend(await _run_crypto_analyzers(ctx, aggregator))
        if carry_over_error is not None:
            outcomes.extend(_crypto_analyzers_failed(ctx, aggregator, carry_over_error))

    if not await _still_claimed(ctx):
        return None

    # External results enrich no dependency, so the enrichments are complete here.
    await _store_dependencies(payload, ctx.project_id, scan_id, db, aggregator.get_dependency_enrichments())
    del payload

    external_load_start = datetime.now(timezone.utc)
    outcomes.extend(await _aggregate_external_results(aggregator, result_repo, scan_id))

    aggregated_findings = aggregator.get_findings()
    _track_findings_metrics(aggregated_findings)
    del aggregator

    findings_to_insert, vulnerability_findings = _prepare_finding_records(
        aggregated_findings, scan_id, ctx.project_id, scan_doc.created_at
    )
    del aggregated_findings
    total_findings_count = len(findings_to_insert)

    component_languages = await _run_vuln_enrichments(ctx, vulnerability_findings, outcomes)
    refresh_vulnerability_info(findings_to_insert)

    if not await _still_claimed(ctx):
        return None

    persisted_findings_count = await _persist_findings_and_waivers(findings_to_insert, scan_id, ctx.project_id, db)
    del findings_to_insert, vulnerability_findings
    stats, ignored_count = await calculate_comprehensive_stats(db, scan_id, component_languages)

    analyzer_outcomes = _worst_outcomes(outcomes)
    failed_analyzers, enrichment_failures = _failed_analyzer_names(analyzer_outcomes)
    partial_reasons = _partial_run_reasons(
        failed_analyzers,
        sbom_load_failures,
        sbom_parse_failures,
        len(stored_ids),
        persisted_findings_count,
        total_findings_count,
    )
    final_status, final_error = _final_scan_status(scan_id, partial_reasons)
    verdict = _Verdict(
        final_status,
        final_error,
        stats,
        persisted_findings_count,
        ignored_count,
        analyzer_outcomes,
        failed_analyzers,
        enrichment_failures,
    )
    return await _conclude(ctx, verdict, external_load_start, aggregation_start_time)
