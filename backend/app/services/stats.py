import logging
import os
import re
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.stats import Stats
from app.models.waiver import Waiver
from app.services.analysis.stats import calculate_comprehensive_stats

logger = logging.getLogger(__name__)

# Waiver field mapping: waiver field -> finding query field
_WAIVER_FIELD_MAP = {
    "finding_id": "finding_id",
    "package_name": "component",
    "package_version": "version",
    "finding_type": "type",
}


def _strip_line_number(finding_id: str) -> Optional[str]:
    """Strip the trailing line number from a SAST finding ID to get the file-level prefix.

    SAST finding IDs end with ``-<line_number>``.  Stripping that suffix
    lets us match all findings for the same rule + file regardless of line.

    Example:
        ``BEARER-rule_id-src/file.js-102`` → ``BEARER-rule_id-src/file.js``
    """
    parts = finding_id.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return None


def _extract_rule_prefix(finding_id: str, component: str) -> Optional[str]:
    """Extract the scanner+rule prefix from a SAST/IAC finding ID.

    Given ``finding_id = {SCANNER}-{rule_id}-{file_path}-{line}``
    and ``component = {file_path}``, returns ``{SCANNER}-{rule_id}``.

    Used by "rule" scope waivers to match all findings for the same rule
    across all files in a project.

    Example:
        ``_extract_rule_prefix(
            "BEARER-javascript_lang_insufficiently_random_values-src/file.js-102",
            "src/file.js",
        )`` → ``"BEARER-javascript_lang_insufficiently_random_values"``
    """
    file_prefix = _strip_line_number(finding_id)
    if not file_prefix:
        return None
    suffix = f"-{component}"
    if file_prefix.endswith(suffix):
        return file_prefix[: -len(suffix)]
    return None


async def _resolve_active_scan_id(
    db: AsyncIOMotorDatabase, project_id: str, scan_id: str, deleted_branches: List[str]
) -> Optional[str]:
    """Resolve the active scan_id, skipping deleted branches if needed."""
    if not deleted_branches:
        return scan_id

    scan_doc = await db.scans.find_one({"_id": scan_id}, {"branch": 1})
    if not scan_doc or scan_doc.get("branch") not in deleted_branches:
        return scan_id

    active_scan = await db.scans.find_one(
        {"project_id": project_id, "branch": {"$nin": deleted_branches}, "status": "completed"},
        sort=[("created_at", -1)],
        projection={"_id": 1},
    )
    return active_scan["_id"] if active_scan else None


def _resolve_finding_id_query(
    finding_id: str,
    scope: str,
    component: str,
) -> str | Dict[str, str]:
    """Resolve the MongoDB query value for ``finding_id`` based on waiver scope."""
    if scope == "file":
        prefix = _strip_line_number(finding_id)
        if prefix:
            return {"$regex": f"^{re.escape(prefix)}-\\d+$"}
    elif scope == "rule":
        rule_prefix = _extract_rule_prefix(finding_id, component)
        if rule_prefix:
            return {"$regex": f"^{re.escape(rule_prefix)}-"}
    return finding_id


def _build_waiver_query(waiver: Waiver) -> Dict[str, str | Dict[str, str]]:
    """Build a finding query dict from a waiver's matching fields."""
    scope = waiver.scope or "finding"
    query: Dict[str, str | Dict[str, str]] = {}

    waiver_values = {
        "finding_id": waiver.finding_id,
        "package_name": waiver.package_name,
        "package_version": waiver.package_version,
        "finding_type": waiver.finding_type,
    }

    for waiver_field, query_field in _WAIVER_FIELD_MAP.items():
        value = waiver_values.get(waiver_field)
        if not value or value == "Unknown":
            continue

        # Rule-scope waivers must NOT filter by component (match all files)
        if waiver_field == "package_name" and scope == "rule":
            continue

        if waiver_field == "finding_id" and scope in ("file", "rule"):
            query[query_field] = _resolve_finding_id_query(
                value,
                scope,
                waiver.package_name or "",
            )
        else:
            query[query_field] = value

    return query


async def _apply_waivers(finding_repo: Any, scan_id: str, waivers: List[Waiver]) -> None:
    """Apply all waivers for a scan."""
    for waiver in waivers:
        query = _build_waiver_query(waiver)

        if waiver.vulnerability_id:
            await finding_repo.apply_vulnerability_waiver(
                scan_id=scan_id,
                vulnerability_id=waiver.vulnerability_id,
                waived=True,
                waiver_reason=waiver.reason,
            )
        else:
            await finding_repo.apply_finding_waiver(
                scan_id=scan_id,
                query=query,
                waived=True,
                waiver_reason=waiver.reason,
            )


def _is_signature_waiver(waiver: Any) -> bool:
    """True if a waiver should be applied via the signature orchestrator rather than the
    legacy finding_id query. Only instance-precise (scope="finding") waivers qualify: file/rule
    scope keep their broad semantics via the legacy _build_waiver_query path. Within finding
    scope, a waiver qualifies if it already carries a MatchSignature, or it explicitly targets a
    location-based finding type (so the back-fill can give it one). Untyped / non-location
    finding-scope waivers stay on the legacy path so they are never silently dropped."""
    from app.repositories.findings import FindingRepository

    if getattr(waiver, "scope", "finding") != "finding":
        return False
    if getattr(waiver, "match", None) is not None:
        return True
    return waiver.finding_type in FindingRepository._LOCATION_TYPES


def _safe_match_signature(raw: dict, context: str) -> Optional[Any]:
    """Build a MatchSignature from a stored dict, returning None (and logging) if malformed.

    Legacy data can carry a `match` sub-document that no longer satisfies the current
    schema. Skipping the malformed one keeps the recalc reset+reapply from aborting and
    leaving findings transiently un-waived (Finding 4).
    """
    from pydantic import ValidationError

    from app.models.match_signature import MatchSignature

    try:
        return MatchSignature(**raw)
    except ValidationError:
        logger.warning("Skipping malformed match signature (%s)", context)
        return None


async def _apply_waivers_signature(finding_repo: Any, waiver_repo: Any, scan_id: str, waivers: List) -> None:
    """Apply non-vulnerability waivers to a scan's location-based findings via signature matching.

    Persists re-anchored waiver signatures and marks lapsed findings. Vulnerability-id waivers
    are handled separately by the caller via apply_vulnerability_waiver.
    """
    from app.services.waivers.matching import MatchFinding, apply_waivers_to_findings

    docs = await finding_repo.find_location_findings(scan_id)

    # Lazy back-fill: legacy finding-scope waivers without a stored signature inherit the
    # signature of the finding they currently match by exact finding_id.
    docs_by_legacy_id = {d.get("finding_id") or d["_id"]: d for d in docs}
    for w in waivers:
        if getattr(w, "match", None) is None:
            legacy_doc = docs_by_legacy_id.get(getattr(w, "finding_id", None))
            if legacy_doc and legacy_doc.get("match"):
                sig = _safe_match_signature(legacy_doc["match"], f"back-fill waiver {getattr(w, 'id', '?')}")
                if sig is not None:
                    w.match = sig
                    await waiver_repo.update(w.id, {"match": legacy_doc["match"]})

    findings = []
    for d in docs:
        sig = None
        if d.get("match"):
            sig = _safe_match_signature(d["match"], f"finding {d['_id']}")
            if sig is None:
                continue  # malformed stored signature — skip rather than abort the batch
        findings.append(MatchFinding(id=d["_id"], sig=sig))

    # Hydrate waiver .match into MatchSignature objects (waivers may arrive as Waiver models already).
    enriched = []
    for w in waivers:
        m = getattr(w, "match", None)
        if isinstance(m, dict):
            sig = _safe_match_signature(m, f"waiver {getattr(w, 'id', '?')}")
            if sig is None:
                continue  # malformed stored waiver signature — skip; others still applied
            w.match = sig
        enriched.append(w)

    app = apply_waivers_to_findings(findings, enriched)

    # Group waive writes by reason for fewer queries.
    reason_by_waiver = {w.id: getattr(w, "reason", None) for w in enriched}
    by_reason: Dict[Optional[str], List[str]] = {}
    for fid, wid in app.waived.items():
        by_reason.setdefault(reason_by_waiver.get(wid), []).append(fid)
    for reason, fids in by_reason.items():
        await finding_repo.set_waived(scan_id, fids, reason)

    if app.lapsed:
        await finding_repo.set_lapsed(scan_id, app.lapsed)

    # Persist re-anchored signatures + walked last_line (only when changed).
    for wid, new_sig in app.reanchored.items():
        await waiver_repo.update(wid, {"match": new_sig.model_dump()})


async def recalculate_project_stats(project_id: str, db: AsyncIOMotorDatabase) -> Optional[Stats]:
    """
    Recalculates statistics for a project based on its latest scan and active waivers.
    This should be called whenever waivers are added, updated, or removed.

    WARNING: This function resets ALL waivers for the scan and re-applies them.
    This is a CRITICAL operation protected by distributed locking to prevent
    race conditions when multiple pods modify waivers concurrently.

    Args:
        project_id: The ID of the project to recalculate stats for
        db: Database connection

    Returns:
        The calculated Stats object, or None if project not found
    """
    from app.repositories import (
        DistributedLocksRepository,
        FindingRepository,
        ProjectRepository,
        ScanRepository,
        WaiverRepository,
    )

    project_repo = ProjectRepository(db)
    finding_repo = FindingRepository(db)
    waiver_repo = WaiverRepository(db)
    lock_repo = DistributedLocksRepository(db)

    project = await project_repo.get_by_id(project_id)
    if not project or not project.latest_scan_id:
        return None

    scan_id = await _resolve_active_scan_id(db, project_id, project.latest_scan_id, project.deleted_branches or [])
    if not scan_id:
        return None

    # Acquire distributed lock to prevent race conditions
    lock_name = f"stats_recalc:{project_id}"
    holder_id = f"pod-{os.getenv('HOSTNAME', 'unknown')}-{os.getpid()}"

    lock_acquired = await lock_repo.acquire_lock(lock_name, holder_id, 300)
    if not lock_acquired:
        logger.warning(
            f"Could not acquire lock for stats recalculation of project {project_id}. "
            f"Another process is already recalculating stats."
        )
        return None

    try:
        logger.info(f"Recalculating stats for project {project_id} (scan {scan_id}) with lock {lock_name}")

        # 1. Reset waivers AND lapsed flags for this scan
        await finding_repo.update_many(
            {"scan_id": scan_id},
            {"waived": False, "waiver_reason": None, "waiver_lapsed": False, "lapsed_waiver_id": None},
        )

        # 2. Fetch active waivers, apply vulnerability-id ones, then signature-match the rest
        waivers = await waiver_repo.find_active_for_project(project_id, include_global=True)
        for waiver in waivers:
            if waiver.vulnerability_id:
                await finding_repo.apply_vulnerability_waiver(
                    scan_id=scan_id, vulnerability_id=waiver.vulnerability_id,
                    waived=True, waiver_reason=waiver.reason,
                )
        non_vuln = [w for w in waivers if not w.vulnerability_id]
        legacy = [w for w in non_vuln if not _is_signature_waiver(w)]
        loc_waivers = [w for w in non_vuln if _is_signature_waiver(w)]
        await _apply_waivers(finding_repo, scan_id, legacy)
        await _apply_waivers_signature(finding_repo, waiver_repo, scan_id, loc_waivers)

        # 3. Compute the authoritative full Stats (severity counts, avg risk_score,
        #    adjusted_risk_score, threat_intel, reachability, prioritized) from the
        #    single canonical pipeline. This replaces the old partial $sum pipeline
        #    so recalc no longer clobbers the comprehensive stats. calculate_comprehensive_stats
        #    reads from PRIMARY for read-after-write consistency.
        stats = await calculate_comprehensive_stats(db, scan_id)

        # 4. Calculate ignored count (read from PRIMARY after waiver writes)
        from pymongo import ReadPreference

        findings_primary = db.findings.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
        ignored_count = await findings_primary.count_documents({"scan_id": scan_id, "waived": True})

        scan_repo = ScanRepository(db)
        await scan_repo.update_raw(
            scan_id,
            {"$set": {"stats": stats.model_dump(), "ignored_count": ignored_count}},
        )

        await project_repo.update_raw(project_id, {"$set": {"stats": stats.model_dump()}})

        logger.info(f"Stats updated for project {project_id}: {stats.model_dump()}")
        return stats

    finally:
        if lock_acquired:
            await lock_repo.release_lock(lock_name, holder_id)
            logger.debug(f"Released lock {lock_name} for project {project_id}")


async def recalculate_all_projects(db: AsyncIOMotorDatabase) -> int:
    """
    Recalculates statistics for ALL projects.
    Use with caution, as this can be resource intensive.

    Args:
        db: Database connection

    Returns:
        Number of projects recalculated
    """
    logger.info("Starting global stats recalculation")
    count = 0
    async for project in db.projects.find({}, {"_id": 1}):
        await recalculate_project_stats(project["_id"], db)
        count += 1
    logger.info(f"Global stats recalculation completed: {count} projects processed")
    return count
