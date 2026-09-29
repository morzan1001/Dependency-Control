import asyncio
import logging
import os
import re
import uuid
from collections import Counter
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import WAIVER_SCOPE_FILE, WAIVER_SCOPE_FINDING, WAIVER_SCOPE_RULE
from app.models.finding import LOCATION_FINDING_TYPES
from app.models.stats import Stats
from app.models.waiver import Waiver
from app.services.analysis.stats import calculate_comprehensive_stats

if TYPE_CHECKING:
    from app.services.waivers.matching import MatchFinding, WaiverApplication

logger = logging.getLogger(__name__)

# A contending recalc waits (at most ~6.2s) for the holder rather than dropping, so both waiver changes land.
_LOCK_MAX_RETRIES = 5
_LOCK_RETRY_BASE_DELAY = 0.2
_LOCK_TTL_SECONDS = 300
# A build finalized during a pass heads next, and the engine re-stamps it only while a waiver is active.
_HEAD_PASSES = 3

# Waiver field mapping: waiver field -> finding query field
_WAIVER_FIELD_MAP = {
    "finding_id": "finding_id",
    "package_name": "component",
    "package_version": "version",
    "finding_type": "type",
}


def _strip_line_number(finding_id: str) -> str | None:
    """Strip the trailing ``-<line_number>`` from a SAST finding ID, so file-scope matching covers
    every line of the same rule + file.
    """
    parts = finding_id.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return None


def _extract_rule_prefix(finding_id: str, component: str) -> str | None:
    """Extract ``{SCANNER}-{rule_id}`` from a SAST/IAC ``{SCANNER}-{rule_id}-{file_path}-{line}``
    ID, given ``component = {file_path}``, so rule-scope waivers match the rule across all files.
    """
    file_prefix = _strip_line_number(finding_id)
    if not file_prefix:
        return None
    suffix = f"-{component}"
    if file_prefix.endswith(suffix):
        return file_prefix[: -len(suffix)]
    return None


def _resolve_finding_id_query(
    finding_id: str,
    scope: str,
    component: str,
) -> str | dict[str, str]:
    """Resolve the MongoDB query value for ``finding_id`` based on waiver scope."""
    if scope == WAIVER_SCOPE_FILE:
        prefix = _strip_line_number(finding_id)
        if prefix:
            return {"$regex": f"^{re.escape(prefix)}-\\d+$"}
    elif scope == WAIVER_SCOPE_RULE:
        rule_prefix = _extract_rule_prefix(finding_id, component)
        if rule_prefix:
            return {"$regex": f"^{re.escape(rule_prefix)}-"}
    return finding_id


def _build_waiver_query(waiver: Waiver) -> dict[str, str | dict[str, str]]:
    """Build a finding query dict from a waiver's matching fields."""
    scope = waiver.scope or WAIVER_SCOPE_FINDING
    query: dict[str, str | dict[str, str]] = {}

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
        if waiver_field == "package_name" and scope == WAIVER_SCOPE_RULE:
            continue

        if waiver_field == "finding_id" and scope in (WAIVER_SCOPE_FILE, WAIVER_SCOPE_RULE):
            query[query_field] = _resolve_finding_id_query(
                value,
                scope,
                waiver.package_name or "",
            )
        else:
            query[query_field] = value

    return query


async def _record_match_outcome(waiver_repo: Any, waiver: Waiver, scan_id: str, count: int) -> None:
    """Persist what a waiver suppressed so an orphaned waiver is visible in the UI."""
    if waiver_repo is None:
        return
    if waiver.last_eval_scan_id != scan_id or waiver.last_match_count != count:
        await waiver_repo.update(waiver.id, {"last_eval_scan_id": scan_id, "last_match_count": count})


async def _apply_waivers(finding_repo: Any, scan_id: str, waivers: list[Waiver], waiver_repo: Any = None) -> None:
    """Apply all waivers for a scan; ``waiver_repo`` records each waiver's match count.

    Only the caller that owns the authoritative pass supplies ``waiver_repo`` — the engine's
    initial persistence routes location waivers through here too and its counts would be
    superseded by the signature pass in the recalculation that follows.
    """
    for waiver in waivers:
        if waiver.vulnerability_id:
            matched = await finding_repo.apply_vulnerability_waiver(
                scan_id=scan_id,
                vulnerability_id=waiver.vulnerability_id,
                waived=True,
                waiver_reason=waiver.reason,
                scope=_build_waiver_query(waiver),
            )
            await _record_match_outcome(waiver_repo, waiver, scan_id, matched)
            continue

        query = _build_waiver_query(waiver)

        # A waiver with no concrete matching criteria produces an empty query. Passing
        # {} to apply_finding_waiver would match (and waive) EVERY finding in the scan,
        # silently suppressing all security findings. Skip and log instead. Legitimate
        # waivers always carry at least one of finding_id/package_name/package_version/
        # finding_type (or a vulnerability_id, handled above).
        if not query:
            logger.warning(
                "Skipping waiver %s: no matching criteria (empty query) — refusing to waive every finding in scan %s",
                getattr(waiver, "id", "?"),
                scan_id,
            )
            continue

        matched = await finding_repo.apply_finding_waiver(
            scan_id=scan_id,
            query=query,
            waived=True,
            waiver_reason=waiver.reason,
        )
        # finding_id is not unique per scan for license/eol findings, so an unscoped waiver
        # can blanket dozens of unrelated components.
        if matched > 1 and not waiver.package_name:
            logger.warning(
                "Waiver %s (%s, finding_id=%s) has no package scope and suppresses %d findings in scan %s",
                waiver.id,
                waiver.finding_type,
                waiver.finding_id,
                matched,
                scan_id,
            )
        await _record_match_outcome(waiver_repo, waiver, scan_id, matched)


def _is_signature_waiver(waiver: Any) -> bool:
    """True if a waiver should be applied via the signature orchestrator rather than the legacy
    finding_id query. File/rule scope keep their broad semantics on the legacy _build_waiver_query
    path; within finding scope a location-typed waiver without a signature qualifies so the
    back-fill can give it one, and untyped non-location ones stay legacy so they are never
    silently dropped."""
    if getattr(waiver, "scope", WAIVER_SCOPE_FINDING) != WAIVER_SCOPE_FINDING:
        return False
    if getattr(waiver, "match", None) is not None:
        return True
    return waiver.finding_type in LOCATION_FINDING_TYPES


def _safe_match_signature(raw: dict, context: str) -> Any | None:
    """Build a MatchSignature from a stored dict, returning None (and logging) if malformed.

    Skipping a malformed sub-document keeps the recalc reset+reapply from aborting and
    leaving findings transiently un-waived.
    """
    from pydantic import ValidationError

    from app.models.match_signature import MatchSignature

    try:
        return MatchSignature(**raw)
    except ValidationError:
        logger.warning("Skipping malformed match signature (%s)", context)
        return None


async def _apply_waivers_signature(finding_repo: Any, waiver_repo: Any, scan_id: str, waivers: list) -> None:
    """Apply non-vulnerability waivers to a scan's location-based findings via signature matching.

    Persists re-anchored waiver signatures and marks lapsed findings. Vulnerability-id waivers
    are handled separately by the caller via apply_vulnerability_waiver.
    """
    from app.services.waivers.matching import apply_waivers_to_findings

    docs = await finding_repo.find_location_findings(scan_id)
    await _backfill_legacy_waiver_signatures(waiver_repo, waivers, docs)
    findings, recomputed = _signed_match_findings(docs)
    enriched = _hydrate_waiver_signatures(waivers)

    app = apply_waivers_to_findings(findings, enriched)

    logger.info(
        "waiver signature apply: scan=%s waivers=%d waived=%d reanchored=%d lapsed=%d dormant=%d recomputed_sig=%d",
        scan_id,
        len(enriched),
        len(app.waived),
        len(app.reanchored),
        len(app.lapsed),
        len(app.dormant),
        recomputed,
    )
    if app.dormant:
        _log_dormant_waivers(scan_id, app.dormant, findings, enriched)

    await _persist_signature_application(finding_repo, waiver_repo, scan_id, app, enriched)


async def _backfill_legacy_waiver_signatures(waiver_repo: Any, waivers: list, docs: list[dict]) -> None:
    """Legacy waivers without a stored signature inherit the one of the finding they name by exact finding_id."""
    docs_by_legacy_id = {d.get("finding_id") or d["_id"]: d for d in docs}
    for w in waivers:
        if getattr(w, "match", None) is not None:
            continue
        legacy_doc = docs_by_legacy_id.get(getattr(w, "finding_id", None))
        if legacy_doc and legacy_doc.get("match"):
            sig = _safe_match_signature(legacy_doc["match"], f"back-fill waiver {getattr(w, 'id', '?')}")
            if sig is not None:
                w.match = sig
                await waiver_repo.update(w.id, {"match": legacy_doc["match"]})


def _signed_match_findings(docs: list[dict]) -> tuple[list["MatchFinding"], int]:
    """MatchFindings for the scan's docs, plus how many signatures were self-healed."""
    from app.services.waivers.matching import MatchFinding
    from app.services.waivers.signature import compute_match_signature_from_doc

    findings = []
    recomputed = 0
    for d in docs:
        stored = d.get("match")
        if stored:
            sig = _safe_match_signature(stored, f"finding {d['_id']}")
            if sig is None:
                continue  # malformed stored signature — skip rather than abort the batch
        else:
            # Self-heal: a missing stored signature would otherwise silently drop this finding
            # from the matchable set and orphan any waiver in its (rule_key,file_key) group.
            sig = compute_match_signature_from_doc(d)
            if sig is not None:
                recomputed += 1
        findings.append(MatchFinding(id=d["_id"], sig=sig))
    return findings, recomputed


def _hydrate_waiver_signatures(waivers: list) -> list:
    """Hydrate dict .match values into MatchSignatures and drop malformed ones; Waiver models pass through."""
    enriched = []
    for w in waivers:
        m = getattr(w, "match", None)
        if isinstance(m, dict):
            sig = _safe_match_signature(m, f"waiver {getattr(w, 'id', '?')}")
            if sig is None:
                continue  # malformed stored waiver signature — skip; others still applied
            w.match = sig
        enriched.append(w)
    return enriched


def _log_dormant_waivers(scan_id: str, dormant: dict[str, str], findings: list["MatchFinding"], enriched: list) -> None:
    group_sizes: dict[str, int] = {}
    for f in findings:
        if f.sig is not None:
            # \x00 delimiter: rule_key/file_key are scanner IDs and file paths; neither contains NUL (so no key collision).
            key = f"{f.sig.rule_key}\x00{f.sig.file_key}"
            group_sizes[key] = group_sizes.get(key, 0) + 1
    match_by_waiver = {w.id: getattr(w, "match", None) for w in enriched}
    for wid, dormant_reason in dormant.items():
        m = match_by_waiver.get(wid)
        rk = getattr(m, "rule_key", None)
        fk = getattr(m, "file_key", None)
        logger.warning(
            "waiver dormant: waiver=%s scan=%s reason=%s rule_key=%s file_key=%s last_line=%s group_findings=%d",
            wid,
            scan_id,
            dormant_reason,
            rk,
            fk,
            getattr(m, "last_line", None),
            group_sizes.get(f"{rk}\x00{fk}", 0),
        )


async def _persist_signature_application(
    finding_repo: Any, waiver_repo: Any, scan_id: str, app: "WaiverApplication", enriched: list
) -> None:
    # Record per-waiver outcome so orphaned waivers (suppressing 0 findings in the latest scan)
    # are visible in the UI. Covers dormant AND match=None waivers (both yield count 0).
    match_counts = Counter(app.waived.values())  # waiver_id -> #findings waived
    # getattr defaults guard pre-schema waiver docs; enriched items are Waiver instances.
    for w in enriched:
        count = match_counts.get(w.id, 0)
        if getattr(w, "last_eval_scan_id", None) != scan_id or getattr(w, "last_match_count", None) != count:
            await waiver_repo.update(w.id, {"last_eval_scan_id": scan_id, "last_match_count": count})

    # Group waive writes by reason for fewer queries.
    reason_by_waiver = {w.id: getattr(w, "reason", None) for w in enriched}
    by_reason: dict[str | None, list[str]] = {}
    for fid, wid in app.waived.items():
        by_reason.setdefault(reason_by_waiver.get(wid), []).append(fid)
    for reason, fids in by_reason.items():
        await finding_repo.set_waived(scan_id, fids, reason)

    if app.lapsed:
        await finding_repo.set_lapsed(scan_id, app.lapsed)

    # Persist re-anchored signatures + walked last_line (only when changed).
    for wid, new_sig in app.reanchored.items():
        await waiver_repo.update(wid, {"match": new_sig.model_dump()})


async def _restamp_scan(
    scan_id: str,
    db: AsyncIOMotorDatabase,
    waivers: list[Waiver],
    finding_repo: Any,
    waiver_repo: Any,
) -> Stats:
    """Re-apply the current waiver set to one scan and rewrite its stats from the result."""
    # 1. Reset waivers AND lapsed flags for this scan, nested vulnerability entries included
    await finding_repo.update_many(
        {"scan_id": scan_id},
        {"waived": False, "waiver_reason": None, "waiver_lapsed": False, "lapsed_waiver_id": None},
    )
    await finding_repo.reset_nested_vulnerability_waivers(scan_id)

    # 2. Apply vulnerability-id waivers, then signature-match the rest
    vuln_waivers = [w for w in waivers if w.vulnerability_id]
    non_vuln = [w for w in waivers if not w.vulnerability_id]
    legacy = [w for w in non_vuln if not _is_signature_waiver(w)]
    loc_waivers = [w for w in non_vuln if _is_signature_waiver(w)]
    await _apply_waivers(finding_repo, scan_id, vuln_waivers + legacy, waiver_repo)
    await _apply_waivers_signature(finding_repo, waiver_repo, scan_id, loc_waivers)

    # 3. Recompute the authoritative full Stats from the waiver writes above.
    stats = await calculate_comprehensive_stats(db, scan_id)
    ignored_count = await finding_repo.count({"scan_id": scan_id, "waived": True})

    from app.repositories.scans import ScanRepository

    await ScanRepository(db).update_raw(
        scan_id,
        {"$set": {"stats": stats.model_dump(), "ignored_count": ignored_count}},
    )
    return stats


async def _released_analysis_ids(db: AsyncIOMotorDatabase, project_id: str) -> list[str]:
    """The scans release mode reports for this project, one per environment.

    A waiver is a decision that holds now, not a property of the build it was written against, so
    revoking one has to reach the shipped build too — otherwise "what is in production" answers
    through flags frozen at analysis time and can report zero criticals against a build that has
    one. The scan's own age is disclosed rather than corrected; its waiver flags are corrected.
    """
    from app.repositories.scans import ScanRepository
    from app.services.releases import released_scan_ids

    marked = set((await released_scan_ids(db, project_id)).values())
    if not marked:
        return []
    resolved = await ScanRepository(db).freshest_in_lineage(marked)
    return sorted({analysis.scan_id for analysis in resolved.values()})


@asynccontextmanager
async def _stats_lock(db: AsyncIOMotorDatabase, project_id: str) -> AsyncIterator[bool]:
    """Hold the project's stats lock for the block; yields False when another holder kept it."""
    from app.repositories.distributed_locks import DistributedLocksRepository

    lock_repo = DistributedLocksRepository(db)
    lock_name = f"stats_recalc:{project_id}"
    holder_id = f"stats-{os.getenv('HOSTNAME', 'unknown')}-{uuid.uuid4().hex[:8]}"
    acquired = False
    for attempt in range(_LOCK_MAX_RETRIES + 1):
        if attempt:
            await asyncio.sleep(_LOCK_RETRY_BASE_DELAY * (2 ** (attempt - 1)))
        if acquired := await lock_repo.acquire_lock(lock_name, holder_id, _LOCK_TTL_SECONDS):
            break
    if not acquired:
        logger.warning(f"Could not acquire {lock_name} after {_LOCK_MAX_RETRIES} retries; stats may be stale")
    try:
        yield acquired
    finally:
        if acquired:
            await lock_repo.release_lock(lock_name, holder_id)


async def recalculate_project_stats(
    project_id: str, db: AsyncIOMotorDatabase, restamp: Sequence[str] = ()
) -> Stats | None:
    """Re-stamp the active waivers onto head, the released scans and ``restamp``, and re-cache head; returns head's
    new stats, or None without a project, a head or the lock (released scans may be re-stamped by then)."""
    from app.repositories.findings import FindingRepository
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository
    from app.repositories.waivers import WaiverRepository

    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    waiver_repo = WaiverRepository(db)

    async with _stats_lock(db, project_id) as locked:
        project = await ProjectRepository(db).get_by_id(project_id) if locked else None
        if not project:
            return None
        scan_id = (await scan_repo.get_latest_active_scan_ids([project])).get(project_id)
        released_ids = sorted({*await _released_analysis_ids(db, project_id), *restamp} - {scan_id})
        logger.info(f"Recalculating stats for project {project_id} (head {scan_id}, released {released_ids})")

        waivers = await waiver_repo.find_active_for_project(project_id, include_global=True)
        # Head last: every pass writes each waiver's last_eval_scan_id and re-anchored signature,
        # and those describe head.
        for released_id in released_ids:
            await _restamp_scan(released_id, db, waivers, finding_repo, waiver_repo)
        for _ in range(_HEAD_PASSES):
            if not scan_id:
                return None
            stats = await _restamp_scan(scan_id, db, waivers, finding_repo, waiver_repo)
            head = await scan_repo.sync_project_head(project_id)
            if head == scan_id:
                return stats
            scan_id = head
        return None


async def refresh_scan_stats(db: AsyncIOMotorDatabase, project_id: str, scan_id: str) -> None:
    """Recompute one scan's stats under the project's stats lock and re-cache the project's head."""
    from app.repositories.scans import ScanRepository

    async with _stats_lock(db, project_id) as locked:
        if not locked:
            return
        scan_repo = ScanRepository(db)
        stats = await calculate_comprehensive_stats(db, scan_id)
        await scan_repo.update_raw(scan_id, {"$set": {"stats": stats.model_dump()}})
        await scan_repo.sync_project_head(project_id)


async def recalculate_all_projects(db: AsyncIOMotorDatabase) -> None:
    """Recalculate stats for every project. Resource intensive."""
    logger.info("Starting global stats recalculation")
    async for project in db.projects.find({}, {"_id": 1}):
        await recalculate_project_stats(project["_id"], db)
    logger.info("Global stats recalculation completed")
