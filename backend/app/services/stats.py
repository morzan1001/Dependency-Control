import asyncio
import logging
import os
import re
from collections import Counter
from typing import TYPE_CHECKING, Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.stats import Stats
from app.models.waiver import Waiver
from app.services.analysis.stats import calculate_comprehensive_stats

if TYPE_CHECKING:
    from app.models.match_signature import MatchSignature
    from app.services.waivers.matching import MatchFinding, WaiverApplication

logger = logging.getLogger(__name__)

# Lock-acquisition retry policy for recalculate_project_stats. Recalc is triggered
# fire-and-forget from waiver CRUD endpoints, so a dropped run (None return) leaves
# stats stale until an unrelated event re-triggers it. Bounded exponential backoff
# lets a contending run wait for the current holder to finish and then recompute
# against the fully-committed waiver set. Total worst-case wait ~= 0.2*(2^5-1) = 6.2s.
_LOCK_MAX_RETRIES = 5
_LOCK_RETRY_BASE_DELAY = 0.2

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
    if scope == "file":
        prefix = _strip_line_number(finding_id)
        if prefix:
            return {"$regex": f"^{re.escape(prefix)}-\\d+$"}
    elif scope == "rule":
        rule_prefix = _extract_rule_prefix(finding_id, component)
        if rule_prefix:
            return {"$regex": f"^{re.escape(rule_prefix)}-"}
    return finding_id


def _build_waiver_query(waiver: Waiver) -> dict[str, str | dict[str, str]]:
    """Build a finding query dict from a waiver's matching fields."""
    scope = waiver.scope or "finding"
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
    from app.repositories.findings import FindingRepository

    if getattr(waiver, "scope", "finding") != "finding":
        return False
    if getattr(waiver, "match", None) is not None:
        return True
    return waiver.finding_type in FindingRepository._LOCATION_TYPES


def _safe_match_signature(raw: dict, context: str) -> "MatchSignature | None":
    """Build a MatchSignature from a stored finding dict, returning None (and logging) if malformed.

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


async def _apply_waivers_signature(
    finding_repo: Any, waiver_repo: Any | None, scan_id: str, waivers: list[Waiver]
) -> None:
    """Apply finding-scope location waivers to a scan by signature; ``waiver_repo``, when given, records
    each waiver's outcome and walked signature. Vulnerability-id waivers are handled by the caller."""
    from app.services.waivers.matching import apply_waivers_to_findings

    if not waivers:
        return
    signed, recomputed = _signed_match_findings(await finding_repo.find_location_findings(scan_id))
    await _backfill_legacy_waiver_signatures(waiver_repo, waivers, {legacy_id: f.sig for legacy_id, f in signed})

    app = apply_waivers_to_findings([f for _, f in signed], waivers)

    logger.info(
        "waiver signature apply: scan=%s waivers=%d waived=%d reanchored=%d refreshed=%d lapsed=%d dormant=%d "
        "recomputed_sig=%d",
        scan_id,
        len(waivers),
        len(app.waived),
        len(app.reanchored),
        len(app.refreshed),
        len(app.lapsed),
        len(app.dormant),
        recomputed,
    )
    match_by_waiver = {w.id: w.match for w in waivers if w.match is not None}
    for wid, dormant_reason in app.dormant.items():
        m = match_by_waiver[wid]
        logger.warning(
            "waiver dormant: waiver=%s scan=%s reason=%s rule_key=%s file_key=%s last_line=%s",
            wid,
            scan_id,
            dormant_reason,
            m.rule_key,
            m.file_key,
            m.last_line,
        )

    await _persist_signature_application(finding_repo, waiver_repo, scan_id, app, waivers)


async def _backfill_legacy_waiver_signatures(
    waiver_repo: Any | None, waivers: list[Waiver], sig_by_finding_id: "dict[str, MatchSignature]"
) -> None:
    """A waiver without a signature takes the one of the finding it names by exact finding_id."""
    for w in waivers:
        sig = sig_by_finding_id.get(w.finding_id or "")
        if w.match is None and sig is not None:
            w.match = sig
            if waiver_repo is not None:
                await waiver_repo.update(w.id, {"match": sig.model_dump()})


def _signed_match_findings(docs: list[dict]) -> "tuple[list[tuple[str, MatchFinding]], int]":
    """The scan's findings that carry a signature, with the finding_id a legacy waiver names them by,
    plus how many signatures were recomputed because none was stored."""
    from app.services.waivers.matching import MatchFinding
    from app.services.waivers.signature import compute_match_signature_from_doc

    signed = []
    recomputed = 0
    for d in docs:
        if d.get("match"):
            sig = _safe_match_signature(d["match"], f"finding {d['_id']}")
        else:
            sig = compute_match_signature_from_doc(d)
            recomputed += sig is not None
        if sig is not None:
            signed.append((d.get("finding_id") or d["_id"], MatchFinding(id=d["_id"], sig=sig)))
    return signed, recomputed


async def _persist_signature_application(
    finding_repo: Any, waiver_repo: Any | None, scan_id: str, app: "WaiverApplication", waivers: list[Waiver]
) -> None:
    reason_by_waiver = {w.id: w.reason for w in waivers}
    by_reason: dict[str | None, list[str]] = {}
    for fid, wid in app.waived.items():
        by_reason.setdefault(reason_by_waiver[wid], []).append(fid)
    for reason, fids in by_reason.items():
        await finding_repo.set_waived(scan_id, fids, reason)

    if app.lapsed:
        await finding_repo.set_lapsed(scan_id, app.lapsed)

    if waiver_repo is None:
        return
    match_counts = Counter(app.waived.values())
    for w in waivers:
        await _record_match_outcome(waiver_repo, w, scan_id, match_counts.get(w.id, 0))
    for wid, sig in (app.refreshed | app.reanchored).items():
        await waiver_repo.update(wid, {"match": sig.model_dump()})


async def _restamp_scan(
    scan_id: str,
    db: AsyncIOMotorDatabase,
    waivers: list[Waiver],
    finding_repo: Any,
    waiver_repo: Any | None,
) -> Stats:
    """Re-apply the current waiver set to one scan and rewrite its stats from the result; ``waiver_repo``,
    when given, records what each waiver matched there."""
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

    # 3. Recompute the authoritative full Stats; it reads from PRIMARY so it sees the waiver
    #    writes above.
    stats = await calculate_comprehensive_stats(db, scan_id)

    # 4. Calculate ignored count (read from PRIMARY after waiver writes)
    from pymongo import ReadPreference

    findings_primary = db.findings.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
    ignored_count = await findings_primary.count_documents({"scan_id": scan_id, "waived": True})

    from app.repositories import ScanRepository

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
    from app.repositories import ScanRepository
    from app.services.releases import released_scan_ids

    marked = set((await released_scan_ids(db, project_id)).values())
    if not marked:
        return []
    resolved = await ScanRepository(db).freshest_in_lineage(marked)
    return sorted({analysis.scan_id for analysis in resolved.values()})


async def recalculate_project_stats(project_id: str, db: AsyncIOMotorDatabase) -> Stats | None:
    """Recalculate a project's stats from its head scan and active waivers, and re-stamp the same
    waiver set onto the scans release mode reports.

    Resets ALL waivers for those scans and re-applies them under a distributed lock to
    prevent races when pods modify waivers concurrently. Returns None if project not found.
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
    if not project:
        return None

    scan_id = await ScanRepository(db).get_latest_active_scan_id(project)
    released_ids = [rid for rid in await _released_analysis_ids(db, project_id) if rid != scan_id]
    if not scan_id and not released_ids:
        return None

    # Acquire distributed lock to prevent race conditions
    lock_name = f"stats_recalc:{project_id}"
    holder_id = f"pod-{os.getenv('HOSTNAME', 'unknown')}-{os.getpid()}"

    # Retry with bounded exponential backoff instead of dropping the recalc on the
    # first contention. Two concurrent waiver changes must both end up reflected: the
    # loser of the lock waits for the holder to release, then recomputes against the
    # now-committed waiver set (avoids stale stats / stale ignored_count).
    lock_acquired = False
    for attempt in range(_LOCK_MAX_RETRIES + 1):
        lock_acquired = await lock_repo.acquire_lock(lock_name, holder_id, 300)
        if lock_acquired:
            break
        if attempt < _LOCK_MAX_RETRIES:
            delay = _LOCK_RETRY_BASE_DELAY * (2**attempt)
            logger.debug(
                f"Lock contention for stats recalculation of project {project_id}; "
                f"retrying in {delay:.2f}s (attempt {attempt + 1}/{_LOCK_MAX_RETRIES})."
            )
            await asyncio.sleep(delay)
    if not lock_acquired:
        logger.warning(
            f"Could not acquire lock for stats recalculation of project {project_id} "
            f"after {_LOCK_MAX_RETRIES} retries. Another process is holding it; "
            f"stats may be stale until the next recalculation."
        )
        return None

    try:
        logger.info(
            f"Recalculating stats for project {project_id} (head {scan_id}, released {released_ids}) "
            f"with lock {lock_name}"
        )

        waivers = await waiver_repo.find_active_for_project(project_id, include_global=True)
        # Head first and alone records waiver outcomes and signatures: those describe head, and the
        # released passes then see the signatures head back-filled.
        stats = await _restamp_scan(scan_id, db, waivers, finding_repo, waiver_repo) if scan_id else None
        for released_id in released_ids:
            await _restamp_scan(released_id, db, waivers, finding_repo, None)
        if stats is None:
            return None

        await project_repo.update_raw(project_id, {"$set": {"stats": stats.model_dump()}})

        logger.info(f"Stats updated for project {project_id}: {stats.model_dump()}")
        return stats

    finally:
        if lock_acquired:
            await lock_repo.release_lock(lock_name, holder_id)
            logger.debug(f"Released lock {lock_name} for project {project_id}")


async def recalculate_all_projects(db: AsyncIOMotorDatabase) -> int:
    """Recalculate stats for ALL projects; returns the number processed. Resource intensive."""
    logger.info("Starting global stats recalculation")
    count = 0
    async for project in db.projects.find({}, {"_id": 1}):
        await recalculate_project_stats(project["_id"], db)
        count += 1
    logger.info(f"Global stats recalculation completed: {count} projects processed")
    return count
