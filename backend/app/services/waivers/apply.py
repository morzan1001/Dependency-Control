"""The one waiver restamp: brings a scan's stored waiver flags in line with the active waiver set."""

import hashlib
import logging
from collections import Counter, defaultdict
from typing import Any

from pydantic import ValidationError

from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver
from app.repositories.findings import FindingRepository
from app.repositories.waivers import WaiverRepository
from app.services.waivers.matching import (
    MatchFinding,
    WaiverApplication,
    advisory_filter,
    apply_waivers_to_findings,
    bind_legacy_signatures,
    may_bind_signature,
    record_matches,
    roll_up_advisories,
    route_waiver,
    waive_advisories,
    waiver_criteria,
    waiver_query,
)
from app.services.waivers.signature import compute_match_signature_from_doc

logger = logging.getLogger(__name__)

_FieldsById = dict[str, dict[str, Any]]

# What a pass writes (its outcome, and the signature it follows the finding with), when an active waiver expires,
# and the creation time (defaulted on load for a document without one) do not change the decision a scan carries.
_NOT_STAMPED = {"last_eval_scan_id", "last_match_count", "match", "expiration_date", "is_active", "created_at"}


def waiver_fingerprint(waivers: list[Waiver]) -> str:
    """Names the waiver set a scan was stamped with, from what decides the stamping."""
    dumps = sorted(w.model_dump_json(exclude=_NOT_STAMPED) for w in waivers)
    return hashlib.sha256("\n".join(dumps).encode()).hexdigest()


async def restamp_waivers(
    finding_repo: FindingRepository, waiver_repo: WaiverRepository | None, scan_id: str, waivers: list[Waiver]
) -> Counter[str]:
    """Bring one scan's waiver flags in line with ``waivers``, writing only the findings whose flags change, and
    return how many findings each waiver matched there.

    ``waiver_repo``, when given, records what each project waiver matched there and where its signature now is.
    """
    finding_fields: _FieldsById = defaultdict(dict)
    counts: Counter[str] = Counter()

    signed = await _signed_location_findings(finding_repo, scan_id, waivers, finding_fields)
    bound = bind_legacy_signatures(waivers, {legacy_id: finding.sig for legacy_id, finding in signed})
    routed: dict[str, list[Waiver]] = defaultdict(list)
    for waiver in waivers:
        routed[route_waiver(waiver)].append(waiver)

    waived = await _stamp_advisories(finding_repo, scan_id, routed["vulnerability"], counts, finding_fields)
    waived |= await _query_matches(finding_repo, scan_id, routed["query"], counts)
    app = _signature_matches(scan_id, [finding for _, finding in signed], routed["signature"])
    reasons = {w.id: w.reason for w in waivers}
    waived |= {fid: reasons[wid] for fid, wid in app.waived.items()}
    counts.update(app.waived.values())

    await _stage_flag_changes(finding_repo, scan_id, waived, app.lapsed, finding_fields)
    await finding_repo.set_fields(scan_id, finding_fields)

    if waiver_repo is not None:
        await waiver_repo.set_fields_many(_waiver_bookkeeping(waivers, scan_id, counts, bound, app))
    return counts


def _safe_match_signature(raw: dict, context: str) -> MatchSignature | None:
    """Build a MatchSignature from a stored finding dict, returning None (and logging) if malformed."""
    try:
        return MatchSignature(**raw)
    except ValidationError:
        logger.warning("Skipping malformed match signature (%s)", context)
        return None


async def _signed_location_findings(
    finding_repo: FindingRepository, scan_id: str, waivers: list[Waiver], finding_fields: _FieldsById
) -> list[tuple[str, MatchFinding]]:
    """The scan's location findings with their signatures and the finding_id a legacy waiver names them by, loaded
    only when a waiver can use them. A signature recomputed because none was stored is staged to persist."""
    if not any(route_waiver(w) == "signature" or may_bind_signature(w) for w in waivers):
        return []
    signed = []
    for doc in await finding_repo.find_location_findings(scan_id):
        if doc.get("match"):
            sig = _safe_match_signature(doc["match"], f"finding {doc['_id']}")
        elif (sig := compute_match_signature_from_doc(doc)) is not None:
            finding_fields[doc["_id"]]["match"] = sig.model_dump()
        if sig is not None:
            signed.append((doc.get("finding_id") or doc["_id"], MatchFinding(id=doc["_id"], sig=sig)))
    return signed


async def _stamp_advisories(
    finding_repo: FindingRepository,
    scan_id: str,
    waivers: list[Waiver],
    counts: Counter[str],
    finding_fields: _FieldsById,
) -> dict[str, str | None]:
    """Recompute the advisories of every vulnerability document a waiver names or that still holds a waived one,
    stage what changed, and return the documents that roll up to waived with their reason."""
    ids = [w.vulnerability_id for w in waivers if w.vulnerability_id]
    clause = {"$or": [{"details.vulnerabilities.waived": True}, *(advisory_filter(ids) if ids else [])]}
    scoped = [(waiver, waiver_criteria(waiver)) for waiver in waivers]
    waived: dict[str, str | None] = {}
    for doc in await finding_repo.find_advisory_state(scan_id, clause):
        stored = (doc.get("details") or {}).get("vulnerabilities") or []
        entries = [{**entry, "waived": False, "waiver_reason": None} for entry in stored]
        record = {**doc, "waived": False, "details": {"vulnerabilities": entries}}
        for waiver, criteria in scoped:
            if record_matches(record, criteria) and waive_advisories(record, waiver):
                counts[waiver.id] += 1
        roll_up_advisories(record)
        if record["waived"]:
            waived[doc["_id"]] = record["waiver_reason"]
        if changes := _advisory_changes(doc, stored, record):
            finding_fields[doc["_id"]].update(changes)
    return waived


def _advisory_changes(doc: dict[str, Any], stored: list[dict[str, Any]], record: dict[str, Any]) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    for index, (before, after) in enumerate(zip(stored, record["details"]["vulnerabilities"], strict=True)):
        if bool(before.get("waived")) != after["waived"] or before.get("waiver_reason") != after["waiver_reason"]:
            changes[f"details.vulnerabilities.{index}.waived"] = after["waived"]
            changes[f"details.vulnerabilities.{index}.waiver_reason"] = after["waiver_reason"]
    if record.get("severity") != doc.get("severity"):
        changes["severity"] = record["severity"]
    return changes


async def _query_matches(
    finding_repo: FindingRepository, scan_id: str, waivers: list[Waiver], counts: Counter[str]
) -> dict[str, str | None]:
    waived: dict[str, str | None] = {}
    for waiver in waivers:
        query = waiver_query(waiver)
        # An empty query would waive every finding in the scan.
        if not query:
            logger.warning(
                "Skipping waiver %s: no matching criteria, it would waive all of scan %s", waiver.id, scan_id
            )
            continue
        ids = await finding_repo.find_ids(scan_id, query)
        counts[waiver.id] = len(ids)
        # finding_id is not unique per scan for license/eol findings, so an unscoped waiver can blanket
        # dozens of unrelated components.
        if len(ids) > 1 and not waiver.package_name:
            logger.warning(
                "Waiver %s (%s, finding_id=%s) has no package scope and suppresses %d findings in scan %s",
                waiver.id,
                waiver.finding_type,
                waiver.finding_id,
                len(ids),
                scan_id,
            )
        waived |= dict.fromkeys(ids, waiver.reason)
    return waived


def _signature_matches(scan_id: str, findings: list[MatchFinding], waivers: list[Waiver]) -> WaiverApplication:
    app = apply_waivers_to_findings(findings, waivers)
    if not waivers:
        return app
    logger.info(
        "waiver signature apply: scan=%s waivers=%d waived=%d reanchored=%d refreshed=%d lapsed=%d dormant=%d",
        scan_id,
        len(waivers),
        len(app.waived),
        len(app.reanchored),
        len(app.refreshed),
        len(app.lapsed),
        len(app.dormant),
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
    return app


async def _stage_flag_changes(
    finding_repo: FindingRepository,
    scan_id: str,
    waived: dict[str, str | None],
    lapsed: dict[str, str],
    finding_fields: _FieldsById,
) -> None:
    """Stage the waived and lapsed flags that differ from what the scan stores; a stored flag nothing targets clears."""
    current = {doc["_id"]: doc for doc in await finding_repo.find_waiver_state(scan_id)}
    for fid, doc in current.items():
        if doc.get("waived") and fid not in waived:
            finding_fields[fid].update(waived=False, waiver_reason=None)
        if doc.get("waiver_lapsed") and fid not in lapsed:
            finding_fields[fid].update(waiver_lapsed=False, lapsed_waiver_id=None)
    for fid, reason in waived.items():
        doc = current.get(fid, {})
        if not doc.get("waived") or doc.get("waiver_reason") != reason:
            finding_fields[fid].update(waived=True, waiver_reason=reason)
    for fid, wid in lapsed.items():
        doc = current.get(fid, {})
        if not doc.get("waiver_lapsed") or doc.get("lapsed_waiver_id") != wid:
            finding_fields[fid].update(waiver_lapsed=True, lapsed_waiver_id=wid)


def _waiver_bookkeeping(
    waivers: list[Waiver],
    scan_id: str,
    counts: Counter[str],
    bound: dict[str, MatchSignature],
    app: WaiverApplication,
) -> _FieldsById:
    """What changed about each project waiver: its match count, a back-filled or walked signature. A global waiver
    spans projects, so no single project's outcome or location is its own."""
    fields: _FieldsById = defaultdict(dict)
    for waiver in waivers:
        if waiver.last_eval_scan_id != scan_id or waiver.last_match_count != counts[waiver.id]:
            fields[waiver.id].update(last_eval_scan_id=scan_id, last_match_count=counts[waiver.id])
    for wid, sig in (bound | app.refreshed | app.reanchored).items():
        fields[wid]["match"] = sig.model_dump()
    project_waivers = {w.id for w in waivers if w.project_id}
    return {wid: f for wid, f in fields.items() if wid in project_waivers}
