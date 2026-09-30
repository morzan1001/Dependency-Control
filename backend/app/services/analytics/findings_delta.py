"""Findings-delta: match findings across two scans by a type-specific semantic key
(CVE id, secret finding_id, SAST rule id, ...) into the unified envelope.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import get_severity_value
from app.core.cve import display_vulnerability_id
from app.models.finding import CRYPTO_FINDING_TYPES
from app.repositories.base import find_window
from app.schemas.scan_delta import (
    DeltaCategory,
    FindingDeltaItem,
    ScanDeltaResponse,
    ScanDeltaTotals,
)
from app.services.component_identity import extract_artifact_name
from app.services.analytics._delta_pagination import MAX_FETCH, by_side, delta_truncation, paginate, pair_versions
from app.services.analytics._delta_reachability import side_reachability
from app.services.recommendation.common import live_cves

# Served by the {scan_id, component, version} index, so a capped side is cut at the same point in
# the identity space on both sides instead of at two arbitrary points in natural order.
_SIDE_SORT: list[tuple[str, int]] = [("component", 1), ("version", 1)]


def _first_id(details: dict[str, Any], *keys: str) -> str:
    """The first truthy ``details[k]`` among ``keys``, stringified; empty when none carries one."""
    for key in keys:
        value = details.get(key)
        if value:
            return str(value)
    return ""


def _joined_ids(entries: Any) -> str:
    return ",".join(sorted({str(e["id"]) for e in entries or [] if isinstance(e, dict) and e.get("id")}))


def _finding_id_identifier(finding: dict[str, Any]) -> str:
    return str(finding.get("finding_id") or "")


def _sast_identifier(finding: dict[str, Any]) -> str:
    """The merged rule-id set; the line moves with every edit above the hit, so it stays out."""
    return _joined_ids((finding.get("details") or {}).get("sast_findings"))


def _iac_identifier(finding: dict[str, Any]) -> str:
    """KICS's search_key names the matched resource; its similarity_id hashes the line for searchLine queries."""
    details = finding.get("details") or {}
    rule = _first_id(details, "rule_id")
    anchor = details.get("search_key") or (details.get("start") or {}).get("line")
    return f"{rule}:{anchor}" if rule and anchor is not None else rule


def _quality_identifier(finding: dict[str, Any]) -> str:
    """The child issue ids name only the component, so a version bump keeps the identity."""
    return _joined_ids((finding.get("details") or {}).get("quality_issues")) or _finding_id_identifier(finding)


_CRYPTO_ID_FIELDS = ("rule_id", "cipher_suite", "issuer_name")


def _crypto_identifier(finding: dict[str, Any]) -> str:
    details = finding.get("details") or {}
    return "|".join(str(details[k]) for k in _CRYPTO_ID_FIELDS if details.get(k))


def _vulnerability_identifier(finding: dict[str, Any], include_waived: bool) -> str:
    """Version plus the sorted advisory ids the side still reports, so a bump or a CVE gained or dropped
    reads as a change; ``include_waived`` keys every entry, the identity had no waiver applied."""
    entries = [e for e in (finding.get("details") or {}).get("vulnerabilities") or [] if isinstance(e, dict)]
    ids = _joined_ids(e for e in entries if include_waived or not e.get("waived"))
    version = finding.get("version") or ""
    return f"{version}|{ids}" if version and ids else ids


def _first_detail(*keys: str) -> tuple[Callable[[dict[str, Any]], str], tuple[str, ...]]:
    return (lambda f: _first_id(f.get("details") or {}, *keys)), tuple(f"details.{k}" for k in keys)


# Each extractor with the document paths it reads; "" means no stable id, and the description hash applies.
_FINDING_TYPE_IDENTIFIER: dict[str, tuple[Callable[[dict[str, Any]], str], tuple[str, ...]]] = {
    "sast": (_sast_identifier, ("details.sast_findings.id",)),
    "iac": (_iac_identifier, ("details.rule_id", "details.search_key", "details.start.line")),
    "secret": (_finding_id_identifier, ("finding_id",)),
    "outdated": (_finding_id_identifier, ("finding_id",)),
    "quality": (_quality_identifier, ("details.quality_issues.id", "finding_id")),
    "license": _first_detail("license"),
    "eol": _first_detail("eol_date"),
    "malware": _first_detail("imitated_package", "osv_id", "reference"),
    **dict.fromkeys(CRYPTO_FINDING_TYPES, (_crypto_identifier, tuple(f"details.{k}" for k in _CRYPTO_ID_FIELDS))),
}


def _fallback_identifier(finding: dict[str, Any]) -> str:
    """Hash of description + found_in so an unidentifiable finding matches itself across scans."""
    digest_src = (finding.get("description") or "") + "|" + "|".join(sorted(finding.get("found_in") or []))
    return hashlib.sha1(digest_src.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]


def finding_identity_key(finding: dict[str, Any], *, include_waived: bool = False) -> tuple[str, str, str]:
    """Stable identity for matching the same finding across two scans. finding_id is deterministic, but
    crypto's embeds the per-scan bom-ref and a vulnerability's leaves out its advisories.

    ``include_waived`` keys a vulnerability record on every entry rather than only the live ones,
    which is the identity it would have carried had no waiver been applied to it.
    """
    ftype = finding.get("type") or ""
    component = finding.get("component") or ""

    if ftype == "vulnerability":
        # Scanners disagree on how far a package name is qualified; fold to the artifact name
        # so a requalified component reads as unchanged instead of removed + added. Other
        # types keep the raw component because theirs is a file path, not a package name.
        component = extract_artifact_name(component)
        identifier = _vulnerability_identifier(finding, include_waived)
    else:
        if ftype in CRYPTO_FINDING_TYPES:
            component = component.partition(" [bom-ref:")[0]
        extractor = _FINDING_TYPE_IDENTIFIER.get(ftype)
        identifier = extractor[0](finding) if extractor else ""
    if not identifier:
        identifier = _fallback_identifier(finding)

    return (ftype, component, identifier)


def advisory_keys(finding: dict[str, Any]) -> set[tuple[str, str]]:
    """One (artifact, CVE) pair per live advisory, independent of the version the record sits at."""
    artifact = extract_artifact_name(finding.get("component") or "")
    return {(artifact, cve) for cve in live_cves([finding.get("details")])}


# Projecting details.vulnerabilities to .id avoids pulling the full per-CVE payload (hundreds of MB
# on large scans) into the worker.
FINDING_IDENTITY_PROJECTION: dict[str, int] = dict.fromkeys(
    (
        "type",
        "component",
        "version",
        "description",
        "found_in",
        "details.vulnerabilities.id",
        "details.vulnerabilities.waived",
        *(path for _, paths in _FINDING_TYPE_IDENTIFIER.values() for path in paths),
    ),
    1,
)

# The identity fields plus what _to_item renders.
_FETCH_PROJECTION: dict[str, int] = {
    **FINDING_IDENTITY_PROJECTION,
    "severity": 1,
    "first_seen_at": 1,
    "details.vulnerabilities.resolved_cve": 1,
    "details.vulnerabilities.aliases": 1,
}


def _side_query(
    project_id: str,
    scan_id: str,
    finding_type: Iterable[str] | None,
    severity: Iterable[str] | None,
) -> dict:
    """The item set of one side before the waiver filter splits it."""
    query: dict = {"project_id": project_id, "scan_id": scan_id}
    if finding_type:
        query["type"] = {"$in": list(finding_type)}
    if severity:
        # Severity is stored UPPERCASE; normalise case-insensitive caller input for $in.
        query["severity"] = {"$in": [s.upper() for s in severity]}
    return query


async def _fetch_scan_findings(
    db: AsyncIOMotorDatabase,
    project_id: str,
    scan_id: str,
    finding_type: Iterable[str] | None,
    severity: Iterable[str] | None,
) -> tuple[list[dict], int]:
    # Waived risk is excluded from every other metric in the product; the delta answers what is
    # delivered, so it has to agree. Documents predating the flag carry no key and are not waived.
    query = _side_query(project_id, scan_id, finding_type, severity) | {"waived": {"$ne": True}}
    return await find_window(db["findings"], query, MAX_FETCH, projection=_FETCH_PROJECTION, sort=_SIDE_SORT)


def _waiver_touched_query(
    project_id: str,
    scan_id: str,
    finding_type: Iterable[str] | None,
    severity: Iterable[str] | None,
) -> dict:
    """Findings a waiver suppresses in whole or in part. A per-CVE waiver leaves the document
    level untouched, so asking only for ``waived: True`` reports nothing hidden while a waiver is
    hiding a critical."""
    return _side_query(project_id, scan_id, finding_type, severity) | {
        "$or": [{"waived": True}, {"details.vulnerabilities.waived": True}]
    }


async def _count_waived_out(
    db: AsyncIOMotorDatabase,
    project_id: str,
    scan_id: str,
    finding_type: Iterable[str] | None,
    severity: Iterable[str] | None,
) -> int:
    """Counted rather than derived from a fetch, so the number stays exact past MAX_FETCH."""
    count: int = await db["findings"].count_documents(
        _waiver_touched_query(project_id, scan_id, finding_type, severity)
    )
    return count


async def _fetch_waiver_touched(
    db: AsyncIOMotorDatabase,
    project_id: str,
    scan_id: str,
    finding_type: Iterable[str] | None,
    severity: Iterable[str] | None,
) -> list[dict]:
    """Read on its own budget so waived documents cannot consume the MAX_FETCH the live findings
    share and push delivered risk out of the delta."""
    cursor = (
        db["findings"]
        .find(_waiver_touched_query(project_id, scan_id, finding_type, severity), projection=_FETCH_PROJECTION)
        .sort(_SIDE_SORT)
        .limit(MAX_FETCH)
    )
    return [doc async for doc in cursor]


def _doc_severity(doc: dict) -> str:
    return doc.get("severity") or "UNKNOWN"


def _doc_type(doc: dict) -> str:
    return doc.get("type") or ""


def _to_item(doc: dict, change: str) -> FindingDeltaItem:
    details = doc.get("details") or {}
    found_in = doc.get("found_in") or []
    return FindingDeltaItem(
        change=change,
        finding_id=str(doc.get("finding_id") or doc.get("_id") or ""),
        finding_type=_doc_type(doc),
        severity=_doc_severity(doc),
        title=doc.get("description") or "",
        component=doc.get("component"),
        cve_id=display_vulnerability_id(details),
        file_path=(found_in[0] if found_in else None),
        first_seen=doc.get("first_seen_at"),
    )


def _to_changed_item(from_doc: dict, to_doc: dict) -> FindingDeltaItem:
    before, after = advisory_keys(from_doc), advisory_keys(to_doc)
    added_cves = sorted(cve for _, cve in after - before)
    dropped_cves = sorted(cve for _, cve in before - after)
    first_seen = [d["first_seen_at"] for d in (from_doc, to_doc) if d.get("first_seen_at")]
    return _to_item(to_doc, "changed").model_copy(
        update={
            "cve_id": next(iter(added_cves + dropped_cves), None),
            "from_version": from_doc.get("version"),
            "to_version": to_doc.get("version"),
            "added_cves": added_cves,
            "dropped_cves": dropped_cves,
            "first_seen": min(first_seen, default=None),
        }
    )


def _match(
    from_docs: Iterable[dict], to_docs: Iterable[dict], *, include_waived: bool = False
) -> tuple[int, list[dict], list[dict]]:
    """Pair the documents sharing an identity; returns the paired count and each side's unpaired documents."""
    paired, removed, added = 0, [], []
    for from_group, to_group in by_side(
        lambda doc: finding_identity_key(doc, include_waived=include_waived), from_docs, to_docs
    ).values():
        pairs, gone, new = pair_versions(from_group, to_group)
        paired += len(pairs)
        removed += gone
        added += new
    return paired, removed, added


def _split_changed(removed: list[dict], added: list[dict]) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """A vulnerability record whose version or advisories moved is the lone unpaired record of its
    artifact on each side."""
    vulnerable = [[d for d in docs if d.get("type") == "vulnerability"] for docs in (removed, added)]
    by_artifact = by_side(lambda doc: extract_artifact_name(doc.get("component") or ""), *vulnerable)
    changed = [(gone[0], new[0]) for gone, new in by_artifact.values() if len(gone) == len(new) == 1]
    paired = {doc["_id"] for pair in changed for doc in pair}
    return (
        changed,
        [d for d in removed if d["_id"] not in paired],
        [d for d in added if d["_id"] not in paired],
    )


def _waiver_only_changes(
    removed: list[dict],
    added: list[dict],
    changed: list[tuple[dict, dict]],
    from_sides: tuple[list[dict], list[dict]],
    to_sides: tuple[list[dict], list[dict]],
) -> int:
    """Reported items the same comparison would not have produced had no waiver applied.

    Waivers are re-evaluated only for the newest scan, so the older side's flags are frozen: a
    waiver that lapsed since makes a pre-existing finding read as added, and a waiver created since
    makes one read as removed. Both sides can hide the same number of findings while hiding
    different ones, so a count comparison cannot see either.
    """

    def unwaived(live: list[dict], touched: list[dict]) -> list[dict]:
        return list({doc["_id"]: doc for doc in (*live, *touched)}.values())

    _, still_removed, still_added = _match(unwaived(*from_sides), unwaived(*to_sides), include_waived=True)
    real = {doc["_id"] for doc in (*still_removed, *still_added)}
    return sum(doc["_id"] not in real for doc in (*removed, *added)) + sum(
        gone["_id"] not in real and new["_id"] not in real for gone, new in changed
    )


async def compute_findings_delta(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    from_scan: str,
    to_scan: str,
    page: int,
    page_size: int,
    change: str | None,
    severity: list[str] | None,
    finding_type: list[str] | None,
) -> ScanDeltaResponse:
    """Compute the delta between two scans' findings as a paginated envelope."""
    from_docs, from_live_total = await _fetch_scan_findings(db, project_id, from_scan, finding_type, severity)
    to_docs, to_live_total = await _fetch_scan_findings(db, project_id, to_scan, finding_type, severity)
    from_waived = await _fetch_waiver_touched(db, project_id, from_scan, finding_type, severity)
    to_waived = await _fetch_waiver_touched(db, project_id, to_scan, finding_type, severity)
    from_waived_excluded = await _count_waived_out(db, project_id, from_scan, finding_type, severity)
    to_waived_excluded = await _count_waived_out(db, project_id, to_scan, finding_type, severity)

    unchanged_count, unpaired_removed, unpaired_added = _match(from_docs, to_docs)
    changed, removed, added = _split_changed(unpaired_removed, unpaired_added)

    # Breakdowns cover the full added+removed populations so they reconcile with
    # totals.added + totals.removed, independent of the `change` filter that only scopes
    # the item list. Count from raw docs to avoid materialising MAX_FETCH Pydantic items.
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for doc in (*added, *removed):
        by_severity[_doc_severity(doc)] = by_severity.get(_doc_severity(doc), 0) + 1
        by_type[_doc_type(doc)] = by_type.get(_doc_type(doc), 0) + 1

    # Build Pydantic items only for the change-filtered set that is returned.
    items: list[FindingDeltaItem] = []
    if change in (None, "all", "added"):
        items.extend(_to_item(doc, "added") for doc in added)
    if change in (None, "all", "changed"):
        items.extend(_to_changed_item(gone, new) for gone, new in changed)
    if change in (None, "all", "removed"):
        items.extend(_to_item(doc, "removed") for doc in removed)

    # Stable sort (added, changed, removed, then severity, title, finding_id) for deterministic pagination.
    items.sort(key=lambda i: (i.change, -get_severity_value(i.severity), i.title, i.finding_id))

    paged, total_pages = paginate(items, page, page_size)

    return ScanDeltaResponse(
        from_scan_id=from_scan,
        to_scan_id=to_scan,
        project_id=project_id,
        category=DeltaCategory.FINDINGS,
        totals=ScanDeltaTotals(
            added=len(added),
            removed=len(removed),
            changed=len(changed),
            unchanged=unchanged_count,
            by_severity=by_severity,
            by_type=by_type,
        ),
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        items=paged,
        from_reachability=await side_reachability(db, from_scan),
        to_reachability=await side_reachability(db, to_scan),
        from_waived_excluded=from_waived_excluded,
        to_waived_excluded=to_waived_excluded,
        waiver_only_changes=_waiver_only_changes(
            removed, added, changed, (from_docs, from_waived), (to_docs, to_waived)
        ),
        # Both fetches per side feed the comparison, so coverage counts them together.
        truncation=delta_truncation(
            MAX_FETCH,
            from_compared=len(from_docs) + len(from_waived),
            from_total=from_live_total + from_waived_excluded,
            to_compared=len(to_docs) + len(to_waived),
            to_total=to_live_total + to_waived_excluded,
        ),
    )
