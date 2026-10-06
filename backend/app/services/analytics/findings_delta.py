"""Findings-delta: match findings across two scans by a type-specific semantic key
(CVE id, secret finding_id, SAST rule id, ...) into the unified envelope.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Callable, Iterable
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import get_severity_value
from app.core.cve import display_vulnerability_id
from app.models.finding import CRYPTO_FINDING_TYPES
from app.schemas.scan_delta import (
    DeltaCategory,
    FindingDeltaItem,
    ScanDeltaResponse,
    ScanDeltaTotals,
)
from app.services.component_identity import extract_artifact_name
from app.services.analytics._delta_pagination import both_sides, by_side, pair_versions
from app.services.recommendation.common import live_cves


def _first_id(details: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = details.get(key)
        if value:
            return str(value)
    return ""


def _joined_ids(entries: Any) -> str:
    return ",".join(sorted({str(e["id"]) for e in entries or [] if isinstance(e, dict) and e.get("id")}))


def _finding_id_identifier(finding: dict[str, Any]) -> str:
    return str(finding.get("finding_id") or "")


def sast_rule_ids(details: dict[str, Any]) -> list[str]:
    entries = details.get("sast_findings") or []
    return list(dict.fromkeys(str(e["id"]) for e in entries if isinstance(e, dict) and e.get("id")))


def _sast_identifier(finding: dict[str, Any]) -> str:
    """The merged rule-id set; the line moves with every edit above the hit, so it stays out."""
    return ",".join(sorted(sast_rule_ids(finding.get("details") or {})))


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
    """Version plus the reported advisory ids, so a bump or a CVE gained or dropped reads as a change."""
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
    """Cross-scan identity: crypto's finding_id embeds the per-scan bom-ref, a vulnerability's omits its advisories."""
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


# Only details.vulnerabilities.id: the full per-CVE payload reaches hundreds of MB on large scans.
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
IDENTITY_FIELDS = tuple(dict.fromkeys(path.split(".")[0] for path in FINDING_IDENTITY_PROJECTION))

# The identity fields, what _to_item renders and the flag that splits live from waived.
_FETCH_PROJECTION: dict[str, int] = {
    **FINDING_IDENTITY_PROJECTION,
    "waived": 1,
    "severity": 1,
    "first_seen_at": 1,
    "scan_created_at": 1,
    "details.vulnerabilities.resolved_cve": 1,
    "details.vulnerabilities.aliases": 1,
}


def _side_query(project_id: str, scan_id: str, finding_type: Iterable[str] | None) -> dict:
    """The item set of one side before the waiver filter splits it."""
    query: dict = {"project_id": project_id, "scan_id": scan_id}
    if finding_type:
        query["type"] = {"$in": list(finding_type)}
    return query


def _waiver_touched(doc: dict) -> bool:
    """A per-CVE waiver leaves the document-level flag unset."""
    entries = (doc.get("details") or {}).get("vulnerabilities") or []
    return doc.get("waived") is True or any(isinstance(e, dict) and e.get("waived") is True for e in entries)


async def _read_side(db: AsyncIOMotorDatabase, query: dict) -> tuple[list[dict], list[dict], int]:
    """The side's live records, every record and how many a waiver touches."""
    read = await db["findings"].find(query, _FETCH_PROJECTION).to_list(None)
    # The delivered risk, as in every other metric; documents predating the flag lack the key and count as unwaived.
    live = [doc for doc in read if doc.get("waived") is not True]
    return live, read, sum(map(_waiver_touched, read))


def _doc_severity(doc: dict) -> str:
    return doc.get("severity") or "UNKNOWN"


def _doc_type(doc: dict) -> str:
    return doc.get("type") or ""


def _first_seen(doc: dict) -> Any:
    """A copy stored without a detection date counts from its scan's, as the CVE SLA counts it."""
    return doc.get("first_seen_at") or doc.get("scan_created_at")


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
        first_seen=_first_seen(doc),
    )


def _to_changed_item(from_doc: dict, to_doc: dict) -> FindingDeltaItem:
    before, after = advisory_keys(from_doc), advisory_keys(to_doc)
    added_cves = sorted(cve for _, cve in after - before)
    dropped_cves = sorted(cve for _, cve in before - after)
    first_seen = [seen for d in (from_doc, to_doc) if (seen := _first_seen(d))]
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
) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """Pair the documents sharing an identity; returns the pairs and each side's unpaired documents."""
    pairs, removed, added = [], [], []
    for from_group, to_group in by_side(
        lambda doc: finding_identity_key(doc, include_waived=include_waived), from_docs, to_docs
    ).values():
        paired, gone, new = pair_versions(from_group, to_group)
        pairs += paired
        removed += gone
        added += new
    return pairs, removed, added


def _split_changed(removed: list[dict], added: list[dict]) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """A vulnerability record whose version or advisories moved is its artifact's lone unpaired record per side."""
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
    from_read: list[dict],
    to_read: list[dict],
) -> int:
    """Items only waivers produced: the older side's flags stay frozen while waivers lapse or get created."""
    _, still_removed, still_added = _match(from_read, to_read, include_waived=True)
    real = {doc["_id"] for doc in (*still_removed, *still_added)}
    return sum(doc["_id"] not in real for doc in (*removed, *added)) + sum(
        gone["_id"] not in real and new["_id"] not in real for gone, new in changed
    )


async def compare_findings(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    from_scan: str,
    to_scan: str,
    severity: list[str] | None,
    finding_type: list[str] | None,
) -> ScanDeltaResponse:
    (from_live, from_read, from_waived), (to_live, to_read, to_waived) = await both_sides(
        lambda scan_id: _read_side(db, _side_query(project_id, scan_id, finding_type)), from_scan, to_scan
    )

    # Severity is not part of the identity, so it filters after matching: a rescored finding stays one finding.
    wanted = {s.upper() for s in severity or ()}

    def kept(*docs: dict) -> bool:
        return not wanted or any(_doc_severity(doc) in wanted for doc in docs)

    pairs, unpaired_removed, unpaired_added = _match(from_live, to_live)
    changed, removed, added = _split_changed(unpaired_removed, unpaired_added)
    changed = [pair for pair in changed if kept(*pair)]
    removed = [doc for doc in removed if kept(doc)]
    added = [doc for doc in added if kept(doc)]

    items = [_to_item(doc, "added") for doc in added]
    items += (_to_changed_item(gone, new) for gone, new in changed)
    items += (_to_item(doc, "removed") for doc in removed)
    # finding_id breaks ties so pagination does not depend on fetch order.
    items.sort(key=lambda i: (i.change, -get_severity_value(i.severity), i.title, i.finding_id))

    return ScanDeltaResponse(
        from_scan_id=from_scan,
        to_scan_id=to_scan,
        project_id=project_id,
        category=DeltaCategory.FINDINGS,
        totals=ScanDeltaTotals(
            added=len(added),
            removed=len(removed),
            changed=len(changed),
            unchanged=sum(kept(*pair) for pair in pairs),
            by_severity=Counter(_doc_severity(doc) for doc in (*added, *removed)),
            by_type=Counter(_doc_type(doc) for doc in (*added, *removed)),
        ),
        items=items,
        from_waived_excluded=from_waived,
        to_waived_excluded=to_waived,
        waiver_only_changes=_waiver_only_changes(removed, added, changed, from_read, to_read),
    )
