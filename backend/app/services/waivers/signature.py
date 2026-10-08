"""Compute a line-independent MatchSignature for location-based findings.

Dispatch is by anchor shape (finding_id prefix / details structure), not by FindingType,
so crypto-misuse SAST findings (id OPENGREP-...) are also covered.
"""

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from app.models.match_signature import AnchorKind, MatchSignature
from app.services.normalizers.utils import FindingIdPrefix

# Stored SAST findings can hold several scanners' entries; pick one deterministically.
_SCANNER_PREFERENCE = ("opengrep", "bearer")

_WS = re.compile(r"\s+")


def snippet_hash(text: str | None) -> str | None:
    """SHA-1 of whitespace-normalized text; None for blank input."""
    if not text:
        return None
    lines = [_WS.sub(" ", ln).strip() for ln in text.splitlines()]
    joined = "\n".join(ln for ln in lines if ln)
    if not joined:
        return None
    return hashlib.sha1(joined.encode("utf-8"), usedforsecurity=False).hexdigest()


def _select_sast_entry(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick a deterministic per-scanner entry (preference list, then sorted by (scanner, id))."""
    for pref in _SCANNER_PREFERENCE:
        matches = [e for e in entries if (e.get("scanner") or "") == pref]
        if matches:
            return min(matches, key=lambda e: str(e.get("id") or ""))
    return min(entries, key=lambda e: (str(e.get("scanner") or ""), str(e.get("id") or "")))


def _sast_signature(finding_id: str, details: Mapping[str, Any], component: str) -> MatchSignature:
    # An unmerged finding (crypto-misuse rules keep their own type) is its own single entry.
    entries = details.get("sast_findings") or [
        {"scanner": finding_id.split("-", 1)[0].lower(), "id": details.get("rule_id"), "details": details}
    ]
    entry = _select_sast_entry(entries)
    edetails = entry.get("details") or {}
    rule_key = f"{entry.get('scanner') or 'unknown'}:{entry.get('id') or 'unknown'}"
    fingerprint = edetails.get("fingerprint")
    content_hash = snippet_hash(edetails.get("code_extract"))
    line = details.get("line") or (edetails.get("start") or {}).get("line")
    kind: AnchorKind
    if fingerprint:
        anchor, kind = fingerprint, "scanner_fp"
    else:
        # Without the scanner's fingerprint or the code, only the exact location identifies the instance.
        content_hash = content_hash or snippet_hash(f"{rule_key}\x00{component}\x00{line}")
        anchor, kind = content_hash, "content_hash"
    return MatchSignature(
        rule_key=rule_key,
        file_key=component,
        anchor=anchor,
        anchor_kind=kind,
        content_hash=content_hash,
        last_line=line,
        rule_keys=sorted({f"{e.get('scanner') or 'unknown'}:{e.get('id') or 'unknown'}" for e in entries}),
    )


def _iac_signature(details: Mapping[str, Any], component: str) -> MatchSignature:
    kics_key = f"KICS:{details.get('rule_id') or 'unknown'}"
    content_hash = snippet_hash("\n".join(str(details.get(k) or "") for k in ("actual_value", "expected_value")))
    similarity_id = details.get("similarity_id")
    search_key = details.get("search_key")
    kind: AnchorKind
    anchor, kind = (
        (similarity_id, "similarity_id")
        if similarity_id
        else (search_key, "search_key")
        if search_key
        else (content_hash, "content_hash")
    )
    return MatchSignature(
        rule_key=kics_key,
        file_key=component,
        anchor=anchor,
        anchor_kind=kind,
        content_hash=content_hash,
        last_line=(details.get("start") or {}).get("line"),
        rule_keys=[kics_key],
    )


def _secret_signature(finding_id: str, details: Mapping[str, Any], component: str) -> MatchSignature:
    detector = details.get("detector") or "unknown"
    secret_hash = finding_id.rsplit("-", 1)[-1]
    return MatchSignature(
        rule_key=detector,
        file_key=component,
        anchor=secret_hash,
        anchor_kind="secret_hash",
        content_hash=secret_hash,
        last_line=None,
        rule_keys=[detector],
    )


def compute_match_signature(
    finding_id: str | None, details: Mapping[str, Any] | None, component: str
) -> MatchSignature | None:
    """Return a MatchSignature for SAST/IaC/Secret findings (dispatched by id prefix / details), else None."""
    fid = finding_id or ""
    details = details or {}

    sast_prefixes = (f"{FindingIdPrefix.OPENGREP}-", f"{FindingIdPrefix.BEARER}-")
    if details.get("sast_findings") is not None or fid.startswith(sast_prefixes):
        return _sast_signature(fid, details, component)
    if fid.startswith(f"{FindingIdPrefix.KICS}-"):
        return _iac_signature(details, component)
    if fid.startswith(f"{FindingIdPrefix.SECRET}-"):
        return _secret_signature(fid, details, component)
    return None
