"""Compute a line-independent MatchSignature for location-based findings.

Dispatch is by anchor shape (finding_id prefix / details structure), not by FindingType,
so crypto-misuse SAST findings (id OPENGREP-...) are also covered.
"""

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from app.models.match_signature import MatchSignature

# Deterministic preference when several scanners confirm one SAST finding.
_SCANNER_PREFERENCE = ("opengrep", "bearer")

_WS = re.compile(r"\s+")


class SignatureSource(Protocol):
    """Structural view of the fields signature derivation needs."""

    @property
    def id(self) -> str | None: ...
    @property
    def details(self) -> dict[str, Any] | None: ...
    @property
    def component(self) -> str: ...


@dataclass(frozen=True)
class _DocSignatureSource:
    id: str | None
    details: dict[str, Any] | None
    component: str


def normalize_snippet(text: str | None) -> str | None:
    """Whitespace-insensitive hash input. Empty/blank -> None (sentinel)."""
    if not text:
        return None
    lines = [_WS.sub(" ", ln).strip() for ln in text.splitlines()]
    joined = "\n".join(ln for ln in lines if ln)
    if not joined:
        return None
    return hashlib.sha1(joined.encode("utf-8"), usedforsecurity=False).hexdigest()


def _hash(text: str | None) -> str | None:
    return normalize_snippet(text)


def _select_sast_entry(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick a deterministic per-scanner entry (preference list, then sorted by (scanner, id))."""
    if not entries:
        return None
    for pref in _SCANNER_PREFERENCE:
        matches = [e for e in entries if (e.get("scanner") or "") == pref]
        if matches:
            return min(matches, key=lambda e: str(e.get("id") or ""))
    return min(entries, key=lambda e: (str(e.get("scanner") or ""), str(e.get("id") or "")))


def _sast_signature(finding: SignatureSource) -> MatchSignature | None:
    details = finding.details or {}
    entries = details.get("sast_findings") or []
    entry = _select_sast_entry(entries)
    if entry is None:
        return None
    edetails = entry.get("details") or {}
    scanner = entry.get("scanner") or "unknown"
    rule_id = entry.get("id") or "unknown"
    fingerprint = edetails.get("fingerprint") or edetails.get("old_fingerprint")
    content_hash = _hash(edetails.get("code_extract"))
    line = details.get("line") or (edetails.get("start") or {}).get("line")
    rule_keys = sorted({f"{e.get('scanner') or 'unknown'}:{e.get('id') or 'unknown'}" for e in entries})

    if fingerprint:
        return MatchSignature(
            rule_key=f"{scanner}:{rule_id}",
            file_key=finding.component,
            anchor=fingerprint,
            anchor_kind="scanner_fp",
            content_hash=content_hash,
            last_line=line,
            rule_keys=rule_keys,
        )
    return MatchSignature(
        rule_key=f"{scanner}:{rule_id}",
        file_key=finding.component,
        anchor=content_hash,
        anchor_kind="content_hash",
        content_hash=content_hash,
        last_line=line,
        rule_keys=rule_keys,
    )


def _iac_signature(finding: SignatureSource) -> MatchSignature | None:
    details = finding.details or {}
    rule_id = details.get("rule_id") or "unknown"
    content_hash = _hash("\n".join(str(details.get(k) or "") for k in ("actual_value", "expected_value")))
    line = (details.get("start") or {}).get("line")
    similarity_id = details.get("similarity_id")
    search_key = details.get("search_key")

    kics_key = f"KICS:{rule_id}"
    if similarity_id:
        return MatchSignature(
            rule_key=kics_key,
            file_key=finding.component,
            anchor=similarity_id,
            anchor_kind="similarity_id",
            content_hash=content_hash,
            last_line=line,
            rule_keys=[kics_key],
        )
    if search_key:
        return MatchSignature(
            rule_key=kics_key,
            file_key=finding.component,
            anchor=search_key,
            anchor_kind="search_key",
            content_hash=content_hash,
            last_line=line,
            rule_keys=[kics_key],
        )
    return MatchSignature(
        rule_key=kics_key,
        file_key=finding.component,
        anchor=content_hash,
        anchor_kind="content_hash",
        content_hash=content_hash,
        last_line=line,
        rule_keys=[kics_key],
    )


def _secret_signature(finding: SignatureSource) -> MatchSignature | None:
    details = finding.details or {}
    detector = details.get("detector") or "unknown"
    secret_hash = finding.id.rsplit("-", 1)[-1] if finding.id else None
    if not secret_hash:
        return None
    return MatchSignature(
        rule_key=detector,
        file_key=finding.component,
        anchor=secret_hash,
        anchor_kind="secret_hash",
        content_hash=secret_hash,
        last_line=None,
        rule_keys=[detector],
    )


def compute_match_signature(finding: SignatureSource) -> MatchSignature | None:
    """Return a MatchSignature for SAST/IaC/Secret findings (dispatched by id prefix / details), else None."""
    fid = finding.id or ""
    details = finding.details or {}

    if details.get("sast_findings") is not None or fid.startswith(("OPENGREP-", "BEARER-", "SAST-AGG-")):
        return _sast_signature(finding)
    if fid.startswith("KICS-"):
        return _iac_signature(finding)
    if fid.startswith("SECRET-"):
        return _secret_signature(finding)
    return None


def compute_match_signature_from_doc(doc: Mapping[str, Any]) -> MatchSignature | None:
    """Recompute a MatchSignature from a raw persisted finding document when the stored `match` field is missing."""
    return compute_match_signature(
        _DocSignatureSource(
            id=doc.get("finding_id"),
            details=doc.get("details"),
            component=doc.get("component") or "",
        )
    )
