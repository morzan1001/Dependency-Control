"""Waiver matching: routing, field criteria (query and in-memory), advisory roll-up, two-pass signature matcher."""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from app.core.constants import (
    WAIVER_SCOPE_FINDING,
    WAIVER_SCOPE_RULE,
    WAIVER_STATUS_FALSE_POSITIVE,
    get_severity_value,
)
from app.core.cve import advisory_ids, advisory_match
from app.models.finding import LOCATION_FINDING_TYPES
from app.models.match_signature import MatchSignature
from app.models.waiver import Waiver

REANCHOR_WINDOW = 50  # max line distance to consider a candidate the moved instance
REANCHOR_MARGIN = 3  # nearest must beat second-nearest by this many lines to be unambiguous

_RULE_ID = "rule_id"
# Where a location finding names its rule: merged SAST entries, flat SAST/IaC details, secrets.
_RULE_ID_PATHS = ("details.sast_findings.id", "details.rule_id", "details.detector")


def finding_rule_id(details: Mapping[str, Any] | None) -> str | None:
    """The rule a location finding reports: its first merged SAST entry's, else its own rule or detector."""
    details = details or {}
    entries = details.get("sast_findings") or []
    return (entries[0].get("id") if entries else None) or details.get("rule_id") or details.get("detector")


def waiver_criteria(waiver: Waiver) -> dict[str, Any]:
    """The finding fields a waiver constrains; a file or rule scope widens to its rule_id, else stays on its finding."""
    # An advisory lives only in vulnerability documents, whatever type or rule the waiver names.
    advisory = bool(waiver.vulnerability_id)
    widened = waiver.scope != WAIVER_SCOPE_FINDING and bool(waiver.rule_id)
    criteria: dict[str, Any] = {}
    if waiver.finding_id and not widened:
        criteria["finding_id"] = waiver.finding_id
    if waiver.package_name and waiver.scope != WAIVER_SCOPE_RULE:
        criteria["component"] = waiver.package_name
    if waiver.package_version:
        criteria["version"] = waiver.package_version
    if waiver.finding_type and not advisory:
        criteria["type"] = waiver.finding_type
    if waiver.rule_id and not advisory:
        criteria[_RULE_ID] = waiver.rule_id
    return criteria


def waiver_query(waiver: Waiver) -> dict[str, Any]:
    """waiver_criteria as a MongoDB filter over findings."""
    query: dict[str, Any] = {}
    for key, expected in waiver_criteria(waiver).items():
        if key == _RULE_ID:
            query["$or"] = [{path: expected} for path in _RULE_ID_PATHS]
        else:
            query[key] = expected
    return query


def record_matches(record: Mapping[str, Any], criteria: Mapping[str, Any]) -> bool:
    """waiver_criteria checked against one in-memory finding record."""
    for key, expected in criteria.items():
        if key == _RULE_ID:
            details = record.get("details") or {}
            rules = {details.get("rule_id"), details.get("detector")}
            rules.update(entry.get("id") for entry in details.get("sast_findings") or [])
            if expected not in rules:
                return False
        elif record.get(key) != expected:
            return False
    return True


WaiverRoute = Literal["vulnerability", "signature", "query"]


def route_waiver(waiver: Waiver) -> WaiverRoute:
    """Which path applies a waiver: its advisory, its location signature, or its field criteria."""
    if waiver.vulnerability_id:
        return "vulnerability"
    # A widened scope keeps its criteria: one signature would narrow it to the location it was taken from.
    if waiver.scope == WAIVER_SCOPE_FINDING and waiver.match is not None:
        return "signature"
    return "query"


def may_bind_signature(waiver: Waiver) -> bool:
    """A waiver without a signature that names a location finding it could take one from."""
    return (
        waiver.match is None
        and waiver.scope == WAIVER_SCOPE_FINDING
        and not waiver.vulnerability_id
        and bool(waiver.finding_id)
        and (waiver.finding_type is None or waiver.finding_type in LOCATION_FINDING_TYPES)
    )


def bind_legacy_signatures(
    waivers: Iterable[Waiver], sig_by_finding_id: Mapping[str, MatchSignature]
) -> dict[str, MatchSignature]:
    """Give each unsigned waiver the signature of the finding it names by exact id; returns what each one took."""
    bound = {}
    for waiver in waivers:
        if may_bind_signature(waiver) and (sig := sig_by_finding_id.get(waiver.finding_id or "")) is not None:
            waiver.match = bound[waiver.id] = sig
    return bound


def waiver_reach_filter(waiver: Waiver) -> dict[str, Any] | None:
    """The findings a waiver can stamp, as a MongoDB filter; None when it can stamp none."""
    route = route_waiver(waiver)
    if route == "vulnerability" and waiver.vulnerability_id:
        return {**waiver_query(waiver), "type": "vulnerability", **advisory_match(waiver.vulnerability_id)}
    if route == "signature" and waiver.match is not None:
        return {"type": {"$in": [t.value for t in LOCATION_FINDING_TYPES]}, "component": waiver.match.file_key}
    return waiver_query(waiver) or None


def waive_advisories(record: dict[str, Any], waiver: Waiver) -> bool:
    """Waive the record's nested advisories known under the waiver's vulnerability_id; False when it holds none."""
    vid = waiver.vulnerability_id
    hit = False
    for entry in (record.get("details") or {}).get("vulnerabilities") or []:
        if vid in advisory_ids(entry):
            entry["waived"] = True
            entry["waiver_reason"] = waiver.reason
            hit = True
    return hit


def roll_up_advisories(record: dict[str, Any]) -> None:
    """Roll advisories up: severity is the highest live one, waived once all are; never un-waives the document."""
    entries = (record.get("details") or {}).get("vulnerabilities") or []
    if not entries:
        return
    # A fully waived document keeps the severity of its advisories, so dropping the waiver restores it.
    live = [entry for entry in entries if not entry.get("waived")] or entries
    severity = max((entry.get("severity") for entry in live), key=get_severity_value)
    if severity:
        record["severity"] = severity
    if not record.get("waived") and all(entry.get("waived") for entry in entries):
        record["waived"] = True
        record["waiver_reason"] = entries[0].get("waiver_reason")


def _content_equal(a: str | None, b: str | None) -> bool:
    """content_hash equality, fail-closed on sentinel (None)."""
    return a is not None and b is not None and a == b


def _rule_keys_intersect(a: MatchSignature, b: MatchSignature) -> bool:
    """True if the two signatures share at least one rule key (handles scanner-selection drift)."""
    return bool(a.effective_rule_keys & b.effective_rule_keys)


def waiver_strong_match(finding_sig: MatchSignature, waiver_sig: MatchSignature, status: str) -> bool:
    """Pass-1 exact-instance match. Only strong anchors qualify; empty anchors never match."""
    if not finding_sig.is_strong or not waiver_sig.is_strong:
        return False
    if finding_sig.file_key != waiver_sig.file_key or not _rule_keys_intersect(finding_sig, waiver_sig):
        return False
    if finding_sig.anchor != waiver_sig.anchor:
        return False
    if status == WAIVER_STATUS_FALSE_POSITIVE or waiver_sig.implies_content_equality:
        return True
    return _content_equal(finding_sig.content_hash, waiver_sig.content_hash)


@dataclass
class MatchFinding:
    id: str
    sig: MatchSignature


@dataclass
class WaiverApplication:
    waived: dict[str, str] = field(default_factory=dict)  # finding_id -> waiver_id
    lapsed: dict[str, str] = field(default_factory=dict)  # finding_id -> waiver_id (re-review)
    reanchored: dict[str, MatchSignature] = field(default_factory=dict)  # waiver_id -> signature it moved to
    refreshed: dict[str, MatchSignature] = field(default_factory=dict)  # waiver_id -> its signature where it now is
    dormant: dict[str, str] = field(default_factory=dict)  # waiver_id -> reason (bound nothing)


_Signed = tuple[Waiver, MatchSignature]


def apply_waivers_to_findings(findings: Sequence[MatchFinding], waivers: Sequence[Waiver]) -> WaiverApplication:
    """Assign each finding to at most one waiver via Pass-1 strong-exact then Pass-2 re-anchoring; lapse on ambiguity."""
    app = WaiverApplication()
    # Sorted, so which waiver claims a contested finding does not depend on load order.
    signed = sorted(((w, w.match) for w in waivers if w.match is not None), key=lambda pair: pair[0].id)
    unmatched = _pass1_strong_exact(app, signed, findings)
    _pass2_reanchor(app, unmatched, findings)

    # A finding waived by some waiver must never also be reported as lapsed (waived wins).
    for fid in list(app.lapsed):
        if fid in app.waived:
            del app.lapsed[fid]

    return app


def _pass1_strong_exact(
    app: WaiverApplication, signed: list[_Signed], findings: Sequence[MatchFinding]
) -> list[_Signed]:
    """Pass 1: bind each waiver to the finding carrying its exact strong anchor; return the waivers left over."""
    by_anchor: dict[tuple[str, str | None], list[MatchFinding]] = {}
    for f in findings:
        by_anchor.setdefault((f.sig.file_key, f.sig.anchor), []).append(f)
    unmatched = []
    for w, wsig in signed:
        exact = [
            f for f in by_anchor.get((wsig.file_key, wsig.anchor), []) if waiver_strong_match(f.sig, wsig, w.status)
        ]
        free = next((f for f in exact if f.id not in app.waived), None)
        if free is not None:
            app.waived[free.id] = w.id
            _refresh(app, w, wsig, free)
        elif exact:
            app.dormant[w.id] = "shadowed"
        else:
            unmatched.append((w, wsig))
    return unmatched


def _refresh(app: WaiverApplication, w: Waiver, wsig: MatchSignature, finding: MatchFinding) -> None:
    """Keep the waiver's stored location current, so a later re-anchor searches where the finding last was."""
    current: dict[str, object] = {"last_line": finding.sig.last_line}
    # accepted_risk keeps the content that was accepted, so a later edit still lapses it.
    if w.status == WAIVER_STATUS_FALSE_POSITIVE:
        current["content_hash"] = finding.sig.content_hash
    refreshed = wsig.model_copy(update=current)
    if refreshed != wsig:
        app.refreshed[w.id] = refreshed


def _pass2_reanchor(app: WaiverApplication, unmatched: list[_Signed], findings: Sequence[MatchFinding]) -> None:
    """Pass 2: content matches, then false_positive proximity; a taken best candidate shadows, never falls back."""
    by_file: dict[str, list[MatchFinding]] = {}
    for f in findings:
        by_file.setdefault(f.sig.file_key, []).append(f)
    content_changed: list[tuple[Waiver, MatchSignature, list[MatchFinding]]] = []
    for w, wsig in unmatched:
        group = [f for f in by_file.get(wsig.file_key, []) if _rule_keys_intersect(f.sig, wsig)]
        if not group:
            app.dormant[w.id] = "no_candidates_in_group"
            continue
        # A KICS resource anchor's content is the query's templated message, shared by every resource.
        content_identifies = not wsig.is_strong or wsig.implies_content_equality
        same_content = [
            f for f in group if content_identifies and _content_equal(f.sig.content_hash, wsig.content_hash)
        ]
        if not same_content:
            content_changed.append((w, wsig, group))
        elif len(same_content) == 1:
            # Identifying content is the instance wherever it moved; last_line tracks head, not a lagging release.
            _bind_reanchor(app, w, wsig, same_content[0])
        elif (chosen := _pick_unique_nearest(same_content, wsig.last_line)) is not None:
            _bind_reanchor(app, w, wsig, chosen)
        else:
            _mark_lapsed(app, same_content, wsig.last_line, w.id)

    for w, wsig, group in content_changed:
        chosen = None
        if w.status == WAIVER_STATUS_FALSE_POSITIVE and wsig.is_strong:
            chosen = _pick_unique_nearest(group, wsig.last_line)
        if chosen is not None:
            _bind_reanchor(app, w, wsig, chosen)
        else:
            _mark_lapsed(app, group, wsig.last_line, w.id)


def _line_distance(f: MatchFinding, last_line: int | None) -> float:
    if last_line is None or f.sig.last_line is None:
        return float("inf")
    return float(abs(f.sig.last_line - last_line))


def _pick_unique_nearest(candidates: list[MatchFinding], last_line: int | None) -> MatchFinding | None:
    """Return the nearest candidate within WINDOW when it beats the runner-up by MARGIN."""
    ranked = sorted(candidates, key=lambda f: _line_distance(f, last_line))
    d0 = _line_distance(ranked[0], last_line)
    d1 = _line_distance(ranked[1], last_line) if len(ranked) > 1 else float("inf")
    if d0 <= REANCHOR_WINDOW and d1 - d0 >= REANCHOR_MARGIN:
        return ranked[0]
    return None


def _bind_reanchor(app: WaiverApplication, w: Waiver, wsig: MatchSignature, finding: MatchFinding) -> None:
    if finding.id in app.waived:
        app.dormant[w.id] = "shadowed"
        return
    app.waived[finding.id] = w.id
    if finding.sig != wsig:
        app.reanchored[w.id] = finding.sig


def _mark_lapsed(app: WaiverApplication, candidates: list[MatchFinding], last_line: int | None, waiver_id: str) -> None:
    """Flag the waiver's likely former location for re-review; with no candidate near its last line it stays dormant."""
    in_window = [f for f in candidates if _line_distance(f, last_line) <= REANCHOR_WINDOW]
    if not in_window:
        app.dormant[waiver_id] = "no_candidate_in_window"
        return
    app.lapsed[min(in_window, key=lambda f: _line_distance(f, last_line)).id] = waiver_id
