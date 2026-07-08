"""Two-pass waiver matching: strong-exact (Pass 1) then content/proximity re-anchor (Pass 2)."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from app.core.constants import WAIVER_STATUS_FALSE_POSITIVE
from app.models.match_signature import MatchSignature

REANCHOR_WINDOW = 50  # max line distance to consider a candidate the moved instance
REANCHOR_MARGIN = 3  # nearest must beat second-nearest by this many lines to be unambiguous


def _content_equal(a: Optional[str], b: Optional[str]) -> bool:
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
    if status == WAIVER_STATUS_FALSE_POSITIVE:
        return True
    # accepted_risk: content-bearing anchors imply content equality; others need explicit content_hash match.
    if waiver_sig.anchor_kind in ("scanner_fp", "secret_hash"):
        return True
    return _content_equal(finding_sig.content_hash, waiver_sig.content_hash)


@dataclass
class MatchFinding:
    id: str
    sig: Optional[MatchSignature]


@dataclass
class WaiverApplication:
    waived: Dict[str, str] = field(default_factory=dict)  # finding_id -> waiver_id
    lapsed: Dict[str, str] = field(default_factory=dict)  # finding_id -> waiver_id (re-review)
    reanchored: Dict[str, MatchSignature] = field(default_factory=dict)  # waiver_id -> new signature
    dormant: Dict[str, str] = field(default_factory=dict)  # waiver_id -> reason (bound nothing)


def _waiver_status(w: Any) -> str:
    return getattr(w, "status", None) or WAIVER_STATUS_FALSE_POSITIVE


def _group_key(s: MatchSignature) -> str:
    return s.file_key


def apply_waivers_to_findings(findings: Sequence[MatchFinding], waivers: Sequence) -> WaiverApplication:
    """Assign each finding to at most one waiver via Pass-1 strong-exact then Pass-2 re-anchoring; lapse on ambiguity."""
    app = WaiverApplication()
    located = [f for f in findings if f.sig is not None]
    claimed: set = set()
    matched_waivers: set = set()
    waivers_with_sig = [w for w in waivers if getattr(w, "match", None) is not None]

    by_group: Dict[str, List[MatchFinding]] = {}
    for f in located:
        assert f.sig is not None
        by_group.setdefault(_group_key(f.sig), []).append(f)

    _pass1_strong_exact(app, waivers_with_sig, by_group, claimed, matched_waivers)
    _pass2_reanchor(app, waivers_with_sig, by_group, claimed, matched_waivers)

    # A finding waived by some waiver must never also be reported as lapsed (waived wins).
    for fid in list(app.lapsed):
        if fid in app.waived:
            del app.lapsed[fid]

    return app


def _pass1_strong_exact(
    app: WaiverApplication,
    waivers_with_sig: List,
    by_group: Dict[str, List[MatchFinding]],
    claimed: set,
    matched_waivers: set,
) -> None:
    """Pass 1: match waivers to findings by exact strong anchor."""
    for w in waivers_with_sig:
        wsig: MatchSignature = w.match
        if not wsig.is_strong:
            continue
        status = _waiver_status(w)
        for f in by_group.get(_group_key(wsig), []):
            if f.id in claimed or f.sig is None:
                continue
            if waiver_strong_match(f.sig, wsig, status):
                app.waived[f.id] = w.id
                claimed.add(f.id)
                matched_waivers.add(w.id)
                break


def _pass2_reanchor(
    app: WaiverApplication,
    waivers_with_sig: List,
    by_group: Dict[str, List[MatchFinding]],
    claimed: set,
    matched_waivers: set,
) -> None:
    """Pass 2: re-anchor unmatched waivers over unclaimed candidates."""
    for w in waivers_with_sig:
        if w.id in matched_waivers:
            continue
        wsig = w.match
        status = _waiver_status(w)
        candidates = [
            f
            for f in by_group.get(_group_key(wsig), [])
            if f.id not in claimed and f.sig is not None and _rule_keys_intersect(f.sig, wsig)
        ]
        if not candidates:
            app.dormant[w.id] = "no_candidates_in_group"
            continue
        _resolve_reanchor(app, claimed, w, wsig, status, candidates)


def _resolve_reanchor(
    app: WaiverApplication,
    claimed: set,
    w: Any,
    wsig: MatchSignature,
    status: str,
    candidates: List[MatchFinding],
) -> None:
    """Decide how to resolve a single unmatched waiver against its candidate findings."""
    # (a) same content => pure move; content identity is proof of identity, no window required
    same_content = [
        f for f in candidates if f.sig is not None and _content_equal(f.sig.content_hash, wsig.content_hash)
    ]
    chosen = _pick_unique_content_match(same_content, wsig.last_line)
    if chosen is not None:
        _bind_reanchor(app, claimed, w, chosen)
        return

    # (b) content changed: false_positive with strong original anchor follows the unique nearest
    if status == WAIVER_STATUS_FALSE_POSITIVE and wsig.is_strong:
        chosen = _pick_unique_nearest(candidates, wsig.last_line)
        if chosen is not None:
            _bind_reanchor(app, claimed, w, chosen)
            return

    # accepted_risk, degraded-anchor FP, or ambiguous => lapse (fail-closed)
    _mark_lapsed(app, candidates, wsig.last_line, w.id)


def _line_distance(f: MatchFinding, last_line: Optional[int]) -> float:
    if last_line is None or f.sig is None or f.sig.last_line is None:
        return float("inf")
    return float(abs(f.sig.last_line - last_line))


def _pick_unique_content_match(candidates: List[MatchFinding], last_line: Optional[int]) -> Optional[MatchFinding]:
    """Return the unambiguous same-content candidate, else None; a lone candidate needs no window."""
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    return _pick_unique_nearest(candidates, last_line)


def _pick_unique_nearest(candidates: List[MatchFinding], last_line: Optional[int]) -> Optional[MatchFinding]:
    """Return the nearest candidate within WINDOW when unambiguous (lone candidate, or beats runner-up by MARGIN)."""
    if not candidates:
        return None
    if len(candidates) == 1:
        d = _line_distance(candidates[0], last_line)
        if last_line is None or d <= REANCHOR_WINDOW:
            return candidates[0]
        return None
    ranked = sorted(candidates, key=lambda f: _line_distance(f, last_line))
    d0 = _line_distance(ranked[0], last_line)
    d1 = _line_distance(ranked[1], last_line)
    if d0 <= REANCHOR_WINDOW and (d1 - d0) >= REANCHOR_MARGIN:
        return ranked[0]
    return None


def _bind_reanchor(app: WaiverApplication, claimed: set, w: Any, finding: MatchFinding) -> None:
    app.waived[finding.id] = w.id
    claimed.add(finding.id)
    assert finding.sig is not None
    new_sig = finding.sig.model_copy()
    app.reanchored[w.id] = new_sig


def _mark_lapsed(
    app: WaiverApplication, candidates: List[MatchFinding], last_line: Optional[int], waiver_id: str
) -> None:
    """Flag the most-likely former location(s) as lapsed so the UI can prompt re-review."""
    in_window = [f for f in candidates if _line_distance(f, last_line) <= REANCHOR_WINDOW] or candidates
    nearest = min(in_window, key=lambda f: _line_distance(f, last_line))
    app.lapsed[nearest.id] = waiver_id
