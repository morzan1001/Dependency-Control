"""Two-pass waiver matching: strong-exact (Pass 1) then content/proximity re-anchor (Pass 2).

Operates on MatchSignatures so both the dict-based recalc path and the Finding-based ingest
path can share one source of truth. See the design spec for the decision table.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from app.core.constants import WAIVER_STATUS_FALSE_POSITIVE
from app.models.match_signature import MatchSignature

# Re-anchoring thresholds (conservative defaults; see spec §8).
REANCHOR_WINDOW = 50   # max line distance to consider a candidate "the moved instance"
REANCHOR_MARGIN = 3    # nearest must beat second-nearest by this many lines to be unambiguous


def _content_equal(a: Optional[str], b: Optional[str]) -> bool:
    """content_hash equality, fail-closed on sentinel (None)."""
    return a is not None and b is not None and a == b


def waiver_strong_match(finding_sig: MatchSignature, waiver_sig: MatchSignature, status: str) -> bool:
    """Pass-1 exact-instance match. Only strong anchors qualify; empty anchors never match."""
    if not finding_sig.is_strong or not waiver_sig.is_strong:
        return False
    if finding_sig.rule_key != waiver_sig.rule_key or finding_sig.file_key != waiver_sig.file_key:
        return False
    if finding_sig.anchor != waiver_sig.anchor:
        return False
    if status == WAIVER_STATUS_FALSE_POSITIVE:
        return True
    # accepted_risk: content-bearing anchors (scanner_fp / secret_hash) already imply content equality;
    # content-independent anchors (similarity_id / search_key) require explicit content_hash match.
    if waiver_sig.anchor_kind in ("scanner_fp", "secret_hash"):
        return True
    return _content_equal(finding_sig.content_hash, waiver_sig.content_hash)
