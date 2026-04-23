"""
Policy audit history service.

Public functions:
    - compute_change_summary(old, new): pure, no I/O. Deterministic one-line
      summary of rule-set differences.
    - record_policy_change(...): async, performs the full persist + webhook +
      notification workflow. (Added in Task B.3.)
"""

from typing import List, Optional, Tuple

from app.models.crypto_policy import CryptoPolicy
from app.schemas.crypto_policy import CryptoRule

# Fields compared when detecting "modified" rules. Not exhaustive — only the
# fields users actually adjust.
_COMPARED_FIELDS: Tuple[str, ...] = (
    "enabled",
    "default_severity",
    "finding_type",
    "match_primitive",
    "match_name_patterns",
    "match_min_key_size_bits",
    "match_curves",
    "match_protocol_versions",
    "quantum_vulnerable",
    "match_cipher_weaknesses",
    "expiry_critical_days",
    "expiry_high_days",
    "expiry_medium_days",
    "expiry_low_days",
    "validity_too_long_days",
)


def compute_change_summary(old: Optional[CryptoPolicy], new: CryptoPolicy) -> str:
    """Deterministic human-readable diff summary (<=200 chars)."""
    if old is None:
        return f"Initial policy ({len(new.rules)} rules)"

    old_by_id = {r.rule_id: r for r in old.rules}
    new_by_id = {r.rule_id: r for r in new.rules}
    added = new_by_id.keys() - old_by_id.keys()
    removed = old_by_id.keys() - new_by_id.keys()
    common = old_by_id.keys() & new_by_id.keys()

    toggled: List[str] = []
    modified: List[str] = []
    for rid in common:
        o_rule = old_by_id[rid]
        n_rule = new_by_id[rid]
        diff_fields = [
            f for f in _COMPARED_FIELDS
            if getattr(o_rule, f, None) != getattr(n_rule, f, None)
        ]
        if not diff_fields:
            continue
        if diff_fields == ["enabled"]:
            toggled.append(rid)
        else:
            modified.append(rid)

    parts: List[str] = []
    if added:
        parts.append(f"added {len(added)} rule(s)")
    if removed:
        parts.append(f"removed {len(removed)}")
    if toggled:
        parts.append(f"toggled enabled on {len(toggled)}")
    if modified:
        parts.append(f"modified {len(modified)}")

    if not parts:
        summary = "No effective changes"
    else:
        summary = ", ".join(parts).capitalize()

    return summary[:200]
