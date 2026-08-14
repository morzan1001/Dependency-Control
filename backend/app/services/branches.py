"""Which single branch a project view defaults to when the caller names none."""

from collections.abc import Mapping, Sequence
from datetime import datetime


def resolve_default_branch(
    configured: str | None,
    active_branches: Sequence[str],
    last_usable_scan_at: Mapping[str, datetime | None],
) -> str | None:
    """The configured default branch while it is still active, else the one scanned most recently.

    Callers must default to exactly one branch: every finding exists on every branch of a repo,
    so a selection spanning n branches multiplies identity-bearing counters by n.

    Rank on the last *usable* scan, never on raw activity — a branch whose newest scans all
    failed has nothing to render and would open the project on an empty page.
    """
    if configured and configured in active_branches:
        return configured

    ordered = sorted(active_branches)
    scanned = [branch for branch in ordered if last_usable_scan_at.get(branch) is not None]
    if scanned:
        return max(scanned, key=lambda branch: last_usable_scan_at[branch])  # type: ignore[arg-type,return-value]
    return ordered[0] if ordered else None
