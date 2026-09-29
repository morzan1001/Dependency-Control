"""Cross-component license compatibility checking against LICENSE_INCOMPATIBILITIES."""

from __future__ import annotations

import itertools
from collections import defaultdict
from typing import Any

from app.models.finding import Severity
from app.models.license import DistributionModel
from app.schemas.project import LicensePolicySchema

from .constants import (
    CANONICAL_LICENSE_ID,
    LICENSE_DATABASE,
    LICENSE_INCOMPATIBILITIES,
    LICENSE_INCOMPATIBILITY_CATEGORY,
)
from .evaluator import create_issue

_CONFLICT_OPTIONS = (
    "• Replace one of the conflicting components with an alternative\n"
    "• Check if a dual-licensed or 'or-later' variant resolves the conflict\n"
    "• Isolate the components into separate processes/services"
)


def partition_or_groups(or_groups: list[list[str]]) -> tuple[list[list[str]], list[str]]:
    """Split OR-alternatives into readable ones, as database ids, and the unknown ids that made the rest unreadable."""
    readable: list[list[str]] = []
    unreadable: list[str] = []
    for group in or_groups:
        # A WITH exception only grants more, so the licence it modifies decides the verdict.
        ids = list(dict.fromkeys(member.partition(" WITH ")[0] for member in group))
        # AND binds every member, so one unrecognised member leaves the whole alternative unreadable.
        missing = [lic for lic in ids if lic not in LICENSE_DATABASE]
        if missing:
            unreadable.extend(lic for lic in missing if lic not in unreadable)
        else:
            readable.append(ids)
    return readable, unreadable


def check_license_compatibility(
    settled: list[tuple[dict[str, Any], list[str]]],
    policy: LicensePolicySchema,
) -> list[tuple[dict[str, Any], bool]]:
    """One issue per incompatible licence pair across the components' settled licences, each with whether
    every component involved is transitive."""
    holders: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for component, license_ids in settled:
        for license_id in license_ids:
            holders[license_id].append(component)

    internal = policy.distribution_model == DistributionModel.INTERNAL_ONLY
    conflicts: list[tuple[dict[str, Any], bool]] = []
    for lo, hi in itertools.combinations(sorted(holders), 2):
        reason = LICENSE_INCOMPATIBILITIES.get(
            frozenset({CANONICAL_LICENSE_ID.get(lo, lo), CANONICAL_LICENSE_ID.get(hi, hi)})
        )
        # Licences from the same component are a packaging reality, not a cross-component conflict.
        if not reason or all(a is b for a in holders[lo] for b in holders[hi]):
            continue
        names = {lic: sorted({f"{c.get('name')}@{c.get('version')}" for c in holders[lic]}) for lic in (lo, hi)}
        involved = "\n".join(f"{lic}: {', '.join(names[lic])}" for lic in (lo, hi))
        issue = create_issue(
            component={
                "name": f"{lo} / {hi}",
                "version": "",
                "purl": min((c["purl"] for c in holders[lo] if c.get("purl")), default=""),
            },
            license_id=f"{lo} / {hi}",
            severity=Severity.INFO if internal else Severity.HIGH,
            category=LICENSE_INCOMPATIBILITY_CATEGORY,
            message=f"License conflict: {lo} and {hi}",
            explanation=f"{reason}\n\n{involved}",
            recommendation=(
                "No action is needed while the software stays internal. Before distributing it:\n"
                if internal
                else "These licenses cannot coexist in the same distributed work. Options:\n"
            )
            + _CONFLICT_OPTIONS,
            risks=[reason],
            context_reason=(
                "Severity reduced: project is internal only, and these licenses conflict only in a distributed work."
                if internal
                else None
            ),
            severity_without_context=Severity.HIGH if internal else None,
        )
        conflicts.append((issue, not any(c.get("direct", True) for c in holders[lo] + holders[hi])))
    return conflicts
