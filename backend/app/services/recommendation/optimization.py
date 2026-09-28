from collections import defaultdict

from app.core.constants import QUICK_WIN_SCORING_WEIGHTS
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
    VulnerabilityInfo,
)
from app.services.component_identity import build_component_index, lookup_component
from app.services.recommendation.common import (
    ModelOrDict,
    VulnStats,
    get_attr,
    sample_components,
    summarize_vulns,
    take_top,
    vuln_info,
)

# A quick win is one recommendation per package, so this bounds the advice feed rather than a
# list inside one card; each emitted card carries the rank it was cut at.
QUICK_WINS_SHOWN = 5

# Keyed by directness: True/False where the SBOM graph records it, None where it does not.
_DEPENDENCY_KIND = {True: "direct dependency", False: "transitive dependency", None: "dependency"}


def _confirmed_directness(dependencies: list[ModelOrDict]) -> dict[str, bool]:
    """Directness per package name, from graph-confirmed rows only; a direct copy wins."""
    confirmed: dict[str, bool] = {}
    for dep in dependencies:
        if not get_attr(dep, "direct_inferred", False):
            name = get_attr(dep, "name", "")
            confirmed[name] = confirmed.get(name, False) or bool(get_attr(dep, "direct", False))
    # Findings carry the qualified component while the inventory keeps the bare name.
    return build_component_index(confirmed)


def identify_quick_wins(
    vuln_findings: list[ModelOrDict],
    dependencies: list[ModelOrDict],
) -> list[Recommendation]:
    """Identify quick wins - single updates that fix many or critical/KEV vulnerabilities."""
    fixable: dict[str, list[VulnerabilityInfo]] = defaultdict(list)
    for f in vuln_findings:
        vuln = vuln_info(f)
        if vuln.package_name and vuln.fixed_version:
            fixable[vuln.package_name].append(vuln)

    directness = _confirmed_directness(dependencies)

    candidates: list[tuple[int, str, VulnStats, bool | None]] = []
    for pkg, vulns in fixable.items():
        if len(vulns) < 2:
            continue
        stats = summarize_vulns(vulns)
        is_direct = lookup_component(directness, pkg)
        score = (
            stats.total * QUICK_WIN_SCORING_WEIGHTS["base_per_vuln"]
            + stats.severity["CRITICAL"] * QUICK_WIN_SCORING_WEIGHTS["critical"]
            + stats.severity["HIGH"] * QUICK_WIN_SCORING_WEIGHTS["high"]
            + stats.kev * QUICK_WIN_SCORING_WEIGHTS["kev"]
            + (QUICK_WIN_SCORING_WEIGHTS["direct_dep_bonus"] if is_direct else 0)
        )
        candidates.append((score, pkg, stats, is_direct))

    candidates.sort(key=lambda candidate: candidate[0], reverse=True)

    return [
        _quick_win_recommendation(pkg, stats, is_direct, rank, ranked_out_of)
        for rank, (_, pkg, stats, is_direct), ranked_out_of in take_top(candidates, QUICK_WINS_SHOWN)
    ]


def _quick_win_recommendation(
    pkg: str, stats: VulnStats, is_direct: bool | None, rank: int, ranked_out_of: int
) -> Recommendation:
    critical, high = stats.severity["CRITICAL"], stats.severity["HIGH"]
    versions = stats.versions or ["unknown"]
    components_shown, components_total = sample_components(f"{pkg}@{version}" for version in versions)
    return Recommendation(
        type=(RecommendationType.SINGLE_UPDATE_MULTI_FIX if stats.total >= 3 else RecommendationType.QUICK_WIN),
        priority=(Priority.HIGH if stats.kev > 0 or critical > 0 else Priority.MEDIUM),
        title=f"Quick Win: Update {pkg}",
        description=(
            f"Updating this {_DEPENDENCY_KIND[is_direct]} from {', '.join(versions)} to {stats.best_fix} "
            f"will fix {stats.total} vulnerabilities in a single update! "
            f"({critical} critical, {high} high)"
        ),
        impact={
            "critical": critical,
            "high": high,
            "medium": stats.total - critical - high,
            "low": 0,
            "total": stats.total,
            "kev_count": stats.kev,
        },
        affected_components=components_shown,
        affected_components_total=components_total,
        action={
            "type": "quick_win_update",
            "package": pkg,
            "current_versions": versions,
            "target_version": stats.best_fix,
            "is_direct": is_direct,
            "fixes_count": stats.total,
        },
        effort="low",
        rank=rank,
        ranked_out_of=ranked_out_of,
    )
