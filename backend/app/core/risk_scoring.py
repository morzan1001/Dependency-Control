"""Saturating severity-weighted risk score for scan stats and the projects dashboard fallback, plus
the actionable/deprioritized predicates scan stats, recommendations and secret scoring must agree on."""

from typing import Any

from app.core.constants import EPSS_HIGH_THRESHOLD, EPSS_MEDIUM_THRESHOLD

# Relative weight per finding: 1 CRITICAL = 5 HIGH = 20 MEDIUM = 80 LOW; INFO/UNKNOWN/NEGLIGIBLE carry none.
RISK_SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 20.0,
    "HIGH": 4.0,
    "MEDIUM": 1.0,
    "LOW": 0.25,
}

# Half saturation at 12.5 CRITICALs' worth of exposure, calibrated on the prod estate so the
# median project lands mid-scale instead of the whole top decile compressing into 99.x.
RISK_SCORE_HALF_SATURATION: float = 250.0

# Per-finding weight multipliers mirroring the reachability scaling of details.adjusted_risk_score.
UNREACHABLE_RISK_MODIFIER: float = 0.4
CONFIRMED_REACHABLE_RISK_MODIFIER: float = 1.1


def saturating_risk_score(exposure: float) -> float:
    """Map a weighted exposure sum onto 0-100; monotone, so extra findings can never lower the score."""
    if exposure <= 0:
        return 0.0
    return round(100.0 * exposure / (exposure + RISK_SCORE_HALF_SATURATION), 1)


def severity_exposure(critical: int, high: int, medium: int, low: int) -> float:
    return (
        RISK_SEVERITY_WEIGHTS["CRITICAL"] * critical
        + RISK_SEVERITY_WEIGHTS["HIGH"] * high
        + RISK_SEVERITY_WEIGHTS["MEDIUM"] * medium
        + RISK_SEVERITY_WEIGHTS["LOW"] * low
    )


def risk_score_expr(count_paths: dict[str, str]) -> dict[str, Any]:
    """Aggregation-expression form of saturating_risk_score over severity-count field paths (e.g. "$stats.critical")."""
    exposure = {
        "$add": [
            {"$multiply": [{"$ifNull": [count_paths[sev.lower()], 0]}, weight]}
            for sev, weight in RISK_SEVERITY_WEIGHTS.items()
        ]
    }
    return {
        "$round": [
            {
                "$divide": [
                    {"$multiply": [100.0, exposure]},
                    {"$add": [exposure, RISK_SCORE_HALF_SATURATION]},
                ]
            },
            1,
        ]
    }


def is_actionable_vulnerability(*, epss_score: float | None, is_kev: bool, reachable: bool | None) -> bool:
    """Exploitable (KEV or high EPSS) and not ruled out by a reachability verdict."""
    exploitable = is_kev or (epss_score is not None and epss_score >= EPSS_HIGH_THRESHOLD)
    return exploitable and (reachable is True or reachable is None)


def is_deprioritized_vulnerability(*, epss_score: float | None, is_kev: bool, reachable: bool | None) -> bool:
    """Proven unreachable, or too unlikely to be exploited to compete for attention."""
    if reachable is False:
        return True
    return not is_kev and (epss_score is None or epss_score < EPSS_MEDIUM_THRESHOLD)


def is_deprioritized_secret(verified: bool | None, in_current_tree: bool | None) -> bool:
    """Unverified and no longer present in the scanned tree."""
    return verified is not True and in_current_tree is False
