"""Saturating severity-weighted risk score shared by scan stats and the projects dashboard fallback."""

from typing import Any

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
