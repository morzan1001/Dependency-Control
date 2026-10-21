from collections.abc import Mapping

from app.core.constants import (
    EPSS_HIGH_THRESHOLD,
    EPSS_MEDIUM_THRESHOLD,
    REACHABILITY_LEVEL_IMPORT,
    REACHABILITY_LEVEL_SYMBOL,
    ExploitMaturity,
)
from app.core.epss import bucket_epss

# INFO, UNKNOWN and NEGLIGIBLE findings carry no weight.
RISK_SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 20.0,
    "HIGH": 4.0,
    "MEDIUM": 1.0,
    "LOW": 0.25,
}

# Calibrated on the prod estate so the median project lands mid-scale, not the top decile all at 99.x.
RISK_SCORE_HALF_SATURATION: float = 250.0

UNREACHABLE_RISK_MODIFIER: float = 0.4
CONFIRMED_REACHABLE_RISK_MODIFIER: float = 1.1


def saturating_risk_score(exposure: float) -> float:
    """Monotone, so extra findings can never lower the score."""
    return round(100.0 * exposure / (exposure + RISK_SCORE_HALF_SATURATION), 1)


def severity_exposure(severity_counts: Mapping[str, int]) -> float:
    return sum(weight * severity_counts.get(severity, 0) for severity, weight in RISK_SEVERITY_WEIGHTS.items())


def reachability_display_tier(is_reachable: bool | None, analysis_level: str | None) -> str:
    if is_reachable is False:
        return "unreachable"
    if is_reachable is True:
        if analysis_level == REACHABILITY_LEVEL_SYMBOL:
            return "confirmed"
        if analysis_level == REACHABILITY_LEVEL_IMPORT:
            return "likely"
    return "unknown"


def reachability_risk_modifier(is_reachable: bool | None, analysis_level: str | None) -> float:
    """Unreachable still weighs, not zero, because the analysis is imperfect."""
    tier = reachability_display_tier(is_reachable, analysis_level)
    if tier == "unreachable":
        return UNREACHABLE_RISK_MODIFIER
    if tier == "confirmed":
        return CONFIRMED_REACHABLE_RISK_MODIFIER
    return 1.0


ACTIVELY_EXPLOITED_MATURITY = ("active", "weaponized")


def calculate_exploit_maturity(is_kev: bool, kev_ransomware: bool, epss_score: float | None) -> ExploitMaturity:
    if kev_ransomware:
        return "weaponized"
    if is_kev:
        return "active"
    if epss_score is not None:
        return bucket_epss(epss_score)
    return "unknown"


def is_actionable_vulnerability(*, epss_score: float | None, is_kev: bool, reachable: bool | None) -> bool:
    exploitable = is_kev or (epss_score is not None and epss_score >= EPSS_HIGH_THRESHOLD)
    return exploitable and (reachable is True or reachable is None)


def is_deprioritized_vulnerability(*, epss_score: float | None, is_kev: bool, reachable: bool | None) -> bool:
    """An absent EPSS score means the CVE is not in the dataset, not that its exploitation is unlikely."""
    if reachable is False:
        return True
    return not is_kev and epss_score is not None and epss_score < EPSS_MEDIUM_THRESHOLD


def is_actionable_secret(verified: bool | None) -> bool:
    """A verified credential is a live leak until rotated, whether or not its file is still in the tree."""
    return verified is True


def is_deprioritized_secret(verified: bool | None, in_current_tree: bool | None) -> bool:
    return verified is not True and in_current_tree is False
