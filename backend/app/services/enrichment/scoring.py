from typing import Optional

from app.core.constants import EPSS_HIGH_THRESHOLD, EPSS_MEDIUM_THRESHOLD
from app.core.epss import bucket_epss


def calculate_exploit_maturity(is_kev: bool, kev_ransomware: bool, epss_score: Optional[float]) -> str:
    """Maturity level: weaponized > active > high/medium/low (EPSS) > unknown."""
    if kev_ransomware:
        return "weaponized"
    if is_kev:
        return "active"
    if epss_score is not None:
        return bucket_epss(epss_score)
    return "unknown"


def _calculate_epss_contribution(epss_score: float) -> float:
    """EPSS → 0..25 points, piecewise linear and continuous at bucket boundaries.

    Anchors: 0@0.0, 10@MEDIUM_THRESHOLD, 20@HIGH_THRESHOLD, 25@1.0.
    """
    if epss_score <= 0:
        return 0.0
    if epss_score >= 1.0:
        return 25.0
    if epss_score >= EPSS_HIGH_THRESHOLD:
        return 20.0 + (epss_score - EPSS_HIGH_THRESHOLD) * (5.0 / (1.0 - EPSS_HIGH_THRESHOLD))
    if epss_score >= EPSS_MEDIUM_THRESHOLD:
        return 10.0 + (epss_score - EPSS_MEDIUM_THRESHOLD) * (
            10.0 / (EPSS_HIGH_THRESHOLD - EPSS_MEDIUM_THRESHOLD)
        )
    return epss_score * (10.0 / EPSS_MEDIUM_THRESHOLD)


def _apply_reachability_modifier(
    score: float,
    is_reachable: Optional[bool],
    reachability_level: Optional[str],
) -> float:
    """Scale by reachability: 0.4 if unreachable, 1.1 if confirmed, else identity.

    The unreachable factor is not 0 — symbol-level analysis isn't perfect.
    """
    if is_reachable is None and reachability_level is None:
        return score
    if is_reachable is False or reachability_level == "unreachable":
        return score * 0.4
    if reachability_level == "confirmed":
        return score * 1.1
    return score


def calculate_risk_score(
    cvss_score: Optional[float],
    epss_score: Optional[float],
    is_kev: bool,
    kev_ransomware: bool,
    is_reachable: Optional[bool] = None,
    reachability_level: Optional[str] = None,
) -> float:
    """Combined risk score 0..100 = CVSS impact + EPSS likelihood + KEV/ransomware + reachability.

    CVSS up to 40 (or 20 default), EPSS up to 25, KEV +20, ransomware +5,
    then the reachability multiplier. Capped at 100.
    """
    score = (cvss_score / 10.0) * 40 if cvss_score is not None else 20.0
    if epss_score is not None:
        score += _calculate_epss_contribution(epss_score)
    if is_kev:
        score += 20
    if kev_ransomware:
        score += 5
    score = _apply_reachability_modifier(score, is_reachable, reachability_level)
    return min(score, 100.0)


def calculate_adjusted_risk_score(
    base_risk_score: float,
    is_reachable: Optional[bool] = None,
    reachability_level: Optional[str] = None,
) -> float:
    """Apply only the reachability modifier to an already-computed risk score."""
    if is_reachable is None and reachability_level is None:
        return base_risk_score
    if is_reachable is False or reachability_level == "unreachable":
        return base_risk_score * 0.4
    if reachability_level == "confirmed":
        return min(base_risk_score * 1.1, 100.0)
    return base_risk_score
