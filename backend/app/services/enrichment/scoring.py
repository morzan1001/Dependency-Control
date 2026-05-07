from typing import Optional

from app.core.constants import EPSS_HIGH_THRESHOLD, EPSS_MEDIUM_THRESHOLD
from app.core.epss import bucket_epss


def calculate_exploit_maturity(is_kev: bool, kev_ransomware: bool, epss_score: Optional[float]) -> str:
    """
    Determine exploit maturity level.

    Levels:
    - weaponized: Active ransomware use
    - active: In CISA KEV (confirmed active exploitation)
    - high: EPSS >= HIGH_THRESHOLD (10% chance of exploitation)
    - medium: EPSS >= MEDIUM_THRESHOLD (1% chance)
    - low: EPSS < MEDIUM_THRESHOLD
    - unknown: No data
    """
    if kev_ransomware:
        return "weaponized"
    if is_kev:
        return "active"
    if epss_score is not None:
        return bucket_epss(epss_score)
    return "unknown"


def _calculate_epss_contribution(epss_score: float) -> float:
    """
    Calculate the EPSS contribution to risk score (0-25 points).

    Piecewise linear, continuous at the bucket boundaries (no cliffs).
    Tier targets:
      - 0       at epss=0
      - 10      at epss=EPSS_MEDIUM_THRESHOLD (0.01)
      - 20      at epss=EPSS_HIGH_THRESHOLD   (0.1)
      - 25      at epss=1.0
    """
    if epss_score <= 0:
        return 0.0
    if epss_score >= 1.0:
        return 25.0
    if epss_score >= EPSS_HIGH_THRESHOLD:
        # 20 → 25 across [0.1, 1.0]
        return 20.0 + (epss_score - EPSS_HIGH_THRESHOLD) * (5.0 / (1.0 - EPSS_HIGH_THRESHOLD))
    if epss_score >= EPSS_MEDIUM_THRESHOLD:
        # 10 → 20 across [0.01, 0.1]
        return 10.0 + (epss_score - EPSS_MEDIUM_THRESHOLD) * (
            10.0 / (EPSS_HIGH_THRESHOLD - EPSS_MEDIUM_THRESHOLD)
        )
    # 0 → 10 across [0, 0.01]
    return epss_score * (10.0 / EPSS_MEDIUM_THRESHOLD)


def _apply_reachability_modifier(
    score: float,
    is_reachable: Optional[bool],
    reachability_level: Optional[str],
) -> float:
    """
    Apply reachability modifier to risk score.

    If code is unreachable, significantly reduce the score.
    If confirmed reachable, apply a slight boost.
    """
    if is_reachable is None and reachability_level is None:
        return score

    if is_reachable is False or reachability_level == "unreachable":
        # Unreachable: reduce score by 60% (still keep some risk as analysis isn't perfect)
        return score * 0.4

    if reachability_level == "confirmed":
        # Confirmed reachable: 10% boost
        return score * 1.1

    # "likely" or other reachable states - no modifier
    return score


def calculate_risk_score(
    cvss_score: Optional[float],
    epss_score: Optional[float],
    is_kev: bool,
    kev_ransomware: bool,
    is_reachable: Optional[bool] = None,
    reachability_level: Optional[str] = None,
) -> float:
    """
    Calculate a combined risk score (0-100) considering:
    - CVSS score (severity/impact)
    - EPSS score (likelihood of exploitation in the wild)
    - KEV status (confirmed active exploitation)
    - Reachability (is the vulnerable code actually used?)

    Formula (revised for realistic prioritization):
    - Base: CVSS normalized to 0-40 (severity is important but not everything)
    - EPSS contribution: up to +25 points (exploitation probability is key)
    - KEV bonus: +20 points (actively exploited = urgent)
    - Ransomware bonus: +5 points (known ransomware = very urgent)
    - Reachability modifier: multiplier based on whether code is used
    """
    score = 0.0

    # CVSS contribution (0-40 points)
    # CVSS tells us the IMPACT if exploited, but not likelihood
    if cvss_score is not None:
        score += (cvss_score / 10.0) * 40
    else:
        # Default to medium if no CVSS
        score += 20

    # EPSS contribution (0-25 points)
    # EPSS tells us the PROBABILITY of exploitation in the next 30 days
    if epss_score is not None:
        score += _calculate_epss_contribution(epss_score)

    # KEV bonus - confirmed active exploitation is critical
    if is_kev:
        score += 20

    # Ransomware bonus - known ransomware campaigns need immediate attention
    if kev_ransomware:
        score += 5

    # Apply reachability modifier
    score = _apply_reachability_modifier(score, is_reachable, reachability_level)

    return min(score, 100.0)


def calculate_adjusted_risk_score(
    base_risk_score: float,
    is_reachable: Optional[bool] = None,
    reachability_level: Optional[str] = None,
) -> float:
    """
    Calculate an adjusted risk score considering reachability.
    Use this when reachability is analyzed separately from EPSS/KEV.
    """
    if is_reachable is None and reachability_level is None:
        return base_risk_score

    if is_reachable is False or reachability_level == "unreachable":
        return base_risk_score * 0.4
    elif reachability_level == "confirmed":
        return min(base_risk_score * 1.1, 100.0)

    return base_risk_score
